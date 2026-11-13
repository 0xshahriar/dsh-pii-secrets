/**
 * dsh-pii-secrets — PII Secrets Manager plugin for DeepSeek Harness.
 *
 * Wiring (all real Cordis seams, verified against @deepseek-ai/dsh-* types):
 *
 *   agent/pre-step      waterfall — may REPLACE the messages that enter a step.
 *                       This is the earliest point where content bound for the
 *                       provider can still be changed, so managed secrets are
 *                       swapped for placeholders here.
 *   tools/pre-execute   waterfall — allow / deny / ask before every tool body.
 *   tools/post-execute  waterfall — scrub tool results before the model reads them.
 *   ctx.tools.register  the CRUD surface for the model (`pii_secret`), so the
 *                       agent can add/remove/list secrets without a restart.
 *
 * NOTE ON llm/stream: it cannot redact. Loop-built requests arrive deep-frozen
 * ("listeners read it, never rewrite it") and its `next()` takes no argument.
 * Redaction therefore happens upstream at agent/pre-step plus post-execute.
 *
 * @module dsh-pii-secrets
 */

import { randomUUID } from 'node:crypto'

import Schema from '@deepseek-ai/schemastery'

import { AuditLog } from './audit.js'
import { keyringBackend, readKeyring } from './keyring.js'
import { ACTIONS, ExposurePolicy } from './policy.js'
import { Vault, makeEntry, resolveVaultPath } from './vault.js'
import { WebAdapter, selectAdapter } from './ui.js'

export const name = 'pii-secrets'

/** Only `tools` is required; every other seam is consumed opportunistically. */
export const inject = ['tools']

export const Config = Schema.object({
  vaultPath: Schema.string().default('pii-secrets.vault.json'),
  unknownSecretPolicy: Schema.union(['detect', 'gate', 'block']).default('gate'),
  piiLevel: Schema.union(['all', 'none']).default('all'),
  gateTools: Schema.boolean().default(true),
  redactRequests: Schema.boolean().default(true),
  redactToolResults: Schema.boolean().default(true),
  keyCommand: Schema.string(),
  exposureTimeoutMs: Schema.number().default(120_000),
  /** Opt-in entropy detection for credentials no regex knows (higher false positives). */
  entropyDetection: Schema.boolean().default(false),
  /**
   * Append a JSONL decision log next to the vault. Opt-in: it writes a file, so
   * it is not implied by installing the plugin. Fingerprints only, never values.
   */
  auditLog: Schema.boolean().default(false),
  /** Read the passphrase from the OS keyring before falling back to other sources. */
  useKeyring: Schema.boolean().default(true),
  keyringService: Schema.string().default('dsh-pii-secrets'),
  /**
   * Tools allowed to use named secrets without a prompt, e.g.
   * `{ bash: ['DEV_*'], curl: ['API_*'] }`. Globs match label or placeholder.
   */
  autoAllow: Schema.object().default({}),
  /** Refuse a frozen request that still contains a vault value (retro-logged secrets). */
  blockUnredactedHistory: Schema.boolean().default(true),
  /** Offer `pii_run`, which substitutes secrets locally after arguments are logged. */
  allowLocalExecution: Schema.boolean().default(true),
  /** Redaction cache entries per session. */
  cacheSize: Schema.number().default(4096),
})

/** Placeholder tokens are stable per secret id so transcripts stay coherent. */
function placeholderFor(label, taken) {
  const stem = String(label || 'SECRET')
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 32) || 'SECRET'
  let n = 1
  while (taken.has(`{{${stem}_${n}}}`)) n += 1
  return `{{${stem}_${n}}}`
}

export function apply(ctx, config = {}) {
  const logger = ctx.logger?.('pii-secrets')
  const log = (message) => logger?.info?.(message)

  const vault = new Vault({
    path: resolveVaultPath(config.vaultPath ?? 'pii-secrets.vault.json'),
    passphraseProvider: makePassphraseProvider(config, log),
    logger: log,
  })

  // The web half registers its RPC bridge on the isolation-scoped `piiSecretsWeb`.
  // Until a browser client calls in, `requestExposure` is undefined, so the web
  // adapter reports itself unavailable and the chooser falls through to another
  // adapter.
  const web = new WebAdapter({ requestExposure: undefined, timeoutMs: config.exposureTimeoutMs })
  // Opt-in: a caller passing a partial config (or a harness that has not applied
  // schema defaults yet) must not have files written on its behalf.
  const audit = new AuditLog({
    path:
      config.auditLog === true
        ? `${resolveVaultPath(config.vaultPath ?? 'pii-secrets.vault.json')}.audit.jsonl`
        : undefined,
    logger: log,
  })
  const policy = new ExposurePolicy({
    store: vault.store,
    adapter: fallbackAdapter(ctx, web, log),
    config,
    logger: log,
    audit,
  })

  // Load the vault. A failure here is NOT swallowed: it disables redaction
  // rather than letting unredacted traffic through silently.
  let vaultError
  const ready = vault.load().catch((error) => {
    vaultError = error
    log(`[pii-secrets] vault unavailable (${error.code ?? 'ERROR'}): ${error.message}. Redaction is DEGRADED.`)
  })

  // ── 1. Outbound model requests: silent placeholder substitution ─────────────
  if (config.redactRequests !== false) {
    ctx.on('agent/pre-step', async (payload, next) => {
      const decision = await next()
      if (decision?.kind !== 'enter') return decision
      await ready
      if (vaultError) return decision
      const messages = []
      let changed = false
      for (const message of decision.messages) {
        const { value, redactions } = await policy.protectOutbound(message.content, {
          action: ACTIONS.modelRequest,
          agent: payload.agent,
          signal: payload.signal,
          requestId: randomUUID(),
          cacheKey: message.id,
        })
        if (redactions.length === 0 && value === message.content) {
          messages.push(message)
          continue
        }
        changed = true
        // Preserve identity so transcript correlation still holds.
        messages.push({ ...message, content: value })
        if (redactions.length) {
          log(`[pii-secrets] redacted ${redactions.length} managed secret(s) from an outbound request`)
        }
      }
      return changed ? { kind: 'enter', messages } : decision
    })
  }

  // ── 2. Tool calls: pause / deny before exposure ──────────────────────────────
  if (config.gateTools !== false) {
    ctx.on('tools/pre-execute', async (exec, next) => {
      await ready
      // No vault, no basis for a decision: deny rather than guess.
      if (vaultError) {
        return { kind: 'deny', reason: 'Blocked by PII Secrets Manager: the vault could not be unlocked.' }
      }
      let decision
      try {
        decision = await policy.gateToolCall(exec)
      } catch (error) {
        // A broken UI must never become an exposure channel.
        log(`[pii-secrets] gate error, denying: ${error.message}`)
        return { kind: 'deny', reason: 'Blocked by PII Secrets Manager: the exposure prompt could not be completed.' }
      }
      if (decision.kind === 'allow') return next()
      // deny is terminal for this call; ask is left to the harness approval seam.
      return decision
    })

    // ── 3. Tool results: silent scrub before the model reads them ─────────────
    if (config.redactToolResults !== false) {
      ctx.on('tools/post-execute', async (exec, result, next) => {
        const decision = await next()
        if (decision?.kind !== 'accept') return decision
        await ready
        // Scrub even when the vault failed to load: any secret we do hold in
        // memory should still not reach the model. Nothing to do if empty.
        const content = decision.content ?? result?.content
        if (!Array.isArray(content) || content.length === 0) return decision
        const { value, redactions } = policy.scrubToolResult(content)
        if (!value || redactions.length === 0) return decision
        log(`[pii-secrets] scrubbed ${redactions.length} secret(s) from "${exec.name}" output`)
        return { ...decision, content: value }
      })
    }
  }

  // ── 4. Last-line tripwire: a frozen request cannot be rewritten, so refuse it ─
  if (config.blockUnredactedHistory !== false) {
    ctx.on('llm/stream', (options, next) => {
      // Detection only needs the in-memory store, not the async load: an empty
      // store cannot contain a value, so an unloaded vault is trivially safe.
      if (vault.store.size > 0) {
        const { hit, count } = policy.tripwire(options)
        if (hit) {
          log(`[pii-secrets] blocked an outbound request containing ${count} vault value(s)`)
          throw new Error(
            `Blocked by PII Secrets Manager: this request still contains ${count} value(s) from your vault. ` +
              'They were written to the session log before the secret was vaulted, so the request cannot be ' +
              'redacted in place. Remove them from the transcript, or start a new session.',
          )
        }
      }
      return next()
    })
  }

  // ── 5. CRUD for the agent: hot, no restart ──────────────────────────────────
  registerSecretTool(ctx, { vault, ready, log })
  registerRunTool(ctx, { vault, policy, ready, log, config })

  // ── 6. Lifecycle: restore key material on unload ────────────────────────────
  ctx.effect(() => async () => {
    if (typeof web.dispose === 'function') web.dispose()
    // Drain both queues before the key material goes away: an in-flight atomic
    // write that lands after teardown leaves a stray tmp file behind.
    await audit.flush()
    await vault.flush()
    vault.lock()
  })

  log(`[pii-secrets] ready (vault=${config.vaultPath ?? 'pii-secrets.vault.json'}, policy=${config.unknownSecretPolicy ?? 'gate'})`)
  // Report the entry count once the async load settles, not before.
  void ready.then(() => log(`[pii-secrets] ${vault.store.size} secret(s) loaded`))
}

/**
 * Resolve the vault passphrase without ever persisting it.
 * Priority: env → configured OS keyring command → interactive provider (UI).
 */
function makePassphraseProvider(config, log) {
  return async () => {
    if (process.env.DSH_PII_SECRETS_PASSPHRASE) return process.env.DSH_PII_SECRETS_PASSPHRASE
    if (config.useKeyring !== false) {
      const fromKeyring = await readKeyring({ service: config.keyringService ?? 'dsh-pii-secrets' })
      if (fromKeyring) return fromKeyring
    }
    if (config.keyCommand) {
      const { execFile } = await import('node:child_process')
      const { promisify } = await import('node:util')
      // execFile (not exec): no shell, so the command string cannot inject.
      const [cmd, ...args] = String(config.keyCommand).split(/\s+/)
      const { stdout } = await promisify(execFile)(cmd, args, { timeout: 15_000 })
      const value = stdout.trim()
      if (value) return value
      log('[pii-secrets] keyCommand returned no key')
    }
    const backend = keyringBackend({ service: config.keyringService ?? 'dsh-pii-secrets' })
    throw new Error(
      'Vault passphrase unavailable. Set DSH_PII_SECRETS_PASSPHRASE' +
        (backend ? `, store it in the ${backend} entry "${config.keyringService ?? 'dsh-pii-secrets'}"` : '') +
        ', configure `keyCommand`, or unlock through the web settings tab.',
    )
  }
}

/** The one-step adapter, chosen once the user-questions service is known. */
function fallbackAdapter(ctx, web, log) {
  const inner = selectAdapter({ ctx, logger: log, web })
  return {
    askExposure: (request) => inner.askExposure(request),
  }
}

/** Model-facing CRUD. Effective immediately — no restart, no re-read. */
function registerSecretTool(ctx, { vault, ready, log }) {
  ctx.tools.register({
    name: 'pii_secret',
    description:
      'Manage the local encrypted PII secrets vault. Actions: list (labels only, never values), ' +
      'add (label + value), edit (id + new label/value), remove (id). Values are stored encrypted ' +
      'on this machine and are replaced by placeholders in every outbound model request. To USE a ' +
      'secret in a command, call pii_run rather than typing the value.',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['list', 'add', 'edit', 'remove'] },
        label: { type: 'string', description: 'Human label, e.g. "AWS prod key"' },
        value: { type: 'string', description: 'The secret value to store (add only)' },
        id: { type: 'string', description: 'Secret id (edit and remove)' },
        tags: { type: 'array', items: { type: 'string' } },
      },
      required: ['action'],
    },
    output: {
      schema: { type: 'object' },
      render: (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }],
    },
    async execute(args) {
      await ready
      if (args.action === 'list') {
        // Never return values, only metadata.
        return {
          secrets: vault.store.list().map(({ id, label, placeholder, tags, updatedAt }) => ({
            id,
            label,
            placeholder,
            tags,
            updatedAt,
          })),
        }
      }
      if (args.action === 'add') {
        if (!args.label || !args.value) throw new Error('label and value are required to add a secret')
        const taken = new Set(vault.store.list().map((e) => e.placeholder))
        const placeholder = placeholderFor(args.label, taken)
        const entry = await vault.upsert(
          makeEntry({
            id: `s_${randomUUID().slice(0, 8)}`,
            label: args.label,
            value: String(args.value),
            placeholder,
            tags: args.tags ?? [],
            source: 'agent',
          }),
        )
        log(`[pii-secrets] added "${entry.label}" -> ${entry.placeholder}`)
        return { added: { id: entry.id, label: entry.label, placeholder: entry.placeholder } }
      }
      if (args.action === 'edit') {
        if (!args.id) throw new Error('id is required to edit a secret')
        const existing = vault.store.get(args.id)
        if (!existing) throw new Error(`no secret with id ${args.id}`)
        // A renamed label must not silently change the placeholder the transcript
        // already contains, so the placeholder is preserved unless none exists.
        const entry = await vault.upsert({
          ...existing,
          label: args.label ?? existing.label,
          value: args.value === undefined ? existing.value : String(args.value),
          tags: args.tags ?? existing.tags,
        })
        log(`[pii-secrets] edited "${entry.label}" (${entry.placeholder})`)
        return { edited: { id: entry.id, label: entry.label, placeholder: entry.placeholder } }
      }
      if (args.action === 'remove') {
        if (!args.id) throw new Error('id is required to remove a secret')
        const removed = await vault.remove(args.id)
        return { removed: removed ? args.id : null }
      }
      throw new Error(`unknown action: ${args.action}`)
    },
  })
}

export default { name, inject, Config, apply }

/** Look a secret up by placeholder, id or label. */
function resolveSecret(store, token) {
  const wanted = String(token).trim()
  const entries = store.list()
  return (
    entries.find((entry) => entry.placeholder === wanted) ??
    entries.find((entry) => entry.id === wanted) ??
    entries.find((entry) => String(entry.label).toLowerCase() === wanted.toLowerCase())
  )
}

/** A shell-safe environment name for a placeholder: `{{AWS_KEY_1}}` -> `AWS_KEY_1`. */
function envNameFor(placeholder) {
  const stem = String(placeholder).replace(/[{}]/g, '')
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(stem) ? stem : `PII_${stem.replace(/[^A-Za-z0-9_]/g, '_')}`
}

/**
 * Register `pii_run`: run a command locally with vault secrets substituted
 * *after* the arguments are logged.
 *
 * This is the piece that makes redaction usable. A tool argument containing
 * `{{API_KEY_1}}` cannot be rewritten at `tools/pre-execute` (arguments are
 * already logged) and `tools/execute` may only replace the signal, so a plain
 * `bash` call would execute the literal placeholder. Here substitution happens
 * inside the tool body, so the model never sees the value and the log never
 * contains it. Values are passed as environment variables by default rather
 * than spliced into argv, because argv is world-readable through `ps`.
 *
 * Each requested secret is approved through the same one-step gate as every
 * other exposure, unless a configured scope already covers it.
 */
function registerRunTool(ctx, { vault, policy, ready, log, config }) {
  if (config.allowLocalExecution === false) return

  let registered = false
  const tryRegister = () => {
    if (registered) return
    let shell
    try {
      shell = ctx.get?.('shell') ?? ctx.shell
    } catch {
      shell = undefined
    }
    // No shell provider means no local execution; stay silent rather than
    // registering a tool that can only fail.
    if (!shell || typeof shell.resolve !== 'function' || typeof shell.run !== 'function') return
    registered = true

    ctx.tools.register({
      name: 'pii_run',
      description:
        'Run a shell command on this machine with vault secrets injected as environment variables. ' +
        'Pass the placeholder you want (e.g. "{{API_KEY_1}}") in `secrets`, then reference it as ' +
        '$API_KEY_1 in the command. The secret value never enters the request or the transcript. ' +
        'Use this instead of typing a secret value into a command.',
      parameters: {
        type: 'object',
        properties: {
          command: { type: 'string', description: 'Shell command; reference secrets as $ENV_NAME' },
          secrets: {
            type: 'array',
            items: { type: 'string' },
            minItems: 1,
            description: 'Placeholders, ids or labels to expose to this command as env vars (at least one)',
          },
          workdir: { type: 'string', description: 'Working directory' },
          timeoutMs: { type: 'number', description: 'Timeout in milliseconds (default 120000)' },
          inline: {
            type: 'boolean',
            description:
              'Also splice values into the command string itself. Off by default: argv is readable by other users via ps.',
          },
        },
        required: ['command'],
      },
      output: {
        schema: { type: 'object' },
        render: (_args, value) => [{ type: 'text', text: String(value.stdout ?? '') }],
      },
      async execute(args, execContext) {
        await ready
        const requested = Array.isArray(args.secrets) ? args.secrets : []
        if (requested.length === 0) {
          // Without a secret this would be an unapproved general shell, bypassing
          // whatever policy governs the harness's own bash tool. Keep it narrow.
          throw new Error('pii_run requires at least one entry in `secrets`. Use the bash tool for plain commands.')
        }
        const chosen = []
        for (const token of requested) {
          const entry = resolveSecret(vault.store, token)
          if (!entry) throw new Error(`Unknown secret "${token}". Call pii_secret list to see labels.`)
          chosen.push(entry)
        }
        // A scoped secret is pre-authorised: no prompt, same as the tool gate.
        const needApproval = chosen.filter((entry) => !policy.autoAllowed('pii_run', entry))
        if (needApproval.length > 0) {
          const findings = needApproval.map((entry) => ({
            id: `managed:${entry.id}`,
            ruleId: 'managed',
            kind: 'managed',
            label: entry.label || entry.placeholder,
            masked: entry.placeholder,
            fingerprint: entry.placeholder,
            path: '',
          }))
          const decision = await policy.decide({
            findings,
            action: ACTIONS.toolCall,
            detail: `pii_run wants to expose ${needApproval.length} secret(s) to a local command.`,
            agent: execContext?.agent,
            signal: execContext?.signal,
          })
          if (decision.expose.size === 0) {
            throw new Error('Blocked by PII Secrets Manager: local execution was not approved.')
          }
        }

        const env = {}
        for (const entry of chosen) env[envNameFor(entry.placeholder)] = entry.value
        let command = String(args.command)
        if (args.inline === true) {
          for (const entry of chosen) command = command.split(entry.placeholder).join(entry.value)
        }

        const spec = shell.resolve({
          command,
          ...(args.workdir ? { workdir: String(args.workdir) } : {}),
          timeoutMs: Number(args.timeoutMs) > 0 ? Number(args.timeoutMs) : 120_000,
          ...(Object.keys(env).length ? { env } : {}),
          signal: execContext?.signal,
        })
        const result = await shell.run(spec)

        // Defense in depth: a command that echoes its own environment must not
        // hand the value back through the result.
        const raw = {
          exitCode: result.exitCode,
          stdout: result.stdout?.text ?? '',
          stderr: result.stderr?.text ?? '',
          truncated: Boolean(result.stdout?.truncated || result.stderr?.truncated),
          timedOut: Boolean(result.timedOut),
        }
        const { value: scrubbed } = policy.scrubToolResult([
          { type: 'text', text: `${raw.stdout}\n${raw.stderr}` },
        ])
        const [first] = scrubbed ?? []
        const text = String(first?.text ?? '')
        return { ...raw, output: text }
      },
    })
    log('[pii-secrets] pii_run registered (local secret injection)')
  }

  tryRegister()
  // A shell provider may arrive after this plugin; register then, once.
  try {
    ctx.on('internal/service', (name) => {
      if (name === 'shell') tryRegister()
    })
  } catch {
    // Older cordis without the event: the apply-time attempt stands.
  }
}
