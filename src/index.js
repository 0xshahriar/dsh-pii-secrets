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
  const policy = new ExposurePolicy({ store: vault.store, adapter: fallbackAdapter(ctx, web, log), config, logger: log })

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

  // ── 4. CRUD for the agent: hot, no restart ──────────────────────────────────
  registerSecretTool(ctx, { vault, ready, log })

  // ── 5. Lifecycle: restore key material on unload ────────────────────────────
  ctx.effect(() => () => {
    if (typeof web.dispose === 'function') web.dispose()
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
    throw new Error(
      'Vault passphrase unavailable. Set DSH_PII_SECRETS_PASSPHRASE, configure `keyCommand`, or unlock through the web settings tab.',
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
      'add (label + value), remove (id). Values are stored encrypted on this machine and are ' +
      'replaced by placeholders in every outbound model request.',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['list', 'add', 'remove'] },
        label: { type: 'string', description: 'Human label, e.g. "AWS prod key"' },
        value: { type: 'string', description: 'The secret value to store (add only)' },
        id: { type: 'string', description: 'Secret id (remove only)' },
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
