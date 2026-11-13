/**
 * Interception policy for dsh-pii-secrets.
 *
 * One place decides, for any outbound surface, whether a secret may leave:
 *
 *   classify(text) -> { managed, unknown }
 *      managed = values already in the vault  → handled SILENTLY (redacted,
 *                never prompted, per the plugin's core rule)
 *      unknown = pattern matches not in the vault → require a decision
 *
 *   decide(request) -> { expose: Set<id>, reveal }
 *      asks exactly one question (checklist with Select All) and fails closed.
 *
 * Nothing here imports Cordis: it is pure policy so it can be unit-tested and
 * reused by every adapter (agent/pre-step, tools/pre-execute, uploads, web).
 *
 * @module dsh-pii-secrets/policy
 */

import { detect, detectDeep, redactDeep } from './redact.js'
import { AUDIT_EVENTS } from './audit.js'

/** Action classes that can expose data, used for copy and gating policy. */
export const ACTIONS = Object.freeze({
  modelRequest: 'model-request',
  toolCall: 'tool-call',
  terminal: 'terminal',
  read: 'read',
  upload: 'upload',
  publish: 'publish',
})

/** Tools whose whole purpose is pushing data off-machine. */
const PUBLISH_TOOLS = new Set(['web_fetch', 'publish', 'deploy', 'release', 'npm_publish', 'web_search'])
/** Tools that can print arbitrary vault contents (run commands, read files). */
const TERMINAL_TOOLS = new Set(['bash', 'pwsh', 'shell', 'run_code'])
/** Tools that read a file into the transcript but cannot execute anything. */
const FILE_READ_TOOLS = new Set(['read', 'glob', 'grep'])
/** Tool-name hints that mean "this sends files somewhere". */
const UPLOAD_HINTS = [/upload/i, /attach/i, /put_?file/i, /publish/i, /deploy/i]
/** Shortest secret that can be reliably located by substring match. */
const MIN_MATCH_LENGTH = 4
/** Argument keys that name a path a tool will read or send. */
const PATH_KEYS = ['path', 'file', 'filePath', 'file_path', 'target', 'pattern']

/** Classify a tool call into an action class. */
export function classifyTool(name, args) {
  const tool = String(name ?? '')
  if (PUBLISH_TOOLS.has(tool)) return ACTIONS.publish
  if (UPLOAD_HINTS.some((re) => re.test(tool)) || looksLikeUpload(args)) return ACTIONS.upload
  if (TERMINAL_TOOLS.has(tool)) return ACTIONS.terminal
  if (FILE_READ_TOOLS.has(tool)) return ACTIONS.read
  return ACTIONS.toolCall
}

/**
 * Does this call name a path? If so, the file itself may hold a secret even
 * though the arguments (just a path) do not, so the call must be gated.
 */
export function namesAPath(args) {
  if (!args || typeof args !== 'object') return false
  return PATH_KEYS.some((key) => typeof args[key] === 'string' && args[key].length > 0)
}

function looksLikeUpload(args) {
  if (!args || typeof args !== 'object') return false
  return ['files', 'attachments', 'uploads'].some((key) => Array.isArray(args[key]) && args[key].length > 0)
}

export class ExposurePolicy {
  /**
   * @param {object} options
   * @param {import('./vault.js').SecretStore} options.store live store (hot)
   * @param {{ askExposure: Function }} options.adapter one-step UI adapter
   * @param {object} [options.config]
   * @param {(msg: string) => void} [options.logger]
   */
  constructor({ store, adapter, config = {}, logger, audit } = {}) {
    this.store = store
    this.adapter = adapter
    this.config = config
    this._log = logger
    this._audit = audit
    /** Session-scoped approvals so a single allow covers a repetitive loop. */
    this._approved = new Map()
    /**
     * Redaction cache keyed by message id. Messages are immutable and carry a
     * stable id, so a message only needs redacting once per vault revision.
     * Without this, every agent step re-scans the whole history with 17 regexes.
     */
    this._cache = new Map()
    this._cacheRevision = -1
  }

  /** Is this secret pre-authorised for this tool by the configured scopes? */
  autoAllowed(toolName, entry) {
    const scopes = this.config.autoAllow
    if (!scopes || typeof scopes !== 'object') return false
    const globs = scopes[toolName]
    if (!Array.isArray(globs) || globs.length === 0) return false
    const label = String(entry.label ?? '')
    const placeholder = String(entry.placeholder ?? '')
    // Accept `API_KEY_*` as well as `{{API_KEY_1}}`: nobody writes the braces.
    const stem = placeholder.replace(/[{}]/g, '')
    return globs.some(
      (glob) =>
        matchGlob(String(glob), label) ||
        matchGlob(String(glob), placeholder) ||
        matchGlob(String(glob), stem),
    )
  }

  /** Split findings into managed (silent) and unknown (needs a decision). */
  classify(value, { piiLevel, includeRaw = true } = {}) {
    return {
      managed: this.store.list().filter((entry) => entry.value && String(value).includes(entry.value)),
      unknown: detect(value, {
        source: this.store,
        piiLevel: piiLevel ?? this.config.piiLevel ?? 'all',
        entropy: this.config.entropyDetection === true,
        includeRaw,
      }),
    }
  }

  /**
   * The single decision point. Returns the ids the user allowed to expose.
   * Managed secrets are never part of the question and never need permission
   * to be *redacted* — only to be shown raw.
   */
  async decide({ findings, action, detail, agent, signal, requestId }) {
    if (!findings.length) return { expose: new Set(), reveal: false }

    // Session approvals: a repeated identical exposure is not re-asked.
    const cached = findings.filter((f) => this._approved.has(this._key(action, f)))
    const pending = findings.filter((f) => !this._approved.has(this._key(action, f)))
    if (pending.length === 0) {
      return { expose: new Set(findings.map((f) => f.id)), reveal: false }
    }

    const answer = await this.adapter.askExposure({
      // Values stay masked by default; `revealValue` is the only accessor and a
      // UI calls it only after the user presses the eye/reveal control.
      findings: pending.map(({ value, ...finding }) => ({
        ...finding,
        revealValue: value == null ? undefined : () => value,
      })),
      action,
      detail,
      agent,
      signal,
      requestId,
      question:
        pending.length === 1
          ? `Allow "${action}" to expose 1 secret? (${pending[0].label})`
          : `Allow "${action}" to expose ${pending.length} secrets?`,
    })
    // An adapter may resolve to undefined (buggy or absent UI). Never throw here:
    // a crash in the gate must degrade to "nothing exposed", not to an error.
    const selected = Array.isArray(answer?.selected) ? answer.selected : []
    const expose = new Set([...cached, ...selected])
    if (answer?.remember === 'session') {
      for (const id of expose) {
        const finding = findings.find((f) => f.id === id)
        if (finding) this._approved.set(this._key(action, finding), true)
      }
    }
    this._audit?.record(expose.size > 0 ? AUDIT_EVENTS.allowed : AUDIT_EVENTS.denied, {
      action,
      asked: pending.length,
      exposed: expose.size,
      findings: pending.map((f) => ({ ruleId: f.ruleId, fingerprint: f.fingerprint })),
    })
    return { expose, reveal: Boolean(answer?.reveal) }
  }

  /**
   * Last-line defense for history that is already frozen into a request.
   *
   * `agent/pre-step` can only rewrite inbox messages, so a secret logged *before*
   * it was added to the vault stays in the derived history. That request cannot
   * be rewritten at `llm/stream` (it is deep-frozen), so the only correct action
   * is to refuse it loudly rather than ship the value.
   *
   * Uses plain `indexOf` per secret rather than the regex catalog: it runs on
   * every model call and only needs to answer "is a vault value present".
   *
   * @param {{system?: string, messages?: unknown}} request
   * @returns {{hit: boolean, needle?: string, count: number}}
   */
  tripwire(request) {
    const haystack = flattenStrings(request)
    if (!haystack) return { hit: false, count: 0 }
    let count = 0
    let needle
    for (const entry of this.store.list()) {
      const value = entry.value
      if (!value || value.length < 8) continue
      if (haystack.includes(value)) {
        count += 1
        needle ??= entry.placeholder
      }
    }
    if (count > 0) {
      this._audit?.record(AUDIT_EVENTS.tripwire, {
        count,
        placeholders: this.store
          .list()
          .filter((entry) => entry.value && entry.value.length >= 8 && haystack.includes(entry.value))
          .map((entry) => entry.placeholder),
      })
    }
    return { hit: count > 0, needle, count }
  }

  _key(action, finding) {
    return `${action}:${finding.fingerprint}`
  }

  /**
   * Redact a model request body before it leaves the machine.
   *
   * Managed secrets are swapped for placeholders unconditionally — no prompt.
   * Unknown pattern matches are gated: if the user refuses, they are redacted
   * too (a generic placeholder), so nothing unmanaged slips out either.
   */
  async protectOutbound(value, { action = ACTIONS.modelRequest, agent, signal, requestId, cacheKey } = {}) {
    const revision = this.store.revision
    if (revision !== this._cacheRevision) {
      this._cache.clear()
      this._cacheRevision = revision
    }
    if (cacheKey !== undefined) {
      const hit = this._cache.get(cacheKey)
      // Immutable message + unchanged vault ⇒ the projection cannot differ.
      if (hit && hit.revision === revision) return hit.value
    }
    const result = await this._protectOutboundUncached(value, { action, agent, signal, requestId })
    if (cacheKey !== undefined && !result.blocked) {
      if (this._cache.size >= (this.config.cacheSize ?? 4096)) this._cache.clear()
      this._cache.set(cacheKey, { revision, value: result })
    }
    return result
  }

  async _protectOutboundUncached(value, { action, agent, signal, requestId } = {}) {
    const { value: redacted, redactions } = redactDeep(value, this.store)
    if (redactions.length) {
      this._audit?.record(AUDIT_EVENTS.redacted, {
        action,
        count: redactions.length,
        placeholders: redactions.map((r) => r.placeholder),
      })
    }

    if (this.config.unknownSecretPolicy === 'detect') {
      // Observe only: log fingerprints, never values.
      for (const finding of detectDeep(value, { source: this.store, entropy: this.config.entropyDetection === true })) {
        this._log?.(`[pii-secrets] unknown secret observed: ${finding.ruleId} ${finding.fingerprint}`)
      }
      return { value: redacted, redactions, blocked: false }
    }

    const unknown = detectDeep(value, {
      source: this.store,
      includeRaw: true,
      entropy: this.config.entropyDetection === true,
    })
    if (unknown.length === 0) return { value: redacted, redactions, blocked: false }

    if (this.config.unknownSecretPolicy === 'block') {
      return { value: redacted, redactions, blocked: true, reason: blockedReason(unknown.length) }
    }

    const decision = await this.decide({ findings: unknown, action, agent, signal, requestId })
    if (decision.expose.size === 0) {
      // Default-deny: replace every remaining unknown match with a placeholder.
      const { value: scrubbed } = redactUnknown(redacted, unknown)
      this._audit?.record(AUDIT_EVENTS.withheld, {
        action,
        count: unknown.length,
        findings: unknown.map((f) => ({ ruleId: f.ruleId, fingerprint: f.fingerprint, path: f.path })),
      })
      return { value: scrubbed, redactions, blocked: false, withheld: unknown.length }
    }
    // Allowed: only the selected findings survive; the rest are still scrubbed.
    const refused = unknown.filter((f) => !decision.expose.has(f.id))
    const { value: final } = redactUnknown(redacted, refused)
    return { value: final, redactions, blocked: false, revealed: decision.reveal }
  }
  /**
   * Gate a tool call. Returns a PreToolDecision-shaped object so the caller can
   * pass it straight back to the waterfall.
   *
   * A call that would send a secret to a provider is DENIED even if the user
   * allowed display: model requests are never a legitimate exposure channel.
   */
  async gateToolCall(exec) {
    const action = classifyTool(exec.name, exec.arguments)
    // A 1–2 character secret is a substring of almost every command, so it can
    // never be used as a reliable "this call names this secret" signal. Such
    // values are still redacted on the outbound path; they only opt out of the
    // argument-matching heuristic here.
    const managedInArgs = this.store
      .list()
      .filter((entry) => entry.value && entry.value.length >= MIN_MATCH_LENGTH && containsDeep(exec.arguments, entry.value))

    // A tool rarely carries the secret in its arguments: `git log`, `cat .env`
    // and `upload .env` name a *source*, and the value only appears in the
    // output or on the far side of a read. For those the arguments are never a
    // sufficient test, so the call is also gated on its capability.
    const readsASource =
      action === ACTIONS.terminal ||
      action === ACTIONS.read ||
      action === ACTIONS.upload ||
      (action === ACTIONS.toolCall && namesAPath(exec.arguments))

    // ── Unknown (pattern-matched but unmanaged) values in the arguments ──────
    if (managedInArgs.length === 0) {
      const unknown = detectDeep(exec.arguments, { source: this.store, includeRaw: true })
      if (unknown.length > 0) {
        if (this.config.unknownSecretPolicy === 'block') {
          return { kind: 'deny', reason: blockedReason(unknown.length) }
        }
        if (this.config.unknownSecretPolicy !== 'detect') {
          const decision = await this.decide({ findings: unknown, action, agent: exec.agent, signal: exec.signal })
          if (decision.expose.size === 0) {
            return {
              kind: 'deny',
              reason:
                'Blocked: the call contains an unrecognised secret. Add it to the vault to manage it, or allow exposure.',
            }
          }
        }
      }
      // Nothing managed and nothing read-capable: no exposure path, allow.
      if (!readsASource || this.store.size === 0) return { kind: 'allow' }
    }

    // Which secrets this call could surface. Named in the arguments → exactly
    // those. A publish/upload is irreversible, so the whole vault is listed.
    // A terminal/read tool only *might* print one, so it is gated without
    // claiming to know which.
    const managed =
      managedInArgs.length > 0
        ? managedInArgs
        : action === ACTIONS.publish || action === ACTIONS.upload
          ? this.store.list()
          : []

    // Configured scopes let a tool use named secrets without a prompt. Scopes
    // name the *tool* (`bash`, `curl`), not the classified action.
    const managedForGate = managed.filter((entry) => !this.autoAllowed(exec.name, entry))
    if (managedForGate.length === 0) {
      // Either no secret is involved, or every one is inside a configured scope.
      if (managed.length > 0) return { kind: 'allow' }
    } else {
      const findings = managedForGate.map((entry) => ({
        id: `managed:${entry.id}`,
        ruleId: 'managed',
        kind: 'managed',
        label: entry.label || entry.placeholder,
        // Never echo a managed value into the prompt payload.
        masked: entry.placeholder,
        fingerprint: entry.placeholder,
        path: '',
      }))

      // Publishing and uploading never pass without explicit acknowledgement of
      // every item, because the data cannot be recalled afterwards.
      const isShip = action === ACTIONS.publish || action === ACTIONS.upload
      const decision = await this.decide({
        findings,
        action,
        detail: isShip
          ? `"${exec.name}" sends data off this machine.`
          : managedInArgs.length > 0
            ? `"${exec.name}" output would contain managed secrets.`
            : `"${exec.name}" can print any managed secret (its arguments do not contain one).`,
        agent: exec.agent,
        signal: exec.signal,
      })
      if (decision.expose.size === 0) {
        return {
          kind: 'deny',
          reason: isShip
            ? `Blocked by PII Secrets Manager: ${findings.length} secret(s) withheld from "${exec.name}".`
            : `Blocked by PII Secrets Manager: "${exec.name}" may display ${findings.length} managed secret(s).`,
        }
      }
      return { kind: 'allow' }
    }

    // A read-capable call that names no specific secret, in a vault with
    // entries: it could still print one. Gate on capability alone.
    if (readsASource && this.store.size > 0) {
      const decision = await this.decide({
        findings: [
          {
            id: 'vault-reachable',
            ruleId: 'managed',
            kind: 'managed',
            label: `${this.store.size} managed secret(s) reachable`,
            masked: this.store
              .list()
              .map((entry) => entry.placeholder)
              .join(' '),
            fingerprint: 'vault-reachable',
            path: '',
          },
        ],
        action,
        detail: `"${exec.name}" can read or print data that may contain managed secrets.`,
        agent: exec.agent,
        signal: exec.signal,
      })
      if (decision.expose.size === 0) {
        return {
          kind: 'deny',
          reason: `Blocked by PII Secrets Manager: "${exec.name}" may expose managed secrets.`,
        }
      }
    }
    return { kind: 'allow' }
  }

  /**
   * Redact tool *results* before the model reads them (tools/post-execute).
   * Managed secrets are scrubbed silently; there is no prompt because the
   * result is not user-visible — it goes straight to the provider.
   */
  scrubToolResult(content) {
    const { value, redactions } = redactDeep(content, this.store, { skipKeys: new Set(['type']) })
    return { value: redactions.length ? value : undefined, redactions }
  }
}

/**
 * Replace each finding's raw value anywhere in a nested structure with a
 * generic placeholder. Structural, because gate decisions happen per finding
 * while the payload is a deep object (messages, tool arguments, manifests).
 */
function redactUnknown(node, findings) {
  const replacements = findings
    .filter((finding) => finding.value != null)
    // Longest first so nested matches do not truncate the placeholder.
    .sort((a, b) => b.value.length - a.value.length)
    .map((finding) => ({
      value: finding.value,
      token: `{{REDACTED_${finding.ruleId.toUpperCase().replace(/[^A-Z0-9]+/g, '_')}_${finding.fingerprint.slice(0, 6)}}}`,
    }))

  const withheld = new Set()
  const seen = new WeakSet()
  const walk = (current) => {
    if (typeof current === 'string') {
      let output = current
      for (const { value, token } of replacements) {
        if (!output.includes(value)) continue
        output = output.split(value).join(token)
        withheld.add(token)
      }
      return output
    }
    if (Array.isArray(current) || (current && typeof current === 'object')) {
      // Cyclic/shared nodes must not recurse forever.
      if (seen.has(current)) return current
      seen.add(current)
    }
    if (Array.isArray(current)) return current.map(walk)
    if (current && typeof current === 'object') {
      const out = {}
      for (const [key, child] of Object.entries(current)) out[key] = walk(child)
      return out
    }
    return current
  }

  return { value: walk(node), withheld: withheld.size }
}

function blockedReason(count) {
  return `Blocked by PII Secrets Manager: ${count} value(s) match a secret pattern and the policy is "block".`
}

/** Minimal glob matcher for tool scopes: `*` only, case-insensitive. */
export function matchGlob(pattern, value) {
  if (pattern === '*') return true
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')
  return new RegExp(`^${escaped}$`, 'i').test(value)
}

/** Flatten the string leaves of a request into one haystack for the tripwire. */
function flattenStrings(node, budget = { left: 2_000_000 }, seen = new WeakSet()) {
  const parts = []
  const walk = (current) => {
    if (budget.left <= 0) return
    if (typeof current === 'string') {
      parts.push(current)
      budget.left -= current.length
      return
    }
    if (!current || typeof current !== 'object') return
    // A cyclic payload would otherwise walk forever.
    if (seen.has(current)) return
    seen.add(current)
    if (Array.isArray(current)) {
      for (const item of current) walk(item)
      return
    }
    for (const child of Object.values(current)) walk(child)
  }
  walk(node)
  return parts.join('\n')
}

function containsDeep(node, needle, seen = new WeakSet()) {
  if (typeof node === 'string') return node.includes(needle)
  if (Array.isArray(node) || (node && typeof node === 'object')) {
    if (seen.has(node)) return false
    seen.add(node)
  }
  if (Array.isArray(node)) return node.some((item) => containsDeep(item, needle, seen))
  if (node && typeof node === 'object') return Object.values(node).some((child) => containsDeep(child, needle, seen))
  return false
}
