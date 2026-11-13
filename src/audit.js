/**
 * Append-only audit log for dsh-pii-secrets.
 *
 * Answers "why was that blocked?" after the fact without ever writing a secret
 * to disk in the clear. Every record carries *fingerprints* and metadata only:
 * no values, no masked previews, no message content.
 *
 * Format: one JSON object per line (JSONL), so the file can be tailed, grepped
 * or shipped without a parser. A write failure is logged and swallowed — an
 * audit log must never break redaction.
 *
 * @module dsh-pii-secrets/audit
 */

import { promises as fs } from 'node:fs'
import { dirname } from 'node:path'

/** Decisions worth recording. */
export const AUDIT_EVENTS = Object.freeze({
  redacted: 'redact',
  withheld: 'withhold',
  denied: 'deny',
  allowed: 'allow',
  vaultWrite: 'vault-write',
  vaultRotate: 'vault-rotate',
  tripwire: 'tripwire',
})

export class AuditLog {
  /**
   * @param {object} options
   * @param {string} [options.path] JSONL file path; omit to disable
   * @param {(msg: string) => void} [options.logger]
   */
  constructor({ path, logger } = {}) {
    this.path = path
    this._log = logger
    this._queue = Promise.resolve()
    this.enabled = Boolean(path)
  }

  /**
   * Record one decision.
   * @param {string} event one of {@link AUDIT_EVENTS}
   * @param {object} fields metadata; must never contain a secret value
   */
  record(event, fields = {}) {
    if (!this.enabled) return
    // Defensive strip: a caller mistake must not write a value to the audit log.
    const { value, secret, plaintext, ...safe } = fields
    void value
    void secret
    void plaintext
    const line = JSON.stringify({ ts: new Date().toISOString(), event, ...safe })
    this._queue = this._queue
      .then(async () => {
        await fs.mkdir(dirname(this.path), { recursive: true, mode: 0o700 })
        await fs.appendFile(this.path, `${line}\n`, { mode: 0o600 })
      })
      .catch((error) => {
        // Never let an audit failure surface as a redaction failure.
        this._log?.(`[pii-secrets] audit write failed: ${error.message}`)
      })
  }

  /** Wait for queued writes (tests and shutdown). */
  async flush() {
    await this._queue
  }

  /** Read back the log for `pii_secret`-style introspection or tests. */
  async read() {
    const raw = await fs.readFile(this.path, 'utf8').catch(() => '')
    return raw
      .split('\n')
      .filter(Boolean)
      .map((line) => {
        try {
          return JSON.parse(line)
        } catch {
          return { event: 'unparseable', line }
        }
      })
  }
}
