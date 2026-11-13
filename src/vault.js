/**
 * Encrypted local vault for dsh-pii-secrets.
 *
 * Storage format (JSON envelope, versioned):
 *   {
 *     v: 1,
 *     kdf: { name: 'scrypt', N, r, p, salt },
 *     cipher: { name: 'aes-256-gcm', iv, tag },
 *     data: <base64 ciphertext of the JSON payload>
 *   }
 *
 * The passphrase is never persisted. It comes from (in order):
 *   1. config.passphrase (discouraged, in-memory only)
 *   2. env DSH_PII_SECRETS_PASSPHRASE
 *   3. an OS keyring command the user configures (config.keyCommand)
 *   4. an interactive provider registered by a UI adapter (TUI/web)
 *
 * Every mutation rewrites the whole file atomically (tmp + fsync + rename) so a
 * crash never leaves a half-written vault, and in-flight readers only ever see
 * a complete state. That is what makes CRUD hot-reloadable: the in-memory
 * snapshot is rebuilt from the new plaintext before the write returns.
 *
 * @module dsh-pii-secrets/vault
 */

import { createCipheriv, createDecipheriv, randomBytes, scrypt as scryptCb } from 'node:crypto'
import { promises as fs } from 'node:fs'
import { dirname, isAbsolute, resolve } from 'node:path'
import { promisify } from 'node:util'

const scrypt = promisify(scryptCb)

/** KDF / cipher parameters. Raise `N` only with a format bump. */
export const KDF_DEFAULTS = Object.freeze({ N: 2 ** 15, r: 8, p: 1, keyLen: 32 })
const KEY_LEN = 32
const IV_LEN = 12
const TAG_LEN = 16
const FILE_MODE = 0o600
const ENVELOPE_VERSION = 1

export class VaultError extends Error {
  constructor(message, code, options) {
    super(message, options)
    this.name = 'VaultError'
    this.code = code
  }
}

/** A secret's non-sensitive metadata plus its value. */
export function makeEntry({ id, label, value, placeholder, tags = [], source = 'user', createdAt, updatedAt }) {
  const now = new Date().toISOString()
  return Object.freeze({
    id,
    label,
    value,
    placeholder,
    tags: Object.freeze([...tags]),
    source,
    createdAt: createdAt ?? now,
    updatedAt: updatedAt ?? now,
  })
}

async function deriveKey(passphrase, salt, params) {
  if (typeof passphrase !== 'string' || passphrase.length === 0) {
    throw new VaultError('A non-empty passphrase is required to unlock the vault.', 'NO_PASSPHRASE')
  }
  return scrypt(passphrase.normalize('NFKC'), salt, KEY_LEN, {
    N: params.N,
    r: params.r,
    p: params.p,
    maxmem: 256 * params.N * params.r,
  })
}

function seal(key, plaintext) {
  const iv = randomBytes(IV_LEN)
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  const data = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
  return { iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: data.toString('base64') }
}

function open(key, { iv, tag, data }) {
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64'))
  decipher.setAuthTag(Buffer.from(tag, 'base64'))
  try {
    return Buffer.concat([decipher.update(Buffer.from(data, 'base64')), decipher.final()]).toString('utf8')
  } catch {
    // GCM tag mismatch: wrong passphrase or the file was tampered with.
    throw new VaultError('Vault decryption failed: wrong passphrase or tampered file.', 'BAD_PASSPHRASE')
  }
}

async function atomicWrite(file, text) {
  await fs.mkdir(dirname(file), { recursive: true, mode: 0o700 })
  const tmp = `${file}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`
  const handle = await fs.open(tmp, 'wx', FILE_MODE)
  try {
    await handle.writeFile(text, 'utf8')
    await handle.sync()
  } finally {
    await handle.close()
  }
  await fs.rename(tmp, file)
  // Ensure restrictive permissions even if the file pre-existed with wider ones.
  await fs.chmod(file, FILE_MODE).catch(() => {})
}

/**
 * The hot, in-memory view of the vault. All lookups the interceptors perform
 * hit this object, so a CRUD operation is visible to the next request with no
 * restart and no file re-read.
 */
export class SecretStore {
  constructor(entries = []) {
    this._byId = new Map()
    this._byPlaceholder = new Map()
    this._revision = 0
    /** Cached longest-first value list, invalidated on every change. */
    this._values = null
    for (const entry of entries) this._index(entry)
  }

  _index(entry) {
    this._byId.set(entry.id, entry)
    this._byPlaceholder.set(entry.placeholder, entry)
  }

  _bump() {
    this._revision += 1
    this._values = null
  }

  /** Monotonic revision; interceptors can cheaply detect staleness. */
  get revision() {
    return this._revision
  }

  get size() {
    return this._byId.size
  }

  list() {
    return [...this._byId.values()]
  }

  get(id) {
    return this._byId.get(id)
  }

  byPlaceholder(token) {
    return this._byPlaceholder.get(token)
  }

  /**
   * Longest-first value list for the redactor. Values are the sensitive part;
   * they never leave this process except into a local-only substitution.
   */
  values() {
    return this._values ??= [...this._byId.values()].map((e) => e.value).filter(Boolean).sort((a, b) => b.length - a.length)
  }

  upsert(entry) {
    const existing = this._byId.get(entry.id)
    const next = makeEntry({ ...entry, createdAt: existing?.createdAt })
    if (existing && existing.placeholder !== next.placeholder) {
      // Never leave a stale placeholder pointing at a secret that no longer owns it.
      this._byPlaceholder.delete(existing.placeholder)
    }
    this._index(next)
    this._bump()
    return next
  }

  remove(id) {
    const existing = this._byId.get(id)
    if (!existing) return false
    this._byId.delete(id)
    this._byPlaceholder.delete(existing.placeholder)
    this._bump()
    return true
  }

  clear() {
    this._byId.clear()
    this._byPlaceholder.clear()
    this._bump()
  }
}

/**
 * The vault: passphrase resolution, encrypted persistence, and the live store.
 * Owns all secrets on disk; the store owns all reads on the hot path.
 */
export class Vault {
  /**
   * @param {object} options
   * @param {string} options.path absolute or resolved vault file path
   * @param {() => (string|Promise<string>)} [options.passphraseProvider] interactive fallback
   * @param {object} [options.kdf] KDF params for NEW vaults
   * @param {object} [options.logger]
   */
  constructor({ path, passphraseProvider, kdf = KDF_DEFAULTS, logger } = {}) {
    if (!path) throw new VaultError('vaultPath is required.', 'NO_PATH')
    this.path = path
    this.store = new SecretStore()
    this._passphrase = undefined
    this._passphraseProvider = passphraseProvider
    this._kdf = { ...KDF_DEFAULTS, ...kdf }
    this._log = logger
    this._key = undefined
    this._salt = undefined
    this._writing = Promise.resolve()
    /** True once the on-disk state is known (loaded, or confirmed absent). */
    this._loaded = false
    /** True when an existing vault file could not be decrypted. */
    this._loadFailed = false
  }

  /** Resolve the passphrase once and derive the key lazily. */
  async _ensureKey(kdfParams) {
    if (this._key) return this._key
    if (this._passphrase === undefined) {
      const fromEnv = process.env.DSH_PII_SECRETS_PASSPHRASE
      if (fromEnv) this._passphrase = fromEnv
      else if (this._passphraseProvider) this._passphrase = await this._passphraseProvider()
    }
    const params = kdfParams ?? this._kdf
    const salt = this._salt ?? (this._salt = randomBytes(16))
    try {
      this._key = await deriveKey(this._passphrase, salt, params)
    } catch (error) {
      // Never cache a key we could not derive.
      this._key = undefined
      throw error
    }
    return this._key
  }

  /**
   * Drop cached passphrase and key material without clearing the in-memory
   * store. Used when a decryption attempt fails so a corrected passphrase can
   * be retried without restarting the harness.
   */
  invalidateKey() {
    if (this._key) this._key.fill(0)
    this._key = undefined
    this._passphrase = undefined
  }

  /**
   * Drop key material and in-memory secrets (used on shutdown / explicit lock).
   * `store` is intentionally NOT cleared here: a plugin hot-reload disposes and
   * re-applies while other fibers may still be mid-request, and clearing the
   * store would make redaction silently stop working for them. Use
   * `store.clear()` explicitly when a hard wipe is wanted.
   */
  lock() {
    if (this._key) this._key.fill(0)
    this._key = undefined
    this._passphrase = undefined
    this._loaded = false
  }

  /**
   * Load and decrypt the vault, repairing the in-memory store.
   * A missing file yields an empty vault; it is created on first write.
   */
  async load() {
    let raw
    try {
      raw = await fs.readFile(this.path, 'utf8')
    } catch (error) {
      if (error.code === 'ENOENT') {
        this.store.clear()
        this._loaded = true
        return this.store
      }
      throw error
    }
    let envelope
    try {
      envelope = JSON.parse(raw)
    } catch (cause) {
      throw new VaultError(`Vault file is not valid JSON: ${this.path}`, 'CORRUPT', { cause })
    }
    if (envelope?.v !== ENVELOPE_VERSION) {
      throw new VaultError(`Unsupported vault version ${envelope?.v}.`, 'UNSUPPORTED_VERSION')
    }
    // Validate the envelope shape before dereferencing it: a truncated or
    // hand-edited file must fail as a VaultError, not a TypeError.
    const kdf = envelope.kdf
    if (!kdf || typeof kdf.salt !== 'string' || !envelope.cipher || typeof envelope.cipher.data !== 'string') {
      throw new VaultError(`Vault file is missing its kdf/cipher fields: ${this.path}`, 'CORRUPT')
    }
    const params = kdf
    this._salt = Buffer.from(kdf.salt, 'base64')
    const key = await this._ensureKey(params)
    let payload
    try {
      payload = JSON.parse(open(key, envelope.cipher))
    } catch (error) {
      // A wrong passphrase must not poison this instance forever: drop the key so
      // the next attempt re-reads the passphrase (env, keyring, or provider). It
      // must also block a later write from clobbering the undecryptable file.
      this._loadFailed = true
      this.invalidateKey()
      throw error
    }
    this.store.clear()
    for (const entry of payload?.entries ?? []) {
      this.store.upsert(makeEntry(entry))
    }
    this._loaded = true
    this._log?.(() => ['[pii-secrets] vault loaded', { entries: this.store.size }])
    return this.store
  }

  /** Serialize the current store to disk atomically. */
  async save() {
    const run = async () => {
      // Refuse to overwrite an existing vault we FAILED to decrypt: that would
      // silently destroy every stored secret behind a new salt. A vault that was
      // never loaded at all is a fresh instance and may create the file.
      if (this._loadFailed) {
        throw new VaultError(
          'Refusing to overwrite an existing vault that could not be decrypted.',
          'NOT_LOADED',
        )
      }
      const key = await this._ensureKey()
      const payload = JSON.stringify({
        entries: this.store.list().map(({ ...entry }) => entry),
      })
      const envelope = {
        v: ENVELOPE_VERSION,
        kdf: {
          name: 'scrypt',
          N: this._kdf.N,
          r: this._kdf.r,
          p: this._kdf.p,
          salt: Buffer.from(this._salt).toString('base64'),
        },
        cipher: { name: 'aes-256-gcm', ...seal(key, payload) },
      }
      await atomicWrite(this.path, JSON.stringify(envelope))
    }
    // Serialize writers so two hot-reload CRUDs cannot interleave.
    this._writing = this._writing.then(run, run)
    await this._writing
    return this.store
  }

  /** Add or update a secret, then persist. Effective immediately. */
  async upsert(entry) {
    const next = this.store.upsert(entry)
    await this.save()
    return next
  }

  /** Remove a secret, then persist. Effective immediately. */
  async remove(id) {
    const removed = this.store.remove(id)
    if (removed) await this.save()
    return removed
  }
}

/** Resolve the vault path from plugin config against the harness home. */
export function resolveVaultPath(vaultPath, home = process.env.DSH_HOME) {
  if (isAbsolute(vaultPath)) return vaultPath
  return resolve(home ?? process.cwd(), vaultPath)
}
