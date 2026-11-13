/**
 * Native OS keyring support for dsh-pii-secrets.
 *
 * `keyCommand` already lets a user name any command, but requiring them to
 * hand-write a per-platform incantation is friction that pushes people toward
 * exporting a plaintext env var instead. This module auto-detects the platform
 * keyring and returns the passphrase, so the safe option is also the easy one.
 *
 * Every lookup uses `execFile` (never a shell), with a timeout, and the value is
 * read from stdout only. A missing tool, a locked keyring or a non-zero exit all
 * resolve to `undefined` so the caller can fall through to the next source
 * rather than crashing the vault.
 *
 * @module dsh-pii-secrets/keyring
 */

import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

const run = promisify(execFile)

/** Account name stored alongside the service in the OS keyring. */
export const DEFAULT_ACCOUNT = 'dsh'

export class KeyringError extends Error {
  constructor(message, code, options) {
    super(message, options)
    this.name = 'KeyringError'
    this.code = code
  }
}

/**
 * Build the read/write commands for the current platform.
 * @param {object} options
 * @param {string} [options.service] keyring service/entry name
 * @param {string} [options.account] account/user field
 * @param {string} [options.platform] override for tests
 * @returns {{ read: string[], write: ((secret: string) => string[])|null, description: string }|null}
 */
export function keyringCommands({ service = 'dsh-pii-secrets', account = DEFAULT_ACCOUNT, platform = process.platform } = {}) {
  if (platform === 'darwin') {
    return {
      description: 'macOS Keychain',
      read: ['security', ['find-generic-password', '-s', service, '-a', account, '-w']],
      write: (secret) => [
        'security',
        ['add-generic-password', '-s', service, '-a', account, '-w', secret, '-U'],
      ],
    }
  }
  if (platform === 'linux') {
    return {
      description: 'libsecret (secret-tool)',
      read: ['secret-tool', ['lookup', 'service', service, 'account', account]],
      write: (secret) => ['secret-tool', ['store', '--label', service, 'service', service, 'account', account], secret],
    }
  }
  if (platform === 'win32') {
    // No dependency-free DPAPI CLI. Windows users keep env/keyCommand.
    return null
  }
  return null
}

/**
 * Read the passphrase from the OS keyring.
 * @returns {Promise<string|undefined>} the passphrase, or undefined when unavailable
 */
export async function readKeyring(options = {}) {
  const spec = keyringCommands(options)
  if (!spec) return undefined
  const [cmd, args] = spec.read
  try {
    const { stdout } = await run(cmd, args, { timeout: 10_000, windowsHide: true })
    const value = stdout.replace(/\r?\n$/, '')
    return value.length > 0 ? value : undefined
  } catch {
    // Not installed, not configured, or the keyring is locked: not an error.
    return undefined
  }
}

/**
 * Store the passphrase in the OS keyring. Best-effort; used by the `keyring`
 * setup helper, never on the hot path.
 * @returns {Promise<boolean>} true when the entry was written
 */
export async function writeKeyring(secret, options = {}) {
  const spec = keyringCommands(options)
  if (!spec?.write || typeof secret !== 'string' || secret.length === 0) return false
  const [cmd, args, stdin] = spec.write(secret)
  try {
    if (stdin === undefined) await run(cmd, args, { timeout: 10_000, windowsHide: true })
    else await run(cmd, args, { timeout: 10_000, windowsHide: true, input: stdin })
    return true
  } catch {
    return false
  }
}

/** Human-readable name of the detected backend, for logs and error messages. */
export function keyringBackend(options = {}) {
  return keyringCommands(options)?.description ?? null
}
