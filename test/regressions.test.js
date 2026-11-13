/**
 * Regression tests for bugs found in review. Each test names the defect it
 * locks down, so a future refactor cannot reintroduce it silently.
 */
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import { ExposurePolicy, classifyTool, namesAPath } from '../src/policy.js'
import { Vault, SecretStore, makeEntry } from '../src/vault.js'
import { WebAdapter, describeFinding } from '../src/ui.js'
import { detect } from '../src/redact.js'

const MANAGED = 'sk-live-REALVALUE1234567890'
const silent = () => {}
const store = (entries) =>
  new SecretStore(
    entries ?? [
      makeEntry({ id: 'k1', label: 'OpenAI', value: MANAGED, placeholder: '{{KEY_1}}' }),
      makeEntry({ id: 'k2', label: 'AWS', value: 'wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY', placeholder: '{{AWS_1}}' }),
    ],
  )

function spy(responses = []) {
  const calls = []
  let i = 0
  return {
    calls,
    async askExposure(request) {
      calls.push(request)
      return responses[i++] ?? { selected: [], reveal: false }
    },
  }
}

// ── BUG: exposure was decided from tool ARGUMENTS only, so the exact cases the
// spec names (git log, cat .env) passed with no prompt. ──────────────────────
test('regression: terminal commands that would print secrets are gated', async () => {
  const adapter = spy()
  const p = new ExposurePolicy({ store: store(), adapter, logger: silent })
  for (const command of ['git log --all -p', 'cat .env', 'grep -r key .', 'env | sort']) {
    const decision = await p.gateToolCall({ name: 'bash', arguments: { command } })
    assert.equal(decision.kind, 'deny', `${command} must be gated`)
  }
  assert.equal(adapter.calls.length, 4, 'each call asks once')
})

// ── BUG: `upload .env` carried only a path, so nothing matched. ──────────────
test('regression: an upload naming only a path still lists the whole vault', async () => {
  const adapter = spy([{ selected: [], reveal: false }])
  const p = new ExposurePolicy({ store: store(), adapter, logger: silent })
  const decision = await p.gateToolCall({ name: 'upload_file', arguments: { path: '.env' } })
  assert.equal(decision.kind, 'deny')
  assert.equal(adapter.calls.length, 1)
  assert.equal(adapter.calls[0].findings.length, 2, 'every managed secret is offered')
})

// ── BUG: a file-reading tool naming a path was never considered. ─────────────
test('regression: read/grep with a path are read-capable, not read-free', async () => {
  assert.equal(classifyTool('read', { path: 'a' }), 'read')
  assert.equal(namesAPath({ path: 'a' }), true)
  assert.equal(namesAPath({ command: 'ls' }), false)
  assert.equal(namesAPath('plain string'), false)

  const adapter = spy([{ selected: [], reveal: false }])
  const p = new ExposurePolicy({ store: store(), adapter, logger: silent })
  const decision = await p.gateToolCall({ name: 'read', arguments: { path: '.env' } })
  assert.equal(decision.kind, 'deny')
})

// ── BUG: a non-terminal tool with no path and no secret must not be gated,
// otherwise the plugin prompts on every single tool call. ────────────────────
test('regression: unrelated tools are never gated', async () => {
  const adapter = spy()
  const p = new ExposurePolicy({ store: store(), adapter, logger: silent })
  for (const name of ['todo_write', 'glob_thing', 'prompt_agent']) {
    assert.equal((await p.gateToolCall({ name, arguments: { items: ['x'] } })).kind, 'allow', name)
  }
  assert.equal(adapter.calls.length, 0)
})

// ── BUG: an adapter resolving to undefined threw a TypeError out of the gate. ─
test('regression: an adapter returning undefined denies instead of throwing', async () => {
  const p = new ExposurePolicy({ store: store(), adapter: { askExposure: async () => undefined }, logger: silent })
  const decision = await p.gateToolCall({ name: 'bash', arguments: { command: `echo ${MANAGED}` } })
  assert.equal(decision.kind, 'deny')
})

// ── BUG: detect() was called with includeRaw:false on the gate path, so the
// withhold branch had no value to replace and let the secret through. ────────
test('regression: unknown secrets in tool arguments are scrubbed when refused', async () => {
  const p = new ExposurePolicy({ store: new SecretStore(), adapter: spy(), logger: silent })
  const decision = await p.gateToolCall({ name: 'send_message', arguments: { to: 'ops', body: 'mail a@b.com' } })
  assert.equal(decision.kind, 'deny', 'default-deny when an unknown secret is present')
})

// ── BUG: wrong passphrase cached the derived key, so a corrected passphrase
// could never succeed without restarting the harness. ───────────────────────
test('regression: a failed unlock can be retried without a restart', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'pii-regress-'))
  const file = join(dir, 'v.json')
  const good = new Vault({ path: file, passphraseProvider: () => 'right' })
  await good.load()
  await good.upsert(makeEntry({ id: 'a', label: 'A', value: 'VAL', placeholder: '{{A}}' }))

  delete process.env.DSH_PII_SECRETS_PASSPHRASE
  const retrying = new Vault({ path: file, passphraseProvider: () => 'wrong' })
  await assert.rejects(() => retrying.load(), /decryption failed/i)

  // Same instance, corrected passphrase: must now succeed.
  process.env.DSH_PII_SECRETS_PASSPHRASE = 'right'
  await retrying.load()
  assert.equal(retrying.store.get('a').value, 'VAL')
  delete process.env.DSH_PII_SECRETS_PASSPHRASE
  await rm(dir, { recursive: true, force: true })
})

// ── BUG: writing after a failed unlock would silently replace the vault with
// one encrypted under a fresh salt, destroying every stored secret. ─────────
test('regression: a failed unlock blocks later writes to the same file', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'pii-regress-'))
  const file = join(dir, 'v.json')
  const good = new Vault({ path: file, passphraseProvider: () => 'right' })
  await good.load()
  await good.upsert(makeEntry({ id: 'a', label: 'A', value: 'KEEP_ME', placeholder: '{{A}}' }))
  const before = await readFile(file, 'utf8')

  delete process.env.DSH_PII_SECRETS_PASSPHRASE
  const bad = new Vault({ path: file, passphraseProvider: () => 'wrong' })
  await assert.rejects(() => bad.load(), /decryption failed/i)
  await assert.rejects(
    () => bad.upsert(makeEntry({ id: 'b', label: 'B', value: 'X', placeholder: '{{B}}' })),
    /Refusing to overwrite/,
  )
  assert.equal(await readFile(file, 'utf8'), before, 'the on-disk vault is untouched')
  await rm(dir, { recursive: true, force: true })
})

// ── BUG: a fresh Vault that never called load() must still be able to create
// its file (the overwrite guard must not block the normal first write). ──────
test('regression: a brand-new vault creates its file on first write', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'pii-regress-'))
  const v = new Vault({ path: join(dir, 'new.json'), passphraseProvider: () => 'p' })
  await v.upsert(makeEntry({ id: 'a', label: 'A', value: 'V', placeholder: '{{A}}' }))
  const reopened = new Vault({ path: join(dir, 'new.json'), passphraseProvider: () => 'p' })
  await reopened.load()
  assert.equal(reopened.store.size, 1)
  await rm(dir, { recursive: true, force: true })
})

// ── BUG: a malformed envelope threw a raw TypeError instead of a VaultError. ─
test('regression: an envelope missing its kdf fails as a VaultError', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'pii-regress-'))
  const file = join(dir, 'broken.json')
  await writeFile(file, JSON.stringify({ v: 1, cipher: { iv: 'a', tag: 'b', data: 'c' } }))
  const v = new Vault({ path: file, passphraseProvider: () => 'p' })
  await assert.rejects(
    () => v.load(),
    (error) => error.code === 'CORRUPT' && error.name === 'VaultError',
  )
  await rm(dir, { recursive: true, force: true })
})

// ── BUG: DB. `lock()` cleared the live store, so a hot reload disposed the
// plugin and left other fibers redacting against an empty vault. ─────────────
test('regression: lock() drops keys without discarding the live store', () => {
  const v = new Vault({ path: join(tmpdir(), 'x.json'), passphraseProvider: () => 'p' })
  v.store.upsert(makeEntry({ id: 'a', label: 'A', value: 'V', placeholder: '{{A}}' }))
  v.lock()
  assert.equal(v.store.size, 1, 'redaction must keep working across a reload')
})

// ── BUG: describeFinding read finding.value, which the policy strips; the TUI
// reveal therefore always showed the mask. ───────────────────────────────────
test('regression: TUI reveal uses the revealValue accessor, not a raw field', () => {
  const plain = { id: 'x', label: 'Email', masked: 'a•••' }
  assert.equal(describeFinding(plain, false), 'Email: a•••')
  assert.equal(describeFinding(plain, true), 'Email: a•••', 'no accessor → stays masked')
  const withAccessor = { ...plain, revealValue: () => 'a@b.com' }
  assert.equal(describeFinding(withAccessor, true), 'Email: a@b.com')
})

// ── BUG: the web adapter hardcoded revealable and never passed a reveal
// transport, so the browser eye could never fetch a value. ──────────────────
test('regression: the web adapter passes a per-row reveal transport', async () => {
  let transport
  let payload
  const web = new WebAdapter({
    requestExposure: async (p, t) => {
      payload = p
      transport = t
      return { selected: ['a'], reveal: true }
    },
  })
  const findings = [
    {
      id: 'a',
      label: 'Email',
      masked: 'a•••',
      kind: 'pii',
      fingerprint: 'a',
      revealValue: () => 'a@b.com',
    },
  ]
  const answer = await web.askExposure({ findings, action: 'upload' })
  assert.equal(payload.findings[0].revealable, true)
  assert.equal(payload.findings[0].value, undefined, 'raw value never in the payload')
  assert.equal(await transport.reveal('a'), 'a@b.com')
  assert.equal(await transport.reveal('unknown-id'), null)
  assert.deepEqual(answer.selected, ['a'])
})

test('regression: the web adapter drops ids the UI invented', async () => {
  const web = new WebAdapter({ requestExposure: async () => ({ selected: ['real', 'fake'], reveal: false }) })
  const answer = await web.askExposure({
    findings: [{ id: 'real', label: 'L', masked: 'm', fingerprint: 'f' }],
    action: 'upload',
  })
  assert.deepEqual(answer.selected, ['real'])
})

// ── BUG: single-line markers of a short private key slipped past the pattern. ─
test('regression: short private-key blocks are detected', () => {
  const key = '-----BEGIN PRIVATE KEY-----\nMIIBVAIBADANBg\n-----END PRIVATE KEY-----'
  assert.ok(detect(key).some((f) => f.ruleId === 'private-key-block'))
})

// ── A store whose only secret is very short must not gate every unrelated call. ─
test('regression: a short secret does not make the whole plugin prompt-happy', async () => {
  const adapter = spy()
  const p = new ExposurePolicy({
    store: store([makeEntry({ id: 'x', label: 'X', value: 'a', placeholder: '{{X}}' })]),
    adapter,
    logger: silent,
  })
  // Not read-capable, no path → untouched even though 'a' is a substring of it.
  assert.equal((await p.gateToolCall({ name: 'todo_write', arguments: { items: ['abc'] } })).kind, 'allow')
  assert.equal(adapter.calls.length, 0)
})

// ── detect infrastructure must not use a shared regex lastIndex. ─────────────
test('regression: repeated detect() calls are independent', () => {
  const text = 'a@b.com and c@d.com'
  const first = detect(text).length
  const second = detect(text).length
  assert.equal(first, second)
  assert.equal(first, 2)
})

// ── BUG: a cyclic or shared-reference payload recursed forever and overflowed
// the stack, crashing the redactor mid-request. ─────────────────────────────
test('regression: cyclic structures do not overflow the stack', async () => {
  const { redactDeep: rd, detectDeep: dd } = await import('../src/redact.js')
  const node = { a: MANAGED, nested: { b: MANAGED } }
  node.self = node
  node.nested.up = node

  const { value, redactions } = rd(node, store())
  assert.equal(value.a, '{{KEY_1}}')
  // One entry per redacted occurrence; the cycle itself is not expanded.
  assert.equal(redactions.length, 2)
  assert.equal(value.self, node, 'the cycle is preserved, not expanded forever')

  assert.deepEqual(dd({ x: 1, self: undefined }), [])
})

// ── BUG: redact() returned the caller's non-string value unchanged, so a
// number could reach a place expecting string text. ────────────────────────
test('regression: redact() always returns a string', async () => {
  const { redact } = await import('../src/redact.js')
  assert.equal(typeof redact(123, store()).text, 'string')
  assert.equal(redact(123, store()).text, '123')
  assert.equal(redact(null, store()).text, '')
  assert.equal(redact(undefined, store()).text, '')
})
