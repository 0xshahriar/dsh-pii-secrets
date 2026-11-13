import assert from 'node:assert/strict'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import { SecretStore, Vault, makeEntry, resolveVaultPath } from '../src/vault.js'
import { PATTERNS, detect, detectDeep, luhn, mask, redact, redactDeep, restore } from '../src/redact.js'

const store = () =>
  new SecretStore([
    makeEntry({ id: 'k1', label: 'OpenAI', value: 'sk-live-REALVALUE1234567890', placeholder: '{{API_KEY_1}}' }),
    makeEntry({ id: 'k2', label: 'AWS', value: 'wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY', placeholder: '{{AWS_SECRET_2}}' }),
    makeEntry({ id: 'k3', label: 'Short', value: 'sk-live', placeholder: '{{SHORT_3}}' }),
  ])

test('redact replaces managed values with placeholders', () => {
  const s = store()
  const { text, redactions } = redact('key=sk-live-REALVALUE1234567890 aws=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY', s)
  assert.equal(text, 'key={{API_KEY_1}} aws={{AWS_SECRET_2}}')
  assert.equal(redactions.length, 2)
})

test('redact prefers the longest value (no partial corruption)', () => {
  const s = store()
  const { text } = redact('sk-live-REALVALUE1234567890', s)
  assert.equal(text, '{{API_KEY_1}}')
  assert.ok(!text.includes('{{SHORT_3}}'))
})

test('redact is idempotent on already-redacted text', () => {
  const s = store()
  const once = redact('x sk-live-REALVALUE1234567890 y', s).text
  const twice = redact(once, s).text
  assert.equal(once, twice)
})

test('redact leaves unknown text untouched and handles empty input', () => {
  const s = store()
  assert.equal(redact('nothing secret here', s).text, 'nothing secret here')
  assert.deepEqual(redact('', s), { text: '', redactions: [] })
  assert.deepEqual(redact(null, s), { text: '', redactions: [] })
})

test('restore round-trips placeholders back to values', () => {
  const s = store()
  const text = 'k={{API_KEY_1}}'
  assert.equal(restore(text, s), 'k=sk-live-REALVALUE1234567890')
})

test('managed secrets are silently redacted, never detected as unknown', () => {
  const s = store()
  // Managed vault value must not surface as an unknown finding.
  assert.equal(detect('sk-live-REALVALUE1234567890', { source: s }).length, 0)
  // The same shape, unmanaged, must be detected.
  const unknown = detect('sk-OTHER9999999999999999999', { source: s })
  assert.equal(unknown.length, 1)
  assert.equal(unknown[0].ruleId, 'openai-key')
})

test('detect finds predefined credential patterns', () => {
  const cases = [
    ['AKIAIOSFODNN7EXAMPLE', 'aws-access-key'],
    ['ghp_' + 'a'.repeat(36), 'github-token'],
    ['postgres://user:hunter2@db.example.com/app', 'connection-string'],
    ['eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abcdefghij', 'jwt'],
    ['password = "supersecret123"', 'password-assignment'],
    ['john.doe@example.com', 'email'],
    ['123-45-6789', 'us-ssn'],
    ['4111111111111111', 'credit-card'],
    ['sk-ant-api03-abcdefghijklmnopqrstuvwxyz', 'anthropic-key'],
    ['AIza' + 'b'.repeat(35), 'google-api-key'],
  ]
  for (const [input, ruleId] of cases) {
    const found = detect(input)
    assert.ok(
      found.some((f) => f.ruleId === ruleId),
      `expected ${ruleId} in ${JSON.stringify(found.map((f) => f.ruleId))} for ${input}`,
    )
  }
})

test('detect supports multiple findings in one string', () => {
  const found = detect('mail a@b.com and card 4111111111111111 and key AKIAIOSFODNN7EXAMPLE')
  const rules = new Set(found.map((f) => f.ruleId))
  assert.ok(rules.has('email'))
  assert.ok(rules.has('credit-card'))
  assert.ok(rules.has('aws-access-key'))
})

test('detect does not leak raw values when includeRaw is false', () => {
  const found = detect('token ghp_' + 'a'.repeat(36), { includeRaw: false })
  assert.ok(found.length > 0)
  for (const f of found) {
    assert.equal(f.value, undefined)
    assert.ok(!JSON.stringify(f).includes('a'.repeat(36)))
  }
})

test('credit card uses Luhn validation', () => {
  assert.equal(luhn('4111111111111111'), true)
  assert.equal(luhn('4111111111111112'), false)
  assert.ok(!detect('4111111111111112').some((f) => f.ruleId === 'credit-card'))
})

test('piiLevel none suppresses PII rules only', () => {
  const found = detect('a@b.com AKIAIOSFODNN7EXAMPLE', { piiLevel: 'none' })
  assert.ok(!found.some((f) => f.pii))
  assert.ok(found.some((f) => f.ruleId === 'aws-access-key'))
})

test('redactDeep walks nested structures without mutating input', () => {
  const s = store()
  const input = { messages: [{ content: [{ type: 'text', text: 'sk-live-REALVALUE1234567890' }] }], n: 1 }
  const { value, redactions } = redactDeep(input, s)
  assert.equal(value.messages[0].content[0].text, '{{API_KEY_1}}')
  assert.equal(input.messages[0].content[0].text, 'sk-live-REALVALUE1234567890')
  assert.equal(redactions.length, 1)
})

test('detectDeep tags the path of each finding', () => {
  const found = detectDeep({ a: { b: ['x AKIAIOSFODNN7EXAMPLE'] } })
  assert.equal(found[0].path, 'a.b[0]')
})

test('mask hides the middle of a value', () => {
  const masked = mask('sk-live-REALVALUE1234567890')
  assert.ok(masked.startsWith('sk-l'))
  assert.ok(masked.includes('•'))
  assert.ok(!masked.includes('REALVALUE'))
})

test('SecretStore upsert/remove are reflected immediately', () => {
  const s = store()
  assert.equal(s.size, 3)
  s.upsert(makeEntry({ id: 'k4', label: 'New', value: 'BRAND_NEW_SECRET', placeholder: '{{NEW_4}}' }))
  assert.equal(redact('BRAND_NEW_SECRET', s).text, '{{NEW_4}}')
  const before = s.revision
  s.remove('k4')
  assert.equal(redact('BRAND_NEW_SECRET', s).text, 'BRAND_NEW_SECRET')
  assert.ok(s.revision > before)
})

test('changing a secret placeholder drops the stale mapping', () => {
  const s = store()
  s.upsert(makeEntry({ id: 'k1', label: 'OpenAI', value: 'sk-live-REALVALUE1234567890', placeholder: '{{RENAMED}}' }))
  assert.equal(s.byPlaceholder('{{API_KEY_1}}'), undefined)
  assert.equal(s.byPlaceholder('{{RENAMED}}').id, 'k1')
})

test('vault encrypts, decrypts and round-trips entries', async () => {
  const dir = await import('node:fs/promises').then((fs) => fs.mkdtemp(join(tmpdir(), 'pii-')))
  const file = `${dir}/v.vault.json`
  const pass = 'correct horse battery staple'
  const v = new Vault({ path: file, passphraseProvider: () => pass })
  await v.load()
  await v.upsert(makeEntry({ id: 'a', label: 'A', value: 'SECRET_VALUE_A', placeholder: '{{A}}' }))

  const raw = await (await import('node:fs/promises')).readFile(file, 'utf8')
  assert.ok(!raw.includes('SECRET_VALUE_A'), 'plaintext must not appear on disk')
  const envelope = JSON.parse(raw)
  assert.equal(envelope.cipher.name, 'aes-256-gcm')

  const v2 = new Vault({ path: file, passphraseProvider: () => pass })
  await v2.load()
  assert.equal(v2.store.get('a').value, 'SECRET_VALUE_A')

  // Wrong passphrase must fail loudly, not return garbage.
  const bad = new Vault({ path: file, passphraseProvider: () => 'wrong' })
  await assert.rejects(() => bad.load(), /decryption failed/i)

  await import('node:fs/promises').then((fs) => fs.rm(dir, { recursive: true, force: true }))
})

test('vault file is written with owner-only permissions', async () => {
  const fs = await import('node:fs/promises')
  const dir = await fs.mkdtemp(join(tmpdir(), 'pii-'))
  const file = `${dir}/perm.vault.json`
  const v = new Vault({ path: file, passphraseProvider: () => 'p' })
  await v.upsert(makeEntry({ id: 'a', label: 'A', value: 'x', placeholder: '{{A}}' }))
  const mode = (await fs.stat(file)).mode & 0o777
  assert.equal(mode, 0o600)
  await fs.rm(dir, { recursive: true, force: true })
})

test('concurrent vault writes serialize and keep the last state', async () => {
  const fs = await import('node:fs/promises')
  const dir = await fs.mkdtemp(join(tmpdir(), 'pii-'))
  const file = `${dir}/c.vault.json`
  const v = new Vault({ path: file, passphraseProvider: () => 'p' })
  await Promise.all([
    v.upsert(makeEntry({ id: 'a', label: 'A', value: '1', placeholder: '{{A}}' })),
    v.upsert(makeEntry({ id: 'b', label: 'B', value: '2', placeholder: '{{B}}' })),
    v.upsert(makeEntry({ id: 'c', label: 'C', value: '3', placeholder: '{{C}}' })),
  ])
  const v2 = new Vault({ path: file, passphraseProvider: () => 'p' })
  await v2.load()
  assert.equal(v2.store.size, 3)
  const leftovers = (await fs.readdir(dir)).filter((f) => f.endsWith('.tmp'))
  assert.deepEqual(leftovers, [], 'no temp files left behind')
  await fs.rm(dir, { recursive: true, force: true })
})

test('resolveVaultPath resolves relative paths against DSH_HOME', () => {
  assert.equal(resolveVaultPath('/abs/v.json'), '/abs/v.json')
  assert.equal(resolveVaultPath('v.json', '/home/dsh'), '/home/dsh/v.json')
})

test('patterns are all global and compilable', () => {
  for (const rule of PATTERNS) {
    assert.ok(rule.re.flags.includes('g'), `${rule.id} must be global`)
    assert.doesNotThrow(() => new RegExp(rule.re.source, rule.re.flags))
  }
})
