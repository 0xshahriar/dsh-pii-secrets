import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import { AuditLog, AUDIT_EVENTS } from '../src/audit.js'
import { keyringBackend, keyringCommands, readKeyring } from '../src/keyring.js'
import { ACTIONS, ExposurePolicy, matchGlob } from '../src/policy.js'
import { detect, detectHighEntropy, shannon } from '../src/redact.js'
import { makeEntry, SecretStore, Vault } from '../src/vault.js'

const OPENAI = 'sk-live-REALVALUE1234567890'
const store = () =>
  new SecretStore([
    makeEntry({ id: 'k1', label: 'OpenAI', value: OPENAI, placeholder: '{{API_KEY_1}}' }),
    makeEntry({ id: 'k2', label: 'Dev token', value: 'dev-token-abcdef0123456789', placeholder: '{{DEV_TOKEN_1}}' }),
  ])

const allowAll = () => ({ calls: [], async askExposure(request) { this.calls.push(request); return { selected: request.findings.map((f) => f.id) } } })
const allowNone = () => ({ calls: [], async askExposure(request) { this.calls.push(request); return { selected: [] } } })

// ── 1. Entropy detection ──────────────────────────────────────────────────────

test('upgrade: entropy detection finds a credential no regex knows', () => {
  const text = 'here is the deploy credential: 9fK2mQ7xL4pR8tW1yZ6bN3vC5'
  const found = detectHighEntropy(text)
  assert.equal(found.length, 1)
  assert.equal(found[0].ruleId, 'high-entropy')
  assert.equal(found[0].value, '9fK2mQ7xL4pR8tW1yZ6bN3vC5')
})

test('upgrade: entropy detection needs keyword proximity, so prose and paths are safe', () => {
  // High entropy, but no credential keyword nearby.
  assert.deepEqual(detectHighEntropy('the build artifact 9fK2mQ7xL4pR8tW1yZ6bN3vC5 shipped'), [])
  // Low entropy, even with the keyword present.
  assert.deepEqual(detectHighEntropy('secret: aaaaaaaaaaaaaaaaaaaaaaaaaaaa'), [])
  // Too short.
  assert.deepEqual(detectHighEntropy('key: 9fK2mQ7xL4pR'), [])
})

test('upgrade: entropy detection is opt-in and off by default', () => {
  // No `=`/`:` operator, so the assignment grammar cannot fire: only entropy can.
  const text = 'the deploy secret is 9fK2mQ7xL4pR8tW1yZ6bN3vC5'
  assert.equal(detect(text).length, 0)
  assert.equal(detect(text, { entropy: true }).length, 1)
})

test('upgrade: managed secrets never resurface through the entropy path', () => {
  const text = `key: ${OPENAI}`
  const found = detect(text, { source: storeRef(), entropy: true })
  assert.equal(found.length, 0, 'a vaulted value must stay silent')
})

test('upgrade: shannon entropy is bounded and monotonic', () => {
  assert.equal(shannon(''), 0)
  assert.equal(shannon('aaaa'), 0)
  assert.ok(shannon('abcd') > shannon('abab'))
})

let _storeRef
function storeRef() {
  _storeRef ??= store()
  return _storeRef
}

// ── 2. Redaction cache ────────────────────────────────────────────────────────

test('upgrade: an unchanged message is redacted once, not once per step', async () => {
  const s = store()
  const policy = new ExposurePolicy({ store: s, adapter: allowNone(), config: {} })
  const message = { id: 'm1', content: [{ type: 'text', text: `token ${OPENAI}` }] }

  const first = await policy.protectOutbound(message.content, { cacheKey: message.id })
  const second = await policy.protectOutbound(message.content, { cacheKey: message.id })
  assert.equal(first.value[0].text, 'token {{API_KEY_1}}')
  // Same object back proves the second call was served from cache.
  assert.equal(second, first)
  assert.equal(policy._cache.size, 1)
})

test('upgrade: a vault change invalidates every cached projection', async () => {
  const s = store()
  const policy = new ExposurePolicy({ store: s, adapter: allowNone(), config: {} })
  const content = [{ type: 'text', text: 'token dev-token-abcdef0123456789' }]

  const first = await policy.protectOutbound(content, { cacheKey: 'm1' })
  assert.equal(first.value[0].text, 'token {{DEV_TOKEN_1}}')

  // Remove the secret; the same message must now come back untouched.
  s.remove('k2')
  const second = await policy.protectOutbound(content, { cacheKey: 'm1' })
  assert.equal(second.value[0].text, 'token dev-token-abcdef0123456789')
})

// ── 3. Tripwire ───────────────────────────────────────────────────────────────

test('upgrade: the tripwire flags a frozen request that still holds a vault value', () => {
  const policy = new ExposurePolicy({ store: store(), adapter: allowNone(), config: {} })
  const request = { system: 'be helpful', messages: [{ role: 'user', content: `my key is ${OPENAI}` }] }
  const result = policy.tripwire(request)
  assert.equal(result.hit, true)
  assert.equal(result.count, 1)
  assert.equal(result.needle, '{{API_KEY_1}}', 'the needle is the placeholder, never the value')
})

test('upgrade: the tripwire stays quiet on a redacted request', () => {
  const policy = new ExposurePolicy({ store: store(), adapter: allowNone(), config: {} })
  const request = { messages: [{ role: 'user', content: 'my key is {{API_KEY_1}}' }] }
  assert.equal(policy.tripwire(request).hit, false)
})

test('upgrade: the tripwire survives cyclic and non-string payloads', () => {
  const policy = new ExposurePolicy({ store: store(), adapter: allowNone(), config: {} })
  const cyclic = { role: 'user' }
  cyclic.self = cyclic
  assert.equal(policy.tripwire({ messages: [cyclic] }).hit, false)
  assert.equal(policy.tripwire({ messages: [{ content: 42 }] }).hit, false)
})

// ── 4. Per-tool scopes ────────────────────────────────────────────────────────

test('upgrade: a configured scope lets a tool use a named secret without a prompt', async () => {
  const adapter = allowNone()
  const policy = new ExposurePolicy({
    store: store(),
    adapter,
    config: { autoAllow: { bash: ['API_KEY_*'] } },
  })
  const decision = await policy.gateToolCall({ name: 'bash', arguments: { command: `echo ${OPENAI}` } })
  assert.equal(decision.kind, 'allow')
  assert.equal(adapter.calls.length, 0, 'a scoped secret must not prompt')
})

test('upgrade: an unscoped secret in the same call still prompts', async () => {
  const adapter = allowAll()
  const policy = new ExposurePolicy({
    store: store(),
    adapter,
    config: { autoAllow: { bash: ['API_KEY_*'] } },
  })
  await policy.gateToolCall({ name: 'bash', arguments: { command: `echo ${OPENAI} dev-token-abcdef0123456789` } })
  assert.equal(adapter.calls.length, 1)
  assert.equal(adapter.calls[0].findings.length, 1, 'only the unscoped secret is asked about')
})

test('upgrade: scopes match labels and placeholders, and only listed tools', async () => {
  const policy = new ExposurePolicy({
    store: store(),
    adapter: allowNone(),
    config: { autoAllow: { curl: ['OpenAI'] } },
  })
  assert.equal((await policy.gateToolCall({ name: 'curl', arguments: { body: OPENAI } })).kind, 'allow')
  const other = await policy.gateToolCall({ name: 'bash', arguments: { command: OPENAI } })
  assert.equal(other.kind, 'deny')
})

test('upgrade: matchGlob escapes regex metacharacters', () => {
  assert.equal(matchGlob('API_*', 'API_KEY_1'), true)
  assert.equal(matchGlob('API.*', 'API_KEY_1'), false, 'a dot is literal')
  assert.equal(matchGlob('*', 'anything'), true)
  assert.equal(matchGlob('KEY', 'key'), true, 'case-insensitive')
})

// ── 5. Rotation ───────────────────────────────────────────────────────────────

test('upgrade: rotation re-encrypts under a new passphrase and keeps the data', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'pii-rotate-'))
  try {
    const path = join(dir, 'v.vault.json')
    const vault = new Vault({ path, passphraseProvider: async () => 'old-passphrase' })
    await vault.load()
    await vault.upsert(makeEntry({ id: 'k1', label: 'OpenAI', value: OPENAI, placeholder: '{{API_KEY_1}}' }))
    const before = await readFile(path, 'utf8')
    assert.ok(!before.includes(OPENAI), 'the value is never on disk in the clear')

    const { salt } = await vault.rotate('new-passphrase')
    assert.ok(salt.length > 0)
    const after = await readFile(path, 'utf8')
    assert.ok(!after.includes(OPENAI))
    assert.notEqual(before, after)

    // The new passphrase opens it; the old one must not.
    const reopened = new Vault({ path, passphraseProvider: async () => 'new-passphrase' })
    await reopened.load()
    assert.equal(reopened.store.get('k1').value, OPENAI)

    const stale = new Vault({ path, passphraseProvider: async () => 'old-passphrase' })
    await assert.rejects(() => stale.load())
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('upgrade: rotation refuses an unloaded vault instead of sealing an empty payload', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'pii-rotate2-'))
  try {
    const vault = new Vault({ path: join(dir, 'v.json'), passphraseProvider: async () => 'p' })
    await assert.rejects(() => vault.rotate('p2'), /not loaded|NOT_LOADED/i)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

// ── 6. Audit log ──────────────────────────────────────────────────────────────

test('upgrade: the audit log records decisions but never a secret value', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'pii-audit-'))
  try {
    const path = join(dir, 'audit.jsonl')
    const audit = new AuditLog({ path })
    const policy = new ExposurePolicy({ store: store(), adapter: allowNone(), config: {}, audit })

    await policy.protectOutbound([{ type: 'text', text: `key ${OPENAI}` }])
    await policy.tripwire({ messages: [{ content: OPENAI }] })
    await audit.flush()

    const raw = await readFile(path, 'utf8')
    assert.ok(!raw.includes(OPENAI), 'no plaintext value may reach the audit log')
    const records = await audit.read()
    assert.ok(records.some((r) => r.event === AUDIT_EVENTS.redacted))
    assert.ok(records.some((r) => r.event === AUDIT_EVENTS.tripwire))
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('upgrade: a caller mistake cannot smuggle a value into the audit log', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'pii-audit2-'))
  try {
    const path = join(dir, 'a.jsonl')
    const audit = new AuditLog({ path })
    audit.record(AUDIT_EVENTS.allowed, { action: 'x', value: OPENAI, secret: OPENAI, plaintext: OPENAI })
    await audit.flush()
    assert.ok(!(await readFile(path, 'utf8')).includes(OPENAI))
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('upgrade: a broken audit path never breaks redaction', async () => {
  const audit = new AuditLog({ path: '/proc/definitely/not/writable.jsonl', logger: () => {} })
  const policy = new ExposurePolicy({ store: store(), adapter: allowNone(), config: {}, audit })
  const result = await policy.protectOutbound([{ type: 'text', text: OPENAI }])
  assert.equal(result.value[0].text, '{{API_KEY_1}}')
  await audit.flush()
})

// ── 7. Keyring ────────────────────────────────────────────────────────────────

test('upgrade: keyring commands are per-platform and shell-free', () => {
  const mac = keyringCommands({ platform: 'darwin', service: 'svc' })
  assert.equal(mac.read[0], 'security')
  assert.ok(mac.read[1].includes('-w'))

  const linux = keyringCommands({ platform: 'linux', service: 'svc' })
  assert.equal(linux.read[0], 'secret-tool')

  assert.equal(keyringCommands({ platform: 'win32' }), null, 'no dependency-free Windows backend')
  assert.equal(keyringBackend({ platform: 'darwin' }), 'macOS Keychain')
})

test('upgrade: a missing keyring resolves to undefined instead of throwing', async () => {
  assert.equal(await readKeyring({ platform: 'win32' }), undefined)
  // 'secret-tool' is absent in most CI images: must not reject.
  const value = await readKeyring({ platform: 'linux', service: 'dsh-pii-secrets-does-not-exist' })
  assert.equal(value, undefined)
})

// ── 8. pii_run local executor ─────────────────────────────────────────────────

/** A fake `ctx.shell` that records the spec it was asked to run. */
function fakeShell({ stdout = 'ok', exitCode = 0 } = {}) {
  const specs = []
  return {
    specs,
    resolve: (request) => ({
      command: request.command,
      workdir: request.workdir ?? '/work',
      timeoutMs: request.timeoutMs ?? 120_000,
      stdoutMaxBytes: 1_000_000,
      ...(request.env ? { env: request.env } : {}),
      signal: request.signal,
    }),
    async run(spec) {
      specs.push(spec)
      return {
        exitCode,
        signal: null,
        timedOut: false,
        aborted: false,
        timeoutMs: spec.timeoutMs,
        stdout: { text: stdout, truncated: false },
        stderr: { text: '', truncated: false },
      }
    },
  }
}

/** Minimal tools registry: capture the definition the plugin registers. */
function fakeTools() {
  const tools = new Map()
  return { tools, register: (def) => tools.set(def.name, def) }
}

async function bootRunTool({ shell, config = {}, seeds = [] }) {
  const { apply } = await import('../src/index.js')
  const { mkdtemp: mkdtempAsync } = await import('node:fs/promises')
  const dir = await mkdtempAsync(join(tmpdir(), 'pii-run-'))
  const tools = fakeTools()
  const previousPassphrase = process.env.DSH_PII_SECRETS_PASSPHRASE
  process.env.DSH_PII_SECRETS_PASSPHRASE = 'test-passphrase'
  const ctx = {
    logger: () => ({ info() {}, warn() {}, error() {} }),
    tools,
    get: (name) => (name === 'shell' ? shell : undefined),
    on() {},
    effect() {},
    cleanup: async () => {
      if (previousPassphrase === undefined) delete process.env.DSH_PII_SECRETS_PASSPHRASE
      else process.env.DSH_PII_SECRETS_PASSPHRASE = previousPassphrase
      await rm(dir, { recursive: true, force: true })
    },
  }
  apply(ctx, { vaultPath: join(dir, 'v.json'), ...config })
  // Seed through the real tool so the values land in the real encrypted vault.
  const secret = tools.tools.get('pii_secret')
  for (const seed of seeds) await secret.execute({ action: 'add', ...seed })
  return { ctx, tools, dir }
}

test('upgrade: pii_run injects secrets as env vars, never into argv', async () => {
  const shell = fakeShell()
  const { tools, ctx } = await bootRunTool({
    shell,
    config: { autoAllow: { pii_run: ['*'] } },
    seeds: [{ label: 'API_KEY', value: OPENAI }],
  })
  try {
    const run = tools.tools.get('pii_run')
    assert.ok(run, 'pii_run registers when a shell provider exists')

    const result = await run.execute({ command: 'curl -H "Auth: $API_KEY_1" x', secrets: ['{{API_KEY_1}}'] })
    assert.equal(result.exitCode, 0)
    const spec = shell.specs.at(-1)
    assert.equal(spec.env.API_KEY_1, OPENAI, 'the value reaches the command as env')
    assert.ok(!spec.command.includes(OPENAI), 'the value must never appear in argv')
    assert.ok(spec.command.includes('$API_KEY_1'))
  } finally {
    await ctx.cleanup()
  }
})

test('upgrade: pii_run scrubs a command that echoes its own environment', async () => {
  // A command that prints the secret must not hand it back to the model.
  const shell = fakeShell({ stdout: `key=${OPENAI}` })
  const { tools, ctx } = await bootRunTool({
    shell,
    config: { autoAllow: { pii_run: ['*'] } },
    seeds: [{ label: 'OpenAI', value: OPENAI }],
  })
  try {
    const run = tools.tools.get('pii_run')
    const result = await run.execute({ command: 'env', secrets: ['OpenAI'] })
    assert.ok(!result.output.includes(OPENAI), 'the echoed value is scrubbed from the result')
    assert.ok(result.output.includes('{{OPENAI_1}}'))
  } finally {
    await ctx.cleanup()
  }
})

test('upgrade: pii_run refuses an unknown secret instead of running without it', async () => {
  const shell = fakeShell()
  const { tools, ctx } = await bootRunTool({
    shell,
    config: { autoAllow: { pii_run: ['*'] } },
    seeds: [{ label: 'API_KEY', value: OPENAI }],
  })
  try {
    const run = tools.tools.get('pii_run')
    await assert.rejects(() => run.execute({ command: 'echo hi', secrets: ['{{NOPE_1}}'] }), /Unknown secret/)
    assert.equal(shell.specs.length, 0, 'nothing is executed on a bad request')
  } finally {
    await ctx.cleanup()
  }
})

test('upgrade: pii_run refuses to act as an unapproved general shell', async () => {
  const shell = fakeShell()
  const { tools, ctx } = await bootRunTool({ shell, seeds: [{ label: 'API_KEY', value: OPENAI }] })
  try {
    const run = tools.tools.get('pii_run')
    // No secrets would sidestep whatever policy governs the harness bash tool.
    await assert.rejects(() => run.execute({ command: 'id' }), /at least one/)
    await assert.rejects(() => run.execute({ command: 'id', secrets: [] }), /at least one/)
    assert.equal(shell.specs.length, 0)
  } finally {
    await ctx.cleanup()
  }
})

test('upgrade: pii_run is not registered when local execution is disabled', async () => {
  const { tools } = await bootRunTool({ shell: fakeShell(), config: { allowLocalExecution: false } })
  assert.equal(tools.tools.has('pii_run'), false)
})

test('upgrade: pii_run is not registered without a shell provider', async () => {
  const { tools } = await bootRunTool({ shell: undefined })
  assert.equal(tools.tools.has('pii_run'), false)
})

// ── 9. edit action ────────────────────────────────────────────────────────────

test('upgrade: pii_secret edit changes a label without rewriting the placeholder', async () => {
  const { apply } = await import('../src/index.js')
  const dir = await mkdtemp(join(tmpdir(), 'pii-edit-'))
  try {
    const tools = fakeTools()
    const ctx = {
      logger: () => ({ info() {} }),
      tools,
      get: () => undefined,
      on() {},
      effect() {},
    }
    const previousPassphrase = process.env.DSH_PII_SECRETS_PASSPHRASE
    process.env.DSH_PII_SECRETS_PASSPHRASE = 'test-passphrase'
    apply(ctx, { vaultPath: join(dir, 'v.json') })
    await new Promise((resolve) => setTimeout(resolve, 0))
    const tool = tools.tools.get('pii_secret')

    const added = await tool.execute({ action: 'add', label: 'OpenAI', value: OPENAI })
    assert.equal(added.added.placeholder, '{{OPENAI_1}}')

    const edited = await tool.execute({ action: 'edit', id: added.added.id, label: 'OpenAI prod' })
    assert.equal(edited.edited.label, 'OpenAI prod')
    assert.equal(edited.edited.placeholder, '{{OPENAI_1}}', 'the transcript keeps resolving')

    const listed = await tool.execute({ action: 'list' })
    assert.ok(!JSON.stringify(listed).includes(OPENAI), 'list never returns values')
  } finally {
    delete process.env.DSH_PII_SECRETS_PASSPHRASE
    await rm(dir, { recursive: true, force: true })
  }
})
// ── 10. Opt-in audit + deterministic teardown ────────────────────────────────

test('regression: the audit log stays off when a caller passes a partial config', async () => {
  // Config defaults are applied by the harness; `apply()` can also be called
  // directly (as the tests do). Testing `=== false` instead of `=== true` made
  // every such call write files nobody asked for.
  const { apply } = await import('../src/index.js')
  const dir = await mkdtemp(join(tmpdir(), 'pii-optin-'))
  const previousPassphrase = process.env.DSH_PII_SECRETS_PASSPHRASE
  process.env.DSH_PII_SECRETS_PASSPHRASE = 'test-passphrase'
  try {
    const tools = fakeTools()
    const ctx = { logger: () => ({ info() {} }), tools, get: () => undefined, on() {}, effect() {} }
    apply(ctx, { vaultPath: join(dir, 'v.json') })
    await new Promise((resolve) => setTimeout(resolve, 0))
    await tools.tools.get('pii_secret').execute({ action: 'add', label: 'A', value: OPENAI })
    const { readdir } = await import('node:fs/promises')
    const files = await readdir(dir)
    assert.ok(!files.some((f) => f.endsWith('.audit.jsonl')), `unexpected audit file in ${files.join(',')}`)
  } finally {
    if (previousPassphrase === undefined) delete process.env.DSH_PII_SECRETS_PASSPHRASE
    else process.env.DSH_PII_SECRETS_PASSPHRASE = previousPassphrase
    await rm(dir, { recursive: true, force: true })
  }
})

test('regression: flush() waits for a queued write to land', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'pii-flush-'))
  try {
    const path = join(dir, 'v.json')
    const vault = new Vault({ path, passphraseProvider: async () => 'passphrase' })
    await vault.load()
    // Deliberately do NOT await: this is the teardown race in the wild.
    void vault.upsert(makeEntry({ id: 'k1', label: 'A', value: OPENAI, placeholder: '{{A_1}}' }))
    await vault.flush()
    const raw = await readFile(path, 'utf8')
    assert.ok(raw.includes('"v"'), 'the vault is on disk after flush')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('regression: pii_run asks exactly once, not once per seam', async () => {
  // Its arguments can look like a path (`workdir`, a command naming a file), so
  // the capability gate treated it as read-capable and prompted *in addition to*
  // pii_run's own per-secret prompt.
  const adapter = allowAll()
  const policy = new ExposurePolicy({ store: store(), adapter, config: {} })
  const decision = await policy.gateToolCall({
    name: 'pii_run',
    arguments: { command: 'cat /etc/hosts', workdir: '/srv/app' },
  })
  assert.equal(decision.kind, 'allow', 'the tool gate defers to the in-tool gate')
  assert.equal(adapter.calls.length, 0, 'no prompt at pre-execute')
})

test('regression: unscoped pii_run fails closed when no prompt can be shown', async () => {
  const shell = fakeShell()
  // No userQuestions service and no scope: the in-tool gate has no one to ask,
  // so it must deny rather than assume consent.
  const { tools, ctx } = await bootRunTool({ shell, seeds: [{ label: 'API_KEY', value: OPENAI }] })
  try {
    const run = tools.tools.get('pii_run')
    await assert.rejects(() => run.execute({ command: 'echo $API_KEY_1', secrets: ['API_KEY_1'] }), /not approved/)
    assert.equal(shell.specs.length, 0, 'nothing executes without consent')
  } finally {
    await ctx.cleanup()
  }
})
