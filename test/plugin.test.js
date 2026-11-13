import assert from 'node:assert/strict'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { test } from 'node:test'

/**
 * Wires the plugin against a mock Cordis context that mimics the real event
 * pipeline, so the *wiring* is tested (hook names, waterfall protocol,
 * decision shapes) without booting a harness.
 */
function mockContext({ userQuestions } = {}) {
  const listeners = new Map()
  const registeredTools = []
  const services = new Map()
  if (userQuestions) services.set('userQuestions', userQuestions)

  const ctx = {
    logger: () => ({ info() {}, warn() {}, error() {} }),
    on(event, handler) {
      if (!listeners.has(event)) listeners.set(event, [])
      listeners.get(event).push(handler)
      return () => {}
    },
    effect(fn) {
      const dispose = fn()
      return () => dispose?.()
    },
    get(name) { return services.get(name) },
    tools: {
      register(tool) {
        registeredTools.push(tool)
        return () => {}
      },
    },
  }

  /**
   * Run a waterfall exactly like Cordis: each listener gets (payload, next),
   * and calling next() past the last listener resolves to the harness default.
   */
  async function waterfall(event, payload) {
    const chain = listeners.get(event) ?? []
    let index = -1
    const dispatch = async () => {
      index += 1
      if (index >= chain.length) return terminal(event, payload)
      // tools/post-execute receives (exec, result, next); others (payload, next).
      return event === 'tools/post-execute'
        ? chain[index](payload, payload, dispatch)
        : chain[index](payload, dispatch)
    }
    return dispatch()
  }

  function terminal(event, payload) {
    if (event === 'agent/pre-step') return { kind: 'enter', messages: payload.messages }
    if (event === 'tools/pre-execute') return { kind: 'allow' }
    if (event === 'tools/post-execute') return { kind: 'accept' }
    return undefined
  }
  void terminal

  return { ctx, listeners, registeredTools, waterfall }
}

async function setup(options = {}) {
  process.env.DSH_PII_SECRETS_PASSPHRASE = 'test-passphrase'
  const dir = await mkdtemp(join(tmpdir(), 'pii-plugin-'))
  const { apply } = await import('../src/index.js')
  const harness = mockContext(options)
  apply(harness.ctx, {
    vaultPath: join(dir, 'vault.json'),
    unknownSecretPolicy: options.policy ?? 'gate',
    ...options.config,
  })
  // Let the async vault load settle.
  await new Promise((r) => setImmediate(r))
  return { ...harness, dir, apply }
}

test('plugin exports the dsh contract (name, inject, Config, apply)', async () => {
  const mod = await import('../src/index.js')
  assert.equal(mod.name, 'pii-secrets')
  assert.deepEqual(mod.inject, ['tools'])
  assert.ok(mod.Config, 'Config schema is required by dsh')
  assert.equal(typeof mod.apply, 'function')
  assert.equal(typeof mod.default.apply, 'function')
})

test('registers the three real interception seams plus the CRUD tool', async () => {
  const { listeners, registeredTools, dir } = await setup()
  assert.ok(listeners.has('agent/pre-step'), 'must redact outbound requests')
  assert.ok(listeners.has('tools/pre-execute'), 'must gate tool calls')
  assert.ok(listeners.has('tools/post-execute'), 'must scrub tool results')
  const tool = registeredTools.find((t) => t.name === 'pii_secret')
  assert.ok(tool, 'agent-facing CRUD tool must be registered')
  await rm(dir, { recursive: true, force: true })
})

test('CRUD via the tool is immediately visible to redaction (no restart)', async () => {
  const { registeredTools, waterfall, dir } = await setup()
  const tool = registeredTools.find((t) => t.name === 'pii_secret')

  const added = await tool.execute({ action: 'add', label: 'AWS prod key', value: 'AKIAIOSFODNN7EXAMPLE' })
  assert.match(added.added.placeholder, /^\{\{AWS_PROD_KEY_\d+\}\}$/)

  // The very next pre-step must already redact it.
  const decision = await waterfall('agent/pre-step', {
    messages: [{ id: 'm1', role: 'user', content: [{ type: 'text', text: 'use AKIAIOSFODNN7EXAMPLE' }] }],
    agent: {},
    signal: new AbortController().signal,
  })
  assert.equal(decision.kind, 'enter')
  assert.equal(decision.messages[0].content[0].text, 'use {{AWS_PROD_KEY_1}}')
  assert.equal(decision.messages[0].id, 'm1', 'message identity is preserved')

  // list never returns values
  const listed = await tool.execute({ action: 'list' })
  assert.equal(listed.secrets.length, 1)
  assert.ok(!JSON.stringify(listed).includes('AKIAIOSFODNN7EXAMPLE'))

  // remove is also immediate
  await tool.execute({ action: 'remove', id: added.added.id })
  const after = await waterfall('agent/pre-step', {
    messages: [{ id: 'm2', role: 'user', content: [{ type: 'text', text: 'use AKIAIOSFODNN7EXAMPLE' }] }],
    agent: {},
    signal: new AbortController().signal,
  })
  // Managed value gone; the pattern now matches as "unknown" and is gated.
  assert.ok(!after.messages[0].content[0].text.includes('{{AWS_PROD_KEY_1}}'))

  await rm(dir, { recursive: true, force: true })
})

test('pre-step passes through untouched when nothing matches', async () => {
  const { waterfall, dir } = await setup()
  const payload = { messages: [{ id: 'm1', role: 'user', content: [{ type: 'text', text: 'hello' }] }] }
  const decision = await waterfall('agent/pre-step', payload)
  assert.equal(decision.messages[0].content[0].text, 'hello')
  await rm(dir, { recursive: true, force: true })
})

test('a tool call with a managed secret is gated by the one-step prompt', async () => {
  const asked = []
  const userQuestions = {
    async ask(request) {
      asked.push(request)
      // Simulate "Select All" on the checklist.
      const options = request.questions[0].options
      return { answers: [{ id: request.questions[0].id, selected: options.map((o) => o.label) }] }
    },
  }
  const { registeredTools, waterfall, dir } = await setup({ userQuestions })
  const tool = registeredTools.find((t) => t.name === 'pii_secret')
  await tool.execute({ action: 'add', label: 'AWS', value: 'AKIAIOSFODNN7EXAMPLE' })

  const decision = await waterfall('tools/pre-execute', {
    name: 'bash',
    arguments: { command: 'echo AKIAIOSFODNN7EXAMPLE' },
    agent: {},
    signal: new AbortController().signal,
  })
  assert.equal(decision.kind, 'allow', 'explicit allow must pass through to next()')
  assert.equal(asked.length, 1, 'exactly one prompt')
  const q = asked[0].questions[0]
  assert.equal(q.multiSelect, true)
  assert.ok(q.options.some((o) => o.label === '__select_all__'))
  // Raw value must never reach the prompt payload.
  assert.ok(!JSON.stringify(asked[0]).includes('AKIAIOSFODNN7EXAMPLE'))
  await rm(dir, { recursive: true, force: true })
})

test('a denied exposure stops the tool call with a reason', async () => {
  const userQuestions = {
    async ask() { return { answers: [{ id: 'pii-secrets-expose', selected: [] }] } },
  }
  const { registeredTools, waterfall, dir } = await setup({ userQuestions })
  const tool = registeredTools.find((t) => t.name === 'pii_secret')
  await tool.execute({ action: 'add', label: 'AWS', value: 'AKIAIOSFODNN7EXAMPLE' })

  const decision = await waterfall('tools/pre-execute', {
    name: 'bash',
    arguments: { command: 'cat .env' },
    agent: {},
    signal: new AbortController().signal,
  })
  // `cat .env` names no secret, but its OUTPUT can contain one. A terminal tool
  // must pause even with clean arguments — this is the git-log/cat-env case.
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /Blocked by PII Secrets Manager/)

  const denied = await waterfall('tools/pre-execute', {
    name: 'bash',
    arguments: { command: 'echo AKIAIOSFODNN7EXAMPLE' },
    agent: {},
    signal: new AbortController().signal,
  })
  assert.equal(denied.kind, 'deny')
  assert.match(denied.reason, /Blocked by PII Secrets Manager/)
  await rm(dir, { recursive: true, force: true })
})

test('post-execute scrubs secrets out of tool output', async () => {
  const { registeredTools, waterfall, dir } = await setup()
  const tool = registeredTools.find((t) => t.name === 'pii_secret')
  await tool.execute({ action: 'add', label: 'Key', value: 'TOP_SECRET_VALUE_123' })

  const decision = await waterfall('tools/post-execute', {
    name: 'read',
    arguments: { path: '.env' },
    content: [{ type: 'text', text: 'TOKEN=TOP_SECRET_VALUE_123' }],
    agent: {},
    signal: new AbortController().signal,
  })
  assert.equal(decision.kind, 'accept')
  assert.ok(!decision.content[0].text.includes('TOP_SECRET_VALUE_123'))
  assert.match(decision.content[0].text, /\{\{KEY_1\}\}/)
  await rm(dir, { recursive: true, force: true })
})

test('vault on disk contains no plaintext secret', async () => {
  const { registeredTools, dir } = await setup()
  const tool = registeredTools.find((t) => t.name === 'pii_secret')
  await tool.execute({ action: 'add', label: 'Key', value: 'PLAINTEXT_MUST_NOT_APPEAR' })
  const raw = await readFile(join(dir, 'vault.json'), 'utf8')
  assert.ok(!raw.includes('PLAINTEXT_MUST_NOT_APPEAR'))
  assert.ok(raw.includes('aes-256-gcm'))
  await rm(dir, { recursive: true, force: true })
})
