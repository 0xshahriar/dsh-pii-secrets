import assert from 'node:assert/strict'
import { test } from 'node:test'

import { ACTIONS, ExposurePolicy, classifyTool } from '../src/policy.js'
import { makeEntry, SecretStore } from '../src/vault.js'
import { WebAdapter, normalizeDecision } from '../src/ui.js'

const MANAGED = 'sk-live-REALVALUE1234567890'
const store = () =>
  new SecretStore([
    makeEntry({ id: 'k1', label: 'OpenAI', value: MANAGED, placeholder: '{{API_KEY_1}}' }),
    makeEntry({ id: 'k2', label: 'AWS', value: 'wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY', placeholder: '{{AWS_1}}' }),
  ])

/** A spy adapter that records requests and answers a scripted selection. */
function spyAdapter(responses = []) {
  const calls = []
  let i = 0
  return {
    calls,
    async askExposure(request) {
      calls.push(request)
      const next = responses[i++] ?? { selected: [], reveal: false }
      return next
    },
  }
}

const silent = () => {}

test('classify separates managed (silent) from unknown (needs a decision)', () => {
  const p = new ExposurePolicy({ store: store(), adapter: spyAdapter(), logger: silent })
  const { managed, unknown } = p.classify(`token ${MANAGED} and mail a@b.com`)
  assert.equal(managed.length, 1)
  assert.ok(unknown.some((f) => f.ruleId === 'email'))
  // The managed value must never appear in the unknown list.
  assert.ok(!unknown.some((f) => f.value === MANAGED))
})

test('protectOutbound redacts managed secrets with NO prompt', async () => {
  const adapter = spyAdapter()
  const p = new ExposurePolicy({ store: store(), adapter, logger: silent })
  const result = await p.protectOutbound({ text: `use ${MANAGED}` })
  assert.equal(result.value.text, 'use {{API_KEY_1}}')
  assert.equal(adapter.calls.length, 0, 'managed secrets must be silent')
})

test('protectOutbound withholds an unknown secret when the user refuses', async () => {
  const adapter = spyAdapter([{ selected: [], reveal: false }])
  const p = new ExposurePolicy({ store: store(), adapter, logger: silent })
  const result = await p.protectOutbound({ text: 'contact a@b.com' })
  assert.equal(adapter.calls.length, 1, 'exactly one prompt')
  assert.ok(!result.value.text.includes('a@b.com'))
  assert.match(result.value.text, /\{\{REDACTED_EMAIL_[0-9a-f]{6}\}\}/)
})

test('protectOutbound keeps an allowed unknown secret', async () => {
  const p0 = new ExposurePolicy({ store: store(), adapter: spyAdapter(), logger: silent })
  const findings = p0.classify('contact a@b.com').unknown
  const adapter = spyAdapter([{ selected: findings.map((f) => f.id), reveal: false }])
  const p = new ExposurePolicy({ store: store(), adapter, logger: silent })
  const result = await p.protectOutbound({ text: 'contact a@b.com' })
  assert.equal(result.value.text, 'contact a@b.com')
})

test('protectOutbound in detect mode never prompts and logs fingerprints only', async () => {
  const logs = []
  const adapter = spyAdapter()
  const p = new ExposurePolicy({
    store: store(),
    adapter,
    config: { unknownSecretPolicy: 'detect' },
    logger: (m) => logs.push(m),
  })
  const result = await p.protectOutbound({ text: 'a@b.com and AKIAIOSFODNN7EXAMPLE' })
  assert.equal(adapter.calls.length, 0)
  assert.equal(logs.length, 2)
  for (const line of logs) assert.ok(!line.includes('a@b.com') && !line.includes('AKIAIOSFODNN7EXAMPLE'))
})

test('protectOutbound in block mode refuses without prompting', async () => {
  const adapter = spyAdapter()
  const p = new ExposurePolicy({ store: store(), adapter, config: { unknownSecretPolicy: 'block' }, logger: silent })
  const result = await p.protectOutbound({ text: 'x AKIAIOSFODNN7EXAMPLE' })
  assert.equal(result.blocked, true)
  assert.equal(adapter.calls.length, 0)
})

test('gateToolCall allows a read of an unrelated path when the vault is empty', async () => {
  const adapter = spyAdapter()
  const p = new ExposurePolicy({ store: new SecretStore(), adapter, logger: silent })
  const decision = await p.gateToolCall({ name: 'read', arguments: { path: './README.md' } })
  assert.deepEqual(decision, { kind: 'allow' })
  assert.equal(adapter.calls.length, 0)
})

test('gateToolCall gates a read-capable tool when the vault is non-empty', async () => {
  // A path in the arguments is not a secret, but the file may hold one, so the
  // call is gated on capability rather than on a literal match.
  const adapter = spyAdapter([{ selected: [], reveal: false }])
  const p = new ExposurePolicy({ store: store(), adapter, logger: silent })
  const decision = await p.gateToolCall({ name: 'read', arguments: { path: './README.md' } })
  assert.equal(decision.kind, 'deny')
  assert.equal(adapter.calls.length, 1)
})

test('gateToolCall allows a non-read tool with clean arguments', async () => {
  const adapter = spyAdapter()
  const p = new ExposurePolicy({ store: store(), adapter, logger: silent })
  const decision = await p.gateToolCall({ name: 'todo_write', arguments: { items: ['a'] } })
  assert.deepEqual(decision, { kind: 'allow' })
  assert.equal(adapter.calls.length, 0)
})

test('gateToolCall denies a terminal tool touching a managed secret when refused', async () => {
  const adapter = spyAdapter([{ selected: [], reveal: false }])
  const p = new ExposurePolicy({ store: store(), adapter, logger: silent })
  const decision = await p.gateToolCall({ name: 'bash', arguments: { command: `git log --grep=${MANAGED}` } })
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /PII Secrets Manager/)
})

test('gateToolCall allows a terminal tool when the user exposes it', async () => {
  const adapter = spyAdapter([{ selected: ['managed:k1'], reveal: true }])
  const p = new ExposurePolicy({ store: store(), adapter, logger: silent })
  const decision = await p.gateToolCall({ name: 'bash', arguments: { command: `echo ${MANAGED}` } })
  assert.equal(decision.kind, 'allow')
})

test('publish/upload gate is a multi-select checklist containing Select All', async () => {
  const adapter = spyAdapter([{ selected: ['managed:k1', 'managed:k2'], reveal: false }])
  const p = new ExposurePolicy({ store: store(), adapter, logger: silent })
  const decision = await p.gateToolCall({
    name: 'upload_file',
    arguments: { path: 'a.env', body: `${MANAGED} wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY` },
  })
  assert.equal(decision.kind, 'allow')
  const request = adapter.calls[0]
  assert.equal(request.action, ACTIONS.upload)
  assert.equal(request.findings.length, 2, 'both managed secrets are listed')
  // The prompt payload must not contain raw values.
  assert.ok(!JSON.stringify(request).includes(MANAGED), 'payload must not carry raw values')
})

test('publish gate denies when nothing is selected (default-deny)', async () => {
  const adapter = spyAdapter([{ selected: [], reveal: false }])
  const p = new ExposurePolicy({ store: store(), adapter, logger: silent })
  const decision = await p.gateToolCall({ name: 'publish', arguments: { body: MANAGED } })
  assert.equal(decision.kind, 'deny')
})

test('session remember skips a repeated identical prompt', async () => {
  const adapter = spyAdapter([{ selected: ['managed:k1'], reveal: false, remember: 'session' }])
  const p = new ExposurePolicy({ store: store(), adapter, logger: silent })
  await p.gateToolCall({ name: 'bash', arguments: { cmd: MANAGED } })
  await p.gateToolCall({ name: 'bash', arguments: { cmd: MANAGED } })
  assert.equal(adapter.calls.length, 1)
})

test('scrubToolResult redacts managed values from tool output silently', async () => {
  const adapter = spyAdapter()
  const p = new ExposurePolicy({ store: store(), adapter, logger: silent })
  const { value, redactions } = p.scrubToolResult([{ type: 'text', text: `leaked ${MANAGED}` }])
  assert.equal(value[0].text, 'leaked {{API_KEY_1}}')
  assert.equal(value[0].type, 'text', 'block type must be preserved')
  assert.equal(redactions.length, 1)
  assert.equal(adapter.calls.length, 0)
})

test('scrubToolResult reports no change when nothing matches', () => {
  const p = new ExposurePolicy({ store: store(), adapter: spyAdapter(), logger: silent })
  assert.equal(p.scrubToolResult([{ type: 'text', text: 'clean' }]).value, undefined)
})

test('hot CRUD is visible to the very next decision', async () => {
  const s = store()
  const p = new ExposurePolicy({ store: s, adapter: spyAdapter(), logger: silent })
  assert.equal((await p.protectOutbound({ t: 'NEWSECRET42' })).value.t, 'NEWSECRET42')
  s.upsert(makeEntry({ id: 'k3', label: 'New', value: 'NEWSECRET42', placeholder: '{{NEW_1}}' }))
  assert.equal((await p.protectOutbound({ t: 'NEWSECRET42' })).value.t, '{{NEW_1}}')
  s.remove('k3')
  assert.equal((await p.protectOutbound({ t: 'NEWSECRET42' })).value.t, 'NEWSECRET42')
})

test('classifyTool routes the known action classes', () => {
  assert.equal(classifyTool('publish', {}), ACTIONS.publish)
  assert.equal(classifyTool('upload_file', {}), ACTIONS.upload)
  assert.equal(classifyTool('bash', {}), ACTIONS.terminal)
  assert.equal(classifyTool('custom_fn', { files: ['a'] }), ACTIONS.upload)
  assert.equal(classifyTool('mystery', {}), ACTIONS.toolCall)
})

test('a failing adapter fails closed (denies)', async () => {
  const p = new ExposurePolicy({
    store: store(),
    adapter: { askExposure: async () => { throw new Error('UI gone') } },
    logger: silent,
  })
  await assert.rejects(() => p.gateToolCall({ name: 'bash', arguments: { c: MANAGED } }), /UI gone/)
})

test('WebAdapter returns a refusal when the transport errors', async () => {
  const web = new WebAdapter({ requestExposure: async () => { throw new Error('rpc down') } })
  const answer = await web.askExposure({ findings: [{ id: 'x', label: 'X', masked: 'a•••' }], action: 'upload' })
  assert.deepEqual(answer, { selected: [], reveal: false })
})

test('WebAdapter sends masked values only', async () => {
  let payload
  const web = new WebAdapter({ requestExposure: async (p) => { payload = p; return { selected: [], reveal: false } } })
  await web.askExposure({
    findings: [{ id: 'a', label: 'Email', masked: 'a•••@b.com', kind: 'pii', path: 'body' }],
    action: 'upload',
  })
  assert.equal(payload.findings[0].masked, 'a•••@b.com')
  assert.equal(payload.findings[0].value, undefined)
  assert.equal(payload.multiSelect, false)
})

test('normalizeDecision drops ids the UI invented', () => {
  const findings = [{ id: 'a' }, { id: 'b' }]
  assert.deepEqual(normalizeDecision({ selected: ['a', 'zzz'] }, findings).expose, ['a'])
  assert.deepEqual(normalizeDecision(null, findings), { expose: [], reveal: false })
})
