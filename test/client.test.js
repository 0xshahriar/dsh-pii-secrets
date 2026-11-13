import assert from 'node:assert/strict'
import { test } from 'node:test'

import { installDOM } from './dom-shim.js'

const { body } = installDOM()
const { createExposurePrompt } = await import('../web/client.js')

const request = (n = 2) => ({
  id: 'r1',
  action: 'upload',
  question: 'Allow "upload" to expose 2 secrets?',
  findings: Array.from({ length: n }, (_, i) => ({
    id: `f${i}`,
    token: `item#${i}`,
    label: ['AWS prod key', 'Email address'][i] ?? `Secret ${i}`,
    kind: 'pii',
    path: i === 0 ? 'body' : undefined,
    masked: `sk-l••••${i}`,
    revealable: true,
  })),
})

function mountPrompt(rq = request(), host = { reveal: async (id) => `RAW_${id}` }) {
  const container = document.createElement('div')
  body.append(container)
  let resolve
  const done = new Promise((r) => { resolve = r })
  const prompt = createExposurePrompt({ host, onDone: resolve })
  const mounted = prompt.mount(container, rq)
  return { container, done, mounted }
}

test('renders one row per finding, all masked by default', () => {
  const { container } = mountPrompt()
  const rows = container.findAllMatching('li', 'pii-row')
  assert.equal(rows.length, 2)
  const values = container.findAllMatching('code', 'pii-row-value')
  assert.equal(values[0].textContent, 'sk-l••••0')
  assert.ok(!container.textContent.includes('RAW_'))
})

test('Select All exists only for multiple findings and toggles every box', () => {
  const { container } = mountPrompt(request(3))
  const selectAll = container.querySelector('input.pii-select-all')
  assert.ok(selectAll, 'Select All must exist for a multi-item checklist')
  selectAll.clickCheck(true)
  const boxes = container.findAllMatching('input', 'pii-check').filter((n) => n !== selectAll)
  assert.equal(boxes.length, 3)
  assert.ok(boxes.every((b) => b.checked))
  selectAll.clickCheck(false)
  assert.ok(boxes.every((b) => !b.checked))
})

test('single finding renders no Select All but still a checklist row', () => {
  const { container } = mountPrompt(request(1))
  assert.equal(container.querySelector('input.pii-select-all'), null)
  assert.equal(container.findAllMatching('li', 'pii-row').length, 1)
})

test('eye toggle reveals on demand and hides again', async () => {
  let revealCalls = 0
  const { container } = mountPrompt(request(2), {
    reveal: async (id) => { revealCalls += 1; return `RAW_${id}` },
  })
  const eye = container.querySelector('button.pii-eye')
  assert.equal(eye.getAttribute('aria-pressed'), 'false')
  eye.click()
  await new Promise((r) => setImmediate(r))
  const revealed = container.findAllMatching('code', 'pii-row-value')[0]
  assert.equal(revealed.textContent, 'RAW_f0')
  assert.equal(revealCalls, 1)

  const eyeAgain = container.querySelector('button.pii-eye')
  assert.equal(eyeAgain.getAttribute('aria-pressed'), 'true')
  eyeAgain.click()
  await new Promise((r) => setImmediate(r))
  assert.equal(container.findAllMatching('code', 'pii-row-value')[0].textContent, 'sk-l••••0')
})

test('submitting resolves only the selected ids', async () => {
  const { container, done } = mountPrompt(request(2))
  const boxes = container.findAllMatching('input', 'pii-check').filter((n) => !n.attributes.class?.includes('select-all'))
  boxes[1].clickCheck(true)
  const submit = container.findAllMatching('button', 'pii-btn-primary')[0]
  submit.click()
  const answer = await done
  assert.deepEqual(answer.selected, ['f1'])
  assert.equal(answer.reveal, false)
})

test('cancel resolves to an empty selection (fail closed)', async () => {
  const { container, done } = mountPrompt(request(2))
  const selectAll = container.querySelector('input.pii-select-all')
  selectAll.clickCheck(true)
  const cancel = container.findAllMatching('button', 'pii-btn-secondary')[0]
  cancel.click()
  assert.deepEqual(await done, { selected: [], reveal: false })
})

test('reveal flag is true when a value was revealed before submitting', async () => {
  const { container, done } = mountPrompt(request(1))
  container.querySelector('button.pii-eye').click()
  await new Promise((r) => setImmediate(r))
  container.findAllMatching('button', 'pii-btn-primary')[0].click()
  const answer = await done
  assert.equal(answer.reveal, true)
  assert.deepEqual(answer.selected, [])
})
