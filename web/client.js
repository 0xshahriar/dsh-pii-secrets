/**
 * Browser half of dsh-pii-secrets (dual-face plugin).
 *
 * Renders the ONE-STEP exposure prompt used when a tool call would surface a
 * secret: a multi-select checklist with a Select All option, and an eye toggle
 * per row that reveals the masked value on demand.
 *
 * Values arrive masked from the host (`masked`); the host never ships raw
 * secret values to the browser. The eye toggle asks the host to reveal one row
 * only when the user clicks it, keeping the default state hidden.
 *
 * Registered as a settings tab; the host calls `window.__PII_SECRETS_EXPOSE__`
 * (installed here) with a request and receives a promise for the answer.
 *
 * @module dsh-pii-secrets/client
 */

const SELECT_ALL = '__select_all__'

/** Minimal DOM helper; no framework dependency so the bundle stays tiny. */
function h(tag, props = {}, children = []) {
  const node = document.createElement(tag)
  for (const [key, value] of Object.entries(props)) {
    if (key === 'class') node.className = value
    else if (key === 'text') node.textContent = value
    else if (key.startsWith('on')) node.addEventListener(key.slice(2).toLowerCase(), value)
    else if (value !== undefined && value !== null) node.setAttribute(key, value)
  }
  for (const child of [].concat(children)) if (child) node.append(child)
  return node
}

/**
 * The checklist component. One step: choose rows, optionally reveal, submit.
 * Cancel resolves to an empty selection (fail closed).
 */
export function createExposurePrompt({ host, onDone }) {
  const state = {
    selected: new Set(),
    revealed: new Set(),
    revealedValues: new Map(),
  }

  const rows = new Map()

  function findingRow(finding) {
    const revealed = state.revealed.has(finding.id)
    const shown = revealed ? state.revealedValues.get(finding.id) ?? finding.masked : finding.masked

    const label = h('span', { class: 'pii-row-label', text: finding.label })
    const path = finding.path ? h('code', { class: 'pii-row-path', text: finding.path }) : null
    const value = h('code', { class: `pii-row-value${revealed ? ' revealed' : ''}`, text: shown })

    // Eye toggle: requests the raw value from the host on first click only.
    const eye = h('button', {
      class: 'pii-eye',
      type: 'button',
      'aria-pressed': String(revealed),
      'aria-label': revealed ? 'Hide value' : 'Reveal value',
      title: revealed ? 'Hide value' : 'Reveal value',
      onclick: async (event) => {
        event.preventDefault()
        event.stopPropagation()
        if (state.revealed.has(finding.id)) {
          state.revealed.delete(finding.id)
        } else {
          if (!state.revealedValues.has(finding.id) && typeof host.reveal === 'function') {
            const raw = await host.reveal(finding.id)
            if (raw == null) return
            state.revealedValues.set(finding.id, raw)
          }
          state.revealed.add(finding.id)
        }
        rerenderRow(finding)
      },
    }, [h('span', { class: 'pii-eye-glyph', text: revealed ? '🙈' : '👁' })])

    const checkbox = h('input', {
      type: 'checkbox',
      class: 'pii-check',
      'aria-label': `Expose ${finding.label}`,
      onchange: (event) => {
        if (event.target.checked) state.selected.add(finding.id)
        else state.selected.delete(finding.id)
        syncSelectAll()
      },
    })

    return h('li', { class: 'pii-row', 'data-id': finding.id }, [
      h('label', { class: 'pii-row-main' }, [checkbox, label, path, value]),
      eye,
    ])
  }

  let selectAllInput

  function rerenderRow(finding) {
    const current = rows.get(finding.id)
    if (!current) return
    const container = current
    const replacement = findingRow(finding)
    rows.set(finding.id, replacement)
    container.replaceWith(replacement)
  }

  /**
   * Programmatic checkbox updates do not fire `change` in a real browser (the
   * property setter is silent); keep that invariant explicit here.
   */
  function setChecked(input, checked) {
    if (input) input.checked = checked
  }

  function syncSelectAll() {
    if (!selectAllInput) return
    const all = Number(selectAllInput.dataset.total ?? 0)
    // Programmatic sync must not re-enter syncSelectAll via a change event.
    setChecked(selectAllInput, state.selected.size > 0 && state.selected.size === all)
    selectAllInput.indeterminate = state.selected.size > 0 && state.selected.size < all
  }

  function render(request) {
    rows.clear()
    state.selected = new Set()
    state.revealed = new Set()
    state.revealedValues = new Map()

    const findings = request.findings ?? []
    const list = h('ul', { class: 'pii-list' })
    for (const finding of findings) {
      const row = findingRow(finding)
      rows.set(finding.id, row)
      list.append(row)
    }

    // Built AFTER the rows exist so Select All can drive every checkbox.
    const checkboxInputs = new Map(
      [...rows.entries()].map(([id, node]) => [id, node.querySelector('input.pii-check')]),
    )

    selectAllInput = findings.length > 1
      ? h('input', {
          type: 'checkbox',
          class: 'pii-check pii-select-all',
          'data-total': String(findings.length),
          onchange: (event) => {
            const checked = event.target.checked
            state.selected = checked ? new Set(findings.map((f) => f.id)) : new Set()
            for (const input of checkboxInputs.values()) setChecked(input, checked)
            syncSelectAll()
          },
        })
      : null

    return h('div', { class: 'pii-prompt', role: 'dialog', 'aria-modal': 'true' }, [
      h('h2', { class: 'pii-title', text: 'Secrets about to be exposed' }),
      h('p', { class: 'pii-detail', text: request.question ?? `Allow "${request.action}" to expose these?` }),
      selectAllInput
        ? h('label', { class: 'pii-select-all-row' }, [selectAllInput, h('span', { text: 'Select all' })])
        : null,
      list,
      h('p', { class: 'pii-hint', text: 'Values stay hidden until you click the eye. Nothing is exposed unless you submit.' }),
      h('div', { class: 'pii-actions' }, [
        h('button', {
          class: 'pii-btn pii-btn-secondary',
          type: 'button',
          text: 'Cancel',
          onclick: () => finish({ selected: [], reveal: false }),
        }),
        h('button', {
          class: 'pii-btn pii-btn-primary',
          type: 'button',
          text: 'Allow selected',
          onclick: () =>
            finish({
              selected: [...state.selected],
              reveal: state.revealed.size > 0,
            }),
        }),
      ]),
    ])
  }

  let finish = () => {}

  /** Mount into a container; returns a dispose function. */
  function mount(container, request) {
    return new Promise((resolve) => {
      finish = (answer) => {
        resolve(answer)
        onDone?.(answer)
        container.replaceChildren()
      }
      container.replaceChildren(render(request))
    })
  }

  return { mount }
}

/**
 * Install the host-callable hook for a running dsh web client.
 *
 * The host calls `window.__PII_SECRETS_EXPOSE__(request, { reveal })`; the
 * `reveal` transport is per-prompt (the host resolves one row on demand), so it
 * is handed to the component rather than captured at install time.
 */
export function install(fallbackHost = { reveal: async () => null }) {
  if (typeof window === 'undefined') return
  window.__PII_SECRETS_EXPOSE__ = (request, transport) =>
    new Promise((resolve) => {
      const container = document.createElement('div')
      container.className = 'pii-secrets-overlay'
      document.body.append(container)
      const host = {
        reveal: typeof transport?.reveal === 'function' ? transport.reveal : fallbackHost.reveal,
      }
      const prompt = createExposurePrompt({
        host,
        onDone: (answer) => {
          resolve(answer)
          container.remove()
        },
      })
      prompt.mount(container, request)
    })
}

export default { install, createExposurePrompt }
