/**
 * UI adapters for the one-step exposure prompt.
 *
 * Contract: every adapter implements `askExposure(request)` and resolves to
 * `{ expose: string[], reveal: boolean, remember?: 'once'|'session' }`.
 *
 * Hard rules encoded here, not in the callers:
 *  - Values are masked by default; `reveal` toggles display only.
 *  - Multiple findings are ALWAYS a multi-select checklist with `Select All`.
 *  - Exactly one round-trip per prompt: no wizards, no second confirmation.
 *  - Failure/absence of a UI degrades to "do not expose" (fail closed).
 *
 * @module dsh-pii-secrets/ui
 */

const SELECT_ALL = '__select_all__'

/** Build the checklist label for one finding. Masked unless revealed. */
export function describeFinding(finding, revealed = false) {
  // Raw values are never on the finding object; they live behind revealValue().
  const shown = revealed && typeof finding.revealValue === 'function' ? finding.revealValue() : finding.masked
  const origin = finding.path ? ` (${finding.path})` : ''
  return `${finding.label}${origin}: ${shown}`
}

/**
 * Normalize any adapter answer into a decision. Anything malformed is treated
 * as a refusal — the gate must never expose on an ambiguous answer.
 */
export function normalizeDecision(answer, findings) {
  if (!answer || typeof answer !== 'object') return { expose: [], reveal: false }
  const selected = Array.isArray(answer.selected) ? answer.selected : []
  const ids = new Set(findings.map((f) => f.id))
  const expose = selected.filter((value) => ids.has(value))
  return { expose, reveal: Boolean(answer.reveal), remember: answer.remember }
}

/**
 * TUI adapter backed by the harness user-questions seam (`ctx.userQuestions`),
 * which renders as a multi-select list with a header — the same surface the
 * built-in ask tool uses, so no extra dependency and no terminal takeover.
 *
 * Findings are identified by a short, stable token (not the raw value) so the
 * answer mapping cannot be spoofed by a value containing a label.
 */
export class UserQuestionsAdapter {
  /** @param {object} options
   * @param {(name: string) => any} options.getService resolves `ctx.get('userQuestions')`
   * @param {object} options.logger
   */
  constructor({ getService, logger } = {}) {
    this._get = getService
    this._log = logger
  }

  get available() {
    return Boolean(this._get?.())
  }

  async askExposure(request) {
    const service = this._get?.()
    if (!service) return { selected: [], reveal: false }
    const findings = request.findings
    const options = [
      ...findings.map((finding, index) => ({
        label: tokenFor(index),
        description: describeFinding(finding, false),
      })),
      // Select All is always offered: with one item it is a plain "yes" and
      // with many it satisfies the required multi-select checklist.
      { label: SELECT_ALL, description: 'Expose every item listed above' },
    ]

    try {
      const answer = await service.ask({
        agent: request.agent,
        signal: request.signal,
        questions: [
          {
            id: 'pii-secrets-expose',
            header: 'Secret exposure',
            question: request.question ?? defaultQuestion(request),
            detail: renderDetail(request),
            multiSelect: true,
            options,
          },
        ],
      })
      const picked = answer?.answers?.[0]?.selected ?? []
      const selectAll = picked.includes(SELECT_ALL)
      const selected = selectAll
        ? findings.map((f) => f.id)
        : picked.map((label) => findings[Number(label.split('#')[1])]?.id).filter(Boolean)
      return { selected, reveal: false }
    } catch (error) {
      this._log?.(`[pii-secrets] exposure prompt failed, denying: ${error.message}`)
      return { selected: [], reveal: false }
    }
  }
}

/**
 * TUI adapter based on inquirer, for hosts that expose no user-questions
 * service (headless CLI). Uses a checkbox list plus a `confirm` for reveal;
 * both are rendered in ONE prompt session by inquirer's single `prompt()` call.
 */
export class InquirerAdapter {
  constructor({ log = console.log } = {}) {
    this._log = log
  }

  async available() {
    try {
      await import('inquirer')
      return true
    } catch {
      return false
    }
  }

  async askExposure(request) {
    let inquirer
    try {
      inquirer = (await import('inquirer')).default
    } catch {
      return { selected: [], reveal: false }
    }
    const findings = request.findings ?? []
    const choices = [
      ...findings.map((finding, index) => ({
        name: `${tokenFor(index)} ${describeFinding(finding, false)}`,
        value: finding.id,
        checked: false,
      })),
      { name: `${SELECT_ALL} — expose everything`, value: SELECT_ALL, checked: false },
    ]
    // One interactive session = one step for the user. The eye/reveal is the
    // third question, asked only after something is selected, and it re-prints
    // the chosen rows in the clear instead of truncating them.
    const answers = await inquirer.prompt([
      {
        type: 'checkbox',
        name: 'selected',
        message: request.question ?? defaultQuestion(request),
        choices,
        pageSize: Math.min(choices.length + 2, 15),
      },
      {
        type: 'confirm',
        name: 'reveal',
        message: 'Reveal the selected values on screen? (they are masked by default)',
        default: false,
        when: (current) => (current.selected ?? []).length > 0,
      },
    ])
    const selected = answers.selected?.includes(SELECT_ALL)
      ? findings.map((f) => f.id)
      : answers.selected ?? []
    if (answers.reveal) {
      for (const finding of findings.filter((f) => selected.includes(f.id))) {
        this._log(`  👁 ${describeFinding(finding, true)}`)
      }
    }
    return { selected, reveal: Boolean(answers.reveal) }
  }
}

/**
 * Web/GUI adapter: delegates to an RPC callback the browser half registers
 * (see web/client.js). The browser renders the checklist and eye toggle; this
 * shim just carries the request and awaits the answer, so the gate stays
 * headless and transport-agnostic.
 */
export class WebAdapter {
  constructor({ requestExposure, timeoutMs = 120_000 } = {}) {
    this._request = requestExposure
    this._timeout = timeoutMs
  }

  get available() {
    return typeof this._request === 'function'
  }

  async askExposure(request) {
    if (!this.available) return { selected: [], reveal: false }
    const findings = request.findings ?? []
    const payload = {
      id: request.requestId,
      action: request.action,
      question: request.question ?? defaultQuestion(request),
      multiSelect: findings.length > 1,
      // Masked values only. The browser asks for a single raw value through the
      // `reveal()` callback when (and only when) the user clicks the eye.
      findings: findings.map((finding, index) => ({
        id: finding.id,
        token: tokenFor(index),
        label: finding.label,
        kind: finding.kind,
        path: finding.path,
        masked: finding.masked,
        revealable: typeof finding.revealValue === 'function',
      })),
    }
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(new Error('exposure prompt timed out')), this._timeout)
    try {
      const answer = await this._request(payload, {
        signal: controller.signal,
        // One row at a time, by id: the browser can never enumerate the vault.
        reveal: async (findingId) => {
          const finding = findings.find((f) => f.id === findingId)
          return typeof finding?.revealValue === 'function' ? finding.revealValue() : null
        },
      })
      const selected = Array.isArray(answer?.selected) ? answer.selected : []
      return {
        // Drop ids the UI invented: an answer may only name real findings.
        selected: selected.filter((id) => findings.some((f) => f.id === id)),
        reveal: Boolean(answer?.reveal),
      }
    } catch {
      return { selected: [], reveal: false }
    } finally {
      clearTimeout(timer)
    }
  }
}

/** Pick the best available adapter once, preserving the one-step contract. */
export function selectAdapter({ ctx, logger, web }) {
  const uq = new UserQuestionsAdapter({ getService: () => ctx.get('userQuestions'), logger })
  if (uq.available) return uq
  if (web?.available) return web
  return new InquirerAdapter()
}

function tokenFor(index) {
  return `item#${index}`
}

function defaultQuestion(request) {
  return `Allow "${request.action}" to expose ${request.findings.length} secret(s)?`
}

function renderDetail(request) {
  const parts = []
  if (request.detail) parts.push(request.detail)
  parts.push('Values are masked. Nothing is redacted if you allow this action.')
  return parts.join('\n')
}
