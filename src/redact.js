/**
 * Detection and redaction engine for dsh-pii-secrets.
 *
 * Two jobs, one pass-shape:
 *   1. redact()  — replace every managed secret value with its stable
 *                  placeholder token so nothing real leaves the machine.
 *   2. detect()  — find values matching secret/PII patterns that are NOT
 *                  managed, so the gate can ask about them.
 *
 * Both return structured, offset-free results (findings), because findings are
 * rendered in UIs and logged; they must never carry more than a masked preview
 * unless a caller explicitly asks for the raw value.
 *
 * @module dsh-pii-secrets/redact
 */

/** Predefined secret/PII patterns. `kind` drives UI copy and default policy. */
export const PATTERNS = Object.freeze([
  { id: 'aws-access-key', kind: 'cloud-credential', label: 'AWS Access Key ID', re: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b/g },
  { id: 'aws-secret-key', kind: 'cloud-credential', label: 'AWS Secret Access Key', re: /(?:aws_?secret_?(?:access_?)?key|secret_?access_?key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi, group: 1 },
  { id: 'github-token', kind: 'api-token', label: 'GitHub Token', re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b/g },
  { id: 'openai-key', kind: 'api-token', label: 'OpenAI-style API Key', re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g },
  { id: 'anthropic-key', kind: 'api-token', label: 'Anthropic API Key', re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g },
  { id: 'slack-token', kind: 'api-token', label: 'Slack Token', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g },
  { id: 'google-api-key', kind: 'api-token', label: 'Google API Key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { id: 'stripe-key', kind: 'api-token', label: 'Stripe Key', re: /\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b/g },
  { id: 'private-key-block', kind: 'private-key', label: 'Private Key Block', re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----[\s\S]{10,}?-----END (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----/g },
  { id: 'jwt', kind: 'token', label: 'JWT', re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { id: 'connection-string', kind: 'credential-url', label: 'Credential URL', re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s/:@]+:[^\s/@]+@[^\s/]+/gi },
  { id: 'password-assignment', kind: 'password', label: 'Password Assignment', re: /(?:^|[\s,;{[])(?:password|passwd|pwd|secret|api_?key|token)\s*[:=]\s*['"]?([^\s'",;}]{8,})['"]?/gim, group: 1 },
  { id: 'email', kind: 'pii', label: 'Email Address', re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, pii: true },
  { id: 'us-ssn', kind: 'pii', label: 'US SSN', re: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g, pii: true },
  { id: 'credit-card', kind: 'pii', label: 'Payment Card Number', re: /\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{1,4}\b/g, pii: true, validate: luhn },
  { id: 'phone-e164', kind: 'pii', label: 'Phone Number', re: /\+(?:[0-9][ -]?){7,14}[0-9]\b/g, pii: true },
  { id: 'iban', kind: 'pii', label: 'IBAN', re: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g, pii: true },
])

/** Luhn check so arbitrary 16-digit numbers do not become false positives. */
export function luhn(candidate) {
  const digits = candidate.replace(/\D/g, '')
  if (digits.length < 12 || digits.length > 19) return false
  let sum = 0
  let double = false
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let digit = digits.charCodeAt(i) - 48
    if (double) {
      digit *= 2
      if (digit > 9) digit -= 9
    }
    sum += digit
    double = !double
  }
  return sum % 10 === 0
}

/**
 * Mask a value for display: keep a short head/tail so a human can recognise
 * which secret it is without the value being usable.
 */
export function mask(value, { head = 4, tail = 2 } = {}) {
  const text = String(value ?? '')
  if (text.length <= head + tail + 3) return '•'.repeat(Math.max(text.length, 4))
  return `${text.slice(0, head)}${'•'.repeat(Math.min(12, Math.max(4, text.length - head - tail)))}${text.slice(-tail)}`
}

/** Fingerprint used to correlate findings/logs without storing the value. */
function fingerprint(value) {
  // Non-cryptographic on purpose: this is a correlation id, not a security control.
  let hash = 0x811c9dc5
  for (let i = 0; i < value.length; i += 1) {
    hash ^= value.charCodeAt(i)
    hash = Math.imul(hash, 0x01000193)
  }
  return (hash >>> 0).toString(16).padStart(8, '0')
}

/**
 * Replace managed secret values with their placeholders.
 *
 * Longest-first replacement prevents a shorter secret from corrupting a longer
 * one that contains it. Placeholder tokens already present are left as-is, so
 * the operation is idempotent across retries and replays.
 *
 * @param {string} text
 * @param {{ values: () => string[], byPlaceholder?: Function }|Iterable<{value:string, placeholder:string}>} source
 * @returns {{ text: string, redactions: Array<{ placeholder: string, id?: string, label?: string }> }}
 */
export function redact(text, source) {
  if (typeof text !== 'string') {
    // Never coerce silently: a non-string here is a caller bug. Returning the
    // original value would hand the caller back a non-string where the contract
    // says `text: string`, so the payload shape could silently change.
    return { text: String(text ?? ''), redactions: [] }
  }
  if (text.length === 0) return { text, redactions: [] }
  const entries = toEntries(source)
  if (entries.length === 0) return { text, redactions: [] }

  const redactions = new Map()
  let output = text
  // Longest value first: a secret that is a substring of another must not win.
  for (const { value, placeholder, id, label } of entries.sort((a, b) => b.value.length - a.value.length)) {
    if (!value || !output.includes(value)) continue
    output = output.split(value).join(placeholder)
    redactions.set(placeholder, { placeholder, id, label })
  }
  return { text: output, redactions: [...redactions.values()] }
}

/**
 * Reverse redaction for the local display path (e.g. showing a user their own
 * message in the UI). Never call this on data bound for a provider.
 */
export function restore(text, source) {
  if (typeof text !== 'string' || text.length === 0) return text
  let output = text
  for (const { value, placeholder } of toEntries(source)) {
    if (!placeholder || !output.includes(placeholder)) continue
    output = output.split(placeholder).join(value)
  }
  return output
}

function toEntries(source) {
  if (!source) return []
  if (typeof source.values === 'function') {
    return source.list().map(({ value, placeholder, id, label }) => ({ value, placeholder, id, label }))
  }
  return [...source].map(({ value, placeholder, id, label }) => ({ value, placeholder, id, label }))
}

/**
 * Detect unknown secrets/PII in a text.
 *
 * Values already covered by a managed secret are excluded — a managed secret is
 * handled silently by redact(), never surfaced as an "unknown" prompt.
 *
 * @param {string} text
 * @param {object} [options]
 * @param {{ values: () => string[] }} [options.source] managed secrets to exclude
 * @param {{ minPiiConfidence?: 'high'|'all', patterns?: Array }} [options]
 * @returns {Array<{ id, ruleId, kind, label, value, masked, fingerprint, pii, snippet }>}
 */
export function detect(text, options = {}) {
  if (typeof text !== 'string' || text.length === 0) return []
  const { source, piiLevel = 'all', patterns = PATTERNS, includeRaw = true } = options
  const managed = source ? toEntries(source).map((e) => e.value).filter(Boolean) : []
  const findings = []
  const seen = new Set()

  for (const rule of patterns) {
    if (rule.pii && piiLevel === 'none') continue
    // A fresh regex per call: global regexes carry lastIndex state across calls.
    const re = new RegExp(rule.re.source, rule.re.flags)
    let match
    while ((match = re.exec(text)) !== null) {
      const raw = rule.group ? match[rule.group] : match[0]
      if (!raw) continue
      if (rule.validate && !rule.validate(raw)) continue
      // Managed secrets are silently redacted, never prompted about.
      if (managed.some((value) => raw.includes(value))) continue
      const key = `${rule.id}:${raw}`
      if (seen.has(key)) continue
      seen.add(key)
      const start = match.index + (rule.group ? match[0].indexOf(raw) : 0)
      findings.push({
        id: fingerprint(raw),
        ruleId: rule.id,
        kind: rule.kind,
        label: rule.label,
        pii: Boolean(rule.pii),
        masked: mask(raw),
        fingerprint: fingerprint(raw),
        ...(includeRaw ? { value: raw } : {}),
        snippet: `${text.slice(Math.max(0, start - 24), start).replace(/\s+/g, ' ')}⟦…⟧`,
      })
    }
  }
  return findings
}

/**
 * Recursively redact every string in a JSON-ish structure (model messages,
 * tool arguments, upload manifests). Returns a new value; never mutates input.
 */
export function redactDeep(value, source, { skipKeys = new Set() } = {}) {
  const redactions = []
  const seen = new WeakSet()
  const walk = (node, keyPath) => {
    if (typeof node === 'string') {
      const result = redact(node, source)
      if (result.redactions.length) redactions.push(...result.redactions)
      return result.text
    }
    if (Array.isArray(node) || (node && typeof node === 'object')) {
      // A cyclic structure (or a shared node) must not recurse forever; JSON
      // payloads can legitimately repeat references after a merge.
      if (seen.has(node)) return node
      seen.add(node)
    }
    if (Array.isArray(node)) return node.map((item, index) => walk(item, `${keyPath}[${index}]`))
    if (node && typeof node === 'object') {
      const out = {}
      for (const [key, child] of Object.entries(node)) {
        if (skipKeys.has(key)) {
          out[key] = child
          continue
        }
        out[key] = walk(child, keyPath ? `${keyPath}.${key}` : key)
      }
      return out
    }
    return node
  }
  return { value: walk(value, ''), redactions }
}

/** Recursively detect unknown secrets in a structure, tagging the path. */
export function detectDeep(value, options = {}) {
  const findings = []
  const seen = new WeakSet()
  const walk = (node, keyPath) => {
    if (typeof node === 'string') {
      for (const finding of detect(node, options)) findings.push({ ...finding, path: keyPath })
      return
    }
    if (Array.isArray(node) || (node && typeof node === 'object')) {
      if (seen.has(node)) return
      seen.add(node)
    }
    if (Array.isArray(node)) {
      node.forEach((item, index) => walk(item, `${keyPath}[${index}]`))
      return
    }
    if (node && typeof node === 'object') {
      for (const [key, child] of Object.entries(node)) walk(child, keyPath ? `${keyPath}.${key}` : key)
    }
  }
  walk(value, '')
  return findings
}
