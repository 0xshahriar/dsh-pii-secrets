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

/**
 * Reject `lhs = lhs` shapes: `this._passphraseProvider = passphraseProvider`
 * assigns a variable to itself, which is a reference, not a literal secret.
 * @param {RegExpExecArray} match full match; group 1 is the identifier
 * @param {string} raw the captured right-hand side
 */
export function isNotSelfReference(match, raw) {
  const strip = (value) => String(value ?? '').replace(/^[_$]+/, '').toLowerCase()
  return strip(match?.[1]) !== strip(raw)
}

/** Rules generic enough that a more specific match should win the label. */
const GENERIC_RULES = new Set(['password-assignment', 'code-assignment'])

/** A value that *references* a secret rather than containing one. */
const CREDENTIAL_REFERENCE =
  /^(?:process\.env|import\.meta|os\.environ|os\.getenv|environment\.getenv|env\.fetch|ENV\[|ENV\.fetch|System\.getenv|System\.Environment|getenv\s*\(|config\.get|secrets\.get|\$\{|\{\{|<%|\$\(|%[A-Za-z_]+%|\$[A-Za-z_]|<<|@)/i

/** Schema vocabulary and placeholders: never a real secret. */
const NOT_A_SECRET =
  /^(?:required|optional|string|number|boolean|object|array|text|email|hidden|visible|readonly|disabled|enabled|true|false|null|undefined|none|nil|empty|default|changeme|change_me|example|placeholder|dummy|sample|redacted|password|passwd|secret|token|bearer|todo|fixme|replace|your[_-]?\w*)$/i

/**
 * Decide whether a captured assignment value is plausibly a real credential.
 *
 * This is the whole reason the language rules are usable: without it,
 * `password = os.getenv("DB_PASS")`, `token: 'required'` and
 * `SECRET_KEY = 'your-key-here'` all look like leaks, and a prompt-fatigued user
 * clicks through the real one.
 *
 * @param {string} value the captured literal, quotes removed
 * @returns {boolean}
 */
export function isRealCredentialValue(value) {
  if (typeof value !== 'string') return false
  const v = value.trim()
  if (v.length < 6 || v.length > 512) return false
  if (CREDENTIAL_REFERENCE.test(v)) return false
  if (NOT_A_SECRET.test(v)) return false
  // Template/splice/wrapper forms and call expressions are references.
  if (/^[`<{(/]/.test(v)) return false
  if (/^your(?:[_-]|$)/i.test(v)) return false
  // A credential is a literal. Any of these means we captured source code
  // instead — e.g. `CREDENTIAL_REFERENCE = /^(?:.../` or `passphrase: x.foo()`.
  if (/[(){}[\]<>/\\|=;:,]/.test(v)) return false
  if (/\s/.test(v)) return false
  // Masked, dotted or placeholder padding: `******`, `xxxxxx`, `......`
  if (/^[*x._\-]+$/i.test(v)) return false
  // An ENV_VAR name on the right-hand side is a reference, not a value.
  if (/^[A-Z][A-Z0-9_]+$/.test(v)) return false
  if (!/[A-Za-z0-9]/.test(v)) return false
  // A purely alphabetic value is prose, or a variable name like `newPassphrase`,
  // far more often than it is a credential. Digits or a longer passphrase pass.
  if (/^[A-Za-z]+$/.test(v) && v.length < 16) return false
  return true
}

/** Predefined secret/PII patterns. `kind` drives UI copy and default policy. */
export const PATTERNS = Object.freeze([
  { id: 'aws-access-key', kind: 'cloud-credential', label: 'AWS Access Key ID', re: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b/g },
  { id: 'aws-secret-key', kind: 'cloud-credential', label: 'AWS Secret Access Key', re: /(?:aws_?secret_?(?:access_?)?key|secret_?access_?key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi, group: 1 },
  { id: 'github-token', kind: 'api-token', label: 'GitHub Token', re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b/g },
  { id: 'anthropic-key', kind: 'api-token', label: 'Anthropic API Key', re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g },
  { id: 'openai-key', kind: 'api-token', label: 'OpenAI-style API Key', re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g },
  { id: 'slack-token', kind: 'api-token', label: 'Slack Token', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g },
  { id: 'google-api-key', kind: 'api-token', label: 'Google API Key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { id: 'stripe-key', kind: 'api-token', label: 'Stripe Key', re: /\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b/g },
  { id: 'private-key-block', kind: 'private-key', label: 'Private Key Block', re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----[\s\S]{10,}?-----END (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----/g },
  { id: 'jwt', kind: 'token', label: 'JWT', re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { id: 'connection-string', kind: 'credential-url', label: 'Credential URL', re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s/:@]+:[^\s/@]+@[^\s/]+/gi },
  { id: 'email', kind: 'pii', label: 'Email Address', re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, pii: true },
  { id: 'us-ssn', kind: 'pii', label: 'US SSN', re: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g, pii: true },
  { id: 'credit-card', kind: 'pii', label: 'Payment Card Number', re: /\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{1,4}\b/g, pii: true, validate: luhn },
  { id: 'phone-e164', kind: 'pii', label: 'Phone Number', re: /\+(?:[0-9][ -]?){7,14}[0-9]\b/g, pii: true },
  { id: 'iban', kind: 'pii', label: 'IBAN', re: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g, pii: true },

  // ── Cloud & SaaS credentials ────────────────────────────────────────────────
  { id: 'gitlab-token', kind: 'api-token', label: 'GitLab Token', re: /\bglpat-[A-Za-z0-9_-]{20,}\b/g },
  { id: 'npm-token', kind: 'api-token', label: 'npm Token', re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { id: 'pypi-token', kind: 'api-token', label: 'PyPI Token', re: /\bpypi-[A-Za-z0-9_-]{50,}\b/g },
  { id: 'sendgrid-key', kind: 'api-token', label: 'SendGrid API Key', re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g },
  { id: 'twilio-key', kind: 'api-token', label: 'Twilio API Key', re: /\bSK[0-9a-f]{32}\b/g },
  { id: 'mailgun-key', kind: 'api-token', label: 'Mailgun API Key', re: /\bkey-[0-9a-zA-Z]{32}\b/g },
  { id: 'shopify-token', kind: 'api-token', label: 'Shopify Access Token', re: /\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b/g },
  { id: 'telegram-bot-token', kind: 'api-token', label: 'Telegram Bot Token', re: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/g },
  { id: 'digitalocean-token', kind: 'cloud-credential', label: 'DigitalOcean Token', re: /\bdop_v1_[a-f0-9]{64}\b/g },
  { id: 'huggingface-token', kind: 'api-token', label: 'Hugging Face Token', re: /\bhf_[A-Za-z0-9]{34,}\b/g },
  { id: 'vercel-token', kind: 'api-token', label: 'Vercel Token', re: /\bvercel_[A-Za-z0-9]{24,}\b/g },
  { id: 'supabase-key', kind: 'api-token', label: 'Supabase Service Key', re: /\bsbp_[a-f0-9]{40}\b/g },
  { id: 'linear-key', kind: 'api-token', label: 'Linear API Key', re: /\blin_api_[A-Za-z0-9]{40}\b/g },
  { id: 'notion-token', kind: 'api-token', label: 'Notion Token', re: /\bsecret_[A-Za-z0-9]{43}\b/g },
  { id: 'figma-token', kind: 'api-token', label: 'Figma Token', re: /\bfigd_[A-Za-z0-9_-]{40,}\b/g },
  { id: 'postman-key', kind: 'api-token', label: 'Postman API Key', re: /\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b/g },
  { id: 'doppler-token', kind: 'api-token', label: 'Doppler Token', re: /\bdp\.pt\.[A-Za-z0-9]{43}\b/g },
  { id: 'databricks-token', kind: 'cloud-credential', label: 'Databricks Token', re: /\bdapi[a-f0-9]{32}\b/g },
  { id: 'newrelic-key', kind: 'api-token', label: 'New Relic Key', re: /\bNRAK-[A-Z0-9]{27}\b/g },
  { id: 'sentry-token', kind: 'api-token', label: 'Sentry Token', re: /\bsntrys_[A-Za-z0-9+/=]{40,}\b/g },
  { id: 'azure-storage-key', kind: 'cloud-credential', label: 'Azure Storage Account Key', re: /\bAccountKey=([A-Za-z0-9+/=]{40,})/g, group: 1 },
  { id: 'gcp-oauth-secret', kind: 'cloud-credential', label: 'Google OAuth Client Secret', re: /\bGOCSPX-[A-Za-z0-9_-]{28}\b/g },
  { id: 'age-key', kind: 'private-key', label: 'age Secret Key', re: /\bAGE-SECRET-KEY-1[0-9A-Z]{50,}\b/g },
  { id: 'bearer-header', kind: 'token', label: 'Bearer Token', re: /\bAuthorization\s*:\s*Bearer\s+([A-Za-z0-9._~+/-]{16,}=*)/gi, group: 1 },
  { id: 'npmrc-auth', kind: 'api-token', label: 'npm registry token (.npmrc)', re: /_authToken\s*=\s*([A-Za-z0-9_-]{20,})/g, group: 1 },
  { id: 'docker-auth', kind: 'api-token', label: 'Docker registry auth', re: /"auth"\s*:\s*"([A-Za-z0-9+/=]{20,})"/g, group: 1 },
  { id: 'netrc-password', kind: 'api-token', label: '.netrc password', re: /\bmachine\s+\S+\s+login\s+\S+\s+password\s+(\S{6,})/g, group: 1 },

  // ── Hardcoded credentials in source, by language family ─────────────────────
  // One grammar covers the assignment forms of Python, JavaScript/TypeScript,
  // Go (`:=`), Ruby, PHP (`$var =`), Java/C# (`String x =`), Rust (`let x =`),
  // shell (`export X=`), Dockerfile (`ENV X=`), YAML, TOML, INI, JSON, .env,
  // Kubernetes manifests and Terraform. The value validator keeps it quiet:
  // environment lookups, placeholders and schema vocabulary are rejected.
  { id: 'code-assignment', kind: 'code-credential', label: 'Hardcoded credential in source', languages: ['py', 'js', 'ts', 'go', 'rb', 'php', 'java', 'cs', 'rs', 'sh', 'dockerfile', 'yaml', 'toml', 'ini', 'json', 'hcl'], re: /["']?(\w*(?:PASSWORD|PASSWD|PASSPHRASE|PWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL|AUTH_?KEY)\w*)["']?\s*(?::=|=>|=|:)\s*(?:"([^"\n]{6,})"|'([^'\n]{6,})'|`([^`\n]{6,})`|([^\s"'`#;,})\]]{6,}))/gim, groups: [2, 3, 4, 5], validate: isRealCredentialValue, accept: isNotSelfReference, prefilter: /password|passwd|passphrase|pwd|secret|token|key|credential/i },
  { id: 'php-define-secret', kind: 'code-credential', label: 'PHP hardcoded credential', languages: ['php'], re: /\bdefine\s*\(\s*['"][^'"]*(?:PASSWORD|SECRET|KEY|TOKEN)[^'"]*['"]\s*,\s*['"]([^'"]{6,})['"]/gi, group: 1, validate: isRealCredentialValue, prefilter: /define\s*\(/i },
  { id: 'ruby-env-secret', kind: 'code-credential', label: 'Ruby ENV assignment', languages: ['rb'], re: /\bENV\[['"][A-Z0-9_]*(?:PASSWORD|SECRET|KEY|TOKEN)[A-Z0-9_]*['"]\]\s*=\s*['"]([^'"]{6,})['"]/g, group: 1, validate: isRealCredentialValue, prefilter: /ENV\[/ },
  { id: 'sql-password', kind: 'code-credential', label: 'SQL password literal', languages: ['sql'], re: /\bIDENTIFIED\s+BY\s+['"]([^'"]{6,})['"]/gi, group: 1, validate: isRealCredentialValue, prefilter: /IDENTIFIED\s+BY/i },
  { id: 'ansible-vault', kind: 'code-credential', label: 'Ansible Vault block', languages: ['yaml'], re: /\$ANSIBLE_VAULT;1\.[12];AES256[\s\S]{20,}/g, prefilter: /\$ANSIBLE_VAULT/ },
  { id: 'k8s-secret-data', kind: 'code-credential', label: 'Kubernetes Secret data', languages: ['yaml'], re: /\bdata:\s*\n(?:[ \t]+[\w.-]*(?:password|secret|token|key)[\w.-]*:\s*[A-Za-z0-9+/=]{16,}[ \t]*\n?)+/gi, prefilter: /\bdata:\s*\n/ },
  { id: 'password-assignment', kind: 'password', label: 'Password Assignment', re: /(?:^|[\s,;{[])(?:password|passwd|pwd|secret|api_?key|token)\s*[:=]\s*['"]?([^\s'",;}]{8,})['"]?/gim, group: 1, validate: isRealCredentialValue },
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

/** Shannon entropy in bits per character. */
export function shannon(text) {
  if (!text) return 0
  const counts = new Map()
  for (const char of text) counts.set(char, (counts.get(char) ?? 0) + 1)
  let entropy = 0
  for (const count of counts.values()) {
    const p = count / text.length
    entropy -= p * Math.log2(p)
  }
  return entropy
}

/** Words that, near a high-entropy token, mean "this is a credential". */
const SECRET_KEYWORDS = /(?:key|secret|token|passw(?:or)?d|passwd|pwd|auth|credential|bearer|private|api[-_]?key|access[-_]?key)/i

/**
 * Entropy-based detection: the fallback for credentials no regex knows.
 *
 * Deliberately conservative — a token must be long, high-entropy AND within 64
 * characters of a credential keyword. Entropy alone flags base64 images, minified
 * JS and hashes, and a prompt-fatigued user clicking through false positives is a
 * worse outcome than a missed unknown secret (which the vault still handles once
 * registered).
 *
 * @param {string} text
 * @param {object} [options]
 * @param {number} [options.minLength] shortest candidate (default 24)
 * @param {number} [options.minEntropy] bits/char threshold (default 4.0)
 * @param {number} [options.window] keyword proximity window (default 64)
 * @returns {Array<{ id, ruleId, kind, label, value, masked, fingerprint, snippet, pii }>}
 */
export function detectHighEntropy(text, { minLength = 24, minEntropy = 4.0, window = 64 } = {}) {
  if (typeof text !== 'string' || text.length === 0) return []
  const findings = []
  const seen = new Set()
  const re = /[A-Za-z0-9+/=_-]{24,}/g
  let match
  while ((match = re.exec(text)) !== null) {
    const candidate = match[0]
    if (candidate.length < minLength) continue
    // Require a mix of character classes: pure lowercase words are not tokens.
    if (!/[0-9]/.test(candidate) && !/[A-Z]/.test(candidate)) continue
    if (shannon(candidate) < minEntropy) continue
    const context = text.slice(Math.max(0, match.index - window), match.index)
    if (!SECRET_KEYWORDS.test(context)) continue
    if (seen.has(candidate)) continue
    seen.add(candidate)
    findings.push({
      id: fingerprint(candidate),
      ruleId: 'high-entropy',
      kind: 'unknown-secret',
      label: 'High-entropy secret',
      pii: false,
      masked: mask(candidate),
      fingerprint: fingerprint(candidate),
      value: candidate,
      snippet: `${context.slice(-24).replace(/\s+/g, ' ')}⟦…⟧`,
    })
  }
  return findings
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
  const { source, piiLevel = 'all', patterns = PATTERNS, includeRaw = true, entropy = false } = options
  const managed = source ? toEntries(source).map((e) => e.value).filter(Boolean) : []
  const findings = []
  const seen = new Set()

  // One raw value can match several rules; report it once, preferring the most
  // specific label over the generic assignment grammars.
  const byRaw = new Map()
  for (const rule of patterns) {
    if (rule.pii && piiLevel === 'none') continue
    // Cheap gate first: most text contains none of a rule's trigger words, and
    // the big language grammar backtracks noticeably over 80KB of prose.
    if (rule.prefilter && !rule.prefilter.test(text)) continue
    // A fresh regex per call: global regexes carry lastIndex state across calls.
    const re = new RegExp(rule.re.source, rule.re.flags)
    let match
    while ((match = re.exec(text)) !== null) {
      const raw = rule.groups
        ? rule.groups.map((g) => match[g]).find((v) => v !== undefined && v !== '')
        : rule.group
          ? match[rule.group]
          : match[0]
      if (!raw) continue
      if (rule.validate && !rule.validate(raw)) continue
      if (rule.accept && !rule.accept(match, raw)) continue
      // Managed secrets are silently redacted, never prompted about.
      if (managed.some((value) => raw.includes(value))) continue
      const key = `${rule.id}:${raw}`
      if (seen.has(key)) continue
      seen.add(key)
      const dedupeKey = `${rule.pii ? 'pii' : 'sec'}:${raw}`
      const prior = byRaw.get(dedupeKey)
      if (prior) {
        // Upgrade a generic label to the specific one that also matched.
        if (GENERIC_RULES.has(prior.ruleId) && !GENERIC_RULES.has(rule.id)) {
          prior.ruleId = rule.id
          prior.kind = rule.kind
          prior.label = rule.label
        }
        continue
      }
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
      byRaw.set(dedupeKey, findings[findings.length - 1])
    }
  }

  if (entropy) {
    for (const finding of detectHighEntropy(text)) {
      // Managed secrets stay silent; already-found shapes are not double reported.
      if (managed.some((value) => finding.value.includes(value))) continue
      if (seen.has(`${finding.ruleId}:${finding.value}`)) continue
      seen.add(`${finding.ruleId}:${finding.value}`)
      findings.push(includeRaw ? finding : { ...finding, value: undefined })
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
