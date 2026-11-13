import assert from 'node:assert/strict'
import { test } from 'node:test'

import { PATTERNS, detect, isNotSelfReference, isRealCredentialValue } from '../src/redact.js'

/** Run detect and return the rule ids that fired. */
const ids = (text) => [...new Set(detect(text).map((f) => f.ruleId))]

/**
 * Every sample is synthetic. Values are assembled at runtime with `join()` so the
 * file itself never contains a contiguous credential-shaped literal — GitHub push
 * protection rejects a commit that does, even when the value is fake.
 */
const join = (...parts) => parts.join('')

const PROVIDERS = [
  ['gitlab-token', join('glpat-', 'A1b2C3d4E5f6G7h8I9j0')],
  ['npm-token', join('npm_', 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8')],
  ['pypi-token', join('pypi-', 'a'.repeat(50))],
  ['sendgrid-key', join('SG.', 'a'.repeat(22), '.', 'b'.repeat(43))],
  ['twilio-key', join('SK', '0123456789abcdef'.repeat(2))],
  ['mailgun-key', join('key-', 'a1'.repeat(16))],
  ['shopify-token', join('shpat_', '0123456789abcdef'.repeat(2))],
  ['telegram-bot-token', join('123456789:AA', 'a'.repeat(33))],
  ['digitalocean-token', join('dop_v1_', '0123456789abcdef'.repeat(4))],
  ['huggingface-token', join('hf_', 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7')],
  ['vercel-token', join('vercel_', 'a'.repeat(24))],
  ['supabase-key', join('sbp_', '0123456789abcdef'.repeat(3).slice(0, 40))],
  ['linear-key', join('lin_api_', 'a'.repeat(40))],
  ['notion-token', join('secret_', 'a'.repeat(43))],
  ['figma-token', join('figd_', 'a'.repeat(40))],
  ['postman-key', join('PMAK-', '0123456789abcdef01234567', '-', '0123456789abcdef0123456789abcdef01')],
  ['doppler-token', join('dp.pt.', 'a'.repeat(43))],
  ['databricks-token', join('dapi', '0123456789abcdef'.repeat(2))],
  ['newrelic-key', join('NRAK-', 'A1B2C3D4E5F6G7H8I9J0K1L2M3N')],
  ['sentry-token', join('sntrys_', 'a'.repeat(40))],
  ['azure-storage-key', join('AccountKey=', 'aB3'.repeat(14))],
  ['gcp-oauth-secret', join('GOCSPX-', 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4')],
  ['age-key', join('AGE-SECRET-KEY-1', 'ABCDEFGH'.repeat(6), 'AB')],
  ['bearer-header', join('Authorization: Bearer ', 'abcdef0123456789abcdef')],
  ['npmrc-auth', join('//registry.npmjs.org/:_authToken=', 'a'.repeat(24))],
  ['docker-auth', join('"auth": "', 'YWJj'.repeat(6), '"')],
  ['netrc-password', 'machine api.example.com login me password n3t-rc-pa55'],
]

for (const [id, sample] of PROVIDERS) {
  test(`pattern: ${id} detects its credential shape`, () => {
    assert.deepEqual(ids(sample), [id], `sample: ${sample}`)
  })
}

/** Hardcoded credentials, one per language family the grammar covers. */
const LANGUAGES = [
  ['python', 'DB_PASSWORD = "hunter2-prod"'],
  ['python-env-file', 'STRIPE_SECRET=stripe-value-1234'],
  ['javascript', 'const apiKey = "ab12cd34ef56gh78"'],
  ['typescript', 'clientSecret: "s3cr3t-value-99"'],
  ['go', 'password := "g0-pa55w0rd-x"'],
  ['ruby', 'password: "ruby-pa55w0rd"'],
  ['ruby-env', "ENV['API_KEY'] = 'ruby-env-key-77'"],
  ['php-variable', '$db_password = "php-pa55w0rd";'],
  ['php-define', "define('DB_PASSWORD', 'php-define-42');"],
  ['java', 'String password = "java-pa55w0rd";'],
  ['csharp', 'string DbPassword = "cs-pa55w0rd";'],
  ['rust', 'let password = "rust-pa55w0rd";'],
  ['shell', 'export GITHUB_TOKEN="sh-t0ken-1234"'],
  ['dockerfile', 'ENV DB_PASSWORD=docker-pass-99'],
  ['yaml', 'password: yaml-pass-1234'],
  ['json', '"client_secret": "json-secret-1234"'],
  ['toml', 'api_key = "toml-key-1234"'],
  ['sql', "IDENTIFIED BY 'sql-pass-1234'"],
  ['kubernetes', 'data:\n  db_password: cGFzc3dvcmQxMjM0NTY3OA==\n'],
  ['ansible-vault', `$ANSIBLE_VAULT;1.2;AES256\n${'3132333435'.repeat(6)}`],
]

for (const [lang, sample] of LANGUAGES) {
  test(`language: ${lang} is detected`, () => {
    const got = ids(sample)
    assert.ok(
      got.some((id) => id === 'code-assignment' || id.endsWith('-secret') || id === 'sql-password' || id === 'ansible-vault' || id === 'k8s-secret-data'),
      `expected a code rule for ${lang}, got ${JSON.stringify(got)}`,
    )
  })
}

/**
 * The false positives that decide whether this feature is usable. Every one of
 * these is a *reference* or a placeholder, not a credential.
 */
const NOT_SECRETS = [
  ['env lookup (js)', 'const password = process.env.DB_PASSWORD'],
  ['env lookup (python)', 'password = os.getenv("DB_PASSWORD")'],
  ['env lookup (go)', 'password := os.Getenv("DB_PASSWORD")'],
  ['env mapping (python)', 'DB_PASSWORD = os.environ["DB_PASSWORD"]'],
  ['template literal', 'const apiKey = `${process.env.API_KEY}`'],
  ['mustache placeholder', 'password: "{{VAULT_PASSWORD}}"'],
  ['shell placeholder', 'password: "${DB_PASSWORD}"'],
  ['angle placeholder', 'api_key: "<your-api-key>"'],
  ['docs placeholder', "secret_key: 'your-key-here'"],
  ['changeme', 'password: "changeme"'],
  ['masked', 'password: "********"'],
  ['null', 'password = null'],
  ['undefined', 'token = undefined'],
  ['schema vocabulary', "token: 'required'"],
  ['env var name as value', 'password: "DB_PASSWORD"'],
  ['prose value', 'password: "hidden"'],
  ['json schema', '"password": {"type": "string"}'],
  ['getter call', 'config.password = config.get("password")'],
  ['no assignment', "ENV['API_KEY']"],
  ['python import', 'from config import SECRET_KEY'],
]

for (const [label, sample] of NOT_SECRETS) {
  test(`no false positive: ${label}`, () => {
    assert.deepEqual(ids(sample), [], `sample: ${sample}`)
  })
}

test('pattern ids are unique and every regex is global', () => {
  const seen = new Set()
  for (const rule of PATTERNS) {
    assert.ok(!seen.has(rule.id), `duplicate pattern id ${rule.id}`)
    seen.add(rule.id)
    assert.ok(rule.re.flags.includes('g'), `${rule.id} must be global`)
  }
  assert.ok(PATTERNS.length >= 45, `expected a broad catalog, got ${PATTERNS.length}`)
})

test('language rules advertise the languages they cover', () => {
  const rule = PATTERNS.find((r) => r.id === 'code-assignment')
  assert.ok(rule.languages.length >= 10)
  for (const lang of ['py', 'js', 'ts', 'go', 'rb', 'php', 'java', 'cs', 'rs', 'sh', 'dockerfile', 'yaml', 'toml', 'json', 'hcl']) {
    assert.ok(rule.languages.includes(lang), `missing ${lang}`)
  }
})

test('a specific provider label wins over the generic assignment grammar', () => {
  const sample = 'const key = "AKIA' + 'IOSFODNN7EXAMPLE"'
  const found = detect(sample)
  assert.equal(found.length, 1, 'one finding, not two')
  assert.equal(found[0].ruleId, 'aws-access-key', 'the specific rule should label it')
})

test('one value is reported once even when several rules match it', () => {
  const sample = 'aws_secret_access_key = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"'
  const found = detect(sample)
  const values = found.map((f) => f.value ?? f.fingerprint)
  assert.equal(new Set(values).size, values.length, 'no duplicate values')
})

test('the validator rejects references and placeholders directly', () => {
  for (const bad of ['process.env.X', '${X}', '$X', 'your-key', 'changeme', '********', 'DB_PASSWORD', 'required', 'short', '']) {
    assert.equal(isRealCredentialValue(bad), false, `${bad} must be rejected`)
  }
  for (const good of ['hunter2-prod', 'ab12cd34ef56gh78', 's3cr3t-value-99', 'aB3aB3aB3']) {
    assert.equal(isRealCredentialValue(good), true, `${good} must be accepted`)
  }
})

test('the catalog does not fire on this project’s own source and docs', async () => {
  // Dogfooding: a detector that cries wolf on ordinary code is worse than none.
  const { readFile, readdir } = await import('node:fs/promises')
  const { join, extname } = await import('node:path')

  const files = []
  const walk = async (dir) => {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const p = join(dir, entry.name)
      if (entry.isDirectory()) {
        if (!['.git', 'test', 'node_modules'].includes(entry.name)) await walk(p)
      } else if (['.js', '.md', '.json', '.yml'].includes(extname(entry.name))) {
        files.push(p)
      }
    }
  }
  await walk('.')

  const allowed = new Set([
    'email', // the maintainer's contact address, deliberately in the docs
    'aws-access-key', // AWS's own documented example key, allowlisted in CI too
  ])
  const unexpected = []
  for (const file of files) {
    for (const finding of detect(await readFile(file, 'utf8'))) {
      if (!allowed.has(finding.ruleId)) unexpected.push(`${file}: ${finding.ruleId} ${finding.masked}`)
    }
  }
  assert.deepEqual(unexpected, [])
})

test('a self-assignment is a reference, not a secret', () => {
  assert.deepEqual(ids('this._passphraseProvider = passphraseProvider'), [])
  assert.deepEqual(ids('passphrase = passphrase'), [])
  assert.equal(isNotSelfReference(['x', '_passphraseProvider'], 'passphraseProvider'), false)
  assert.equal(isNotSelfReference(['x', 'apiKey'], 'ab12cd34ef56'), true)
})
