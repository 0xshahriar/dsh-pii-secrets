# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is `0`, a **minor** bump may contain breaking changes.

## [Unreleased]

Nothing yet.

## [0.1.3] — 2026-11-14

Detection got much wider without getting noisier.

### Added

- **31 new patterns** (19 → 50). Provider shapes: GitLab, npm, PyPI, SendGrid,
  Twilio, Mailgun, Shopify, Telegram bot, DigitalOcean, Databricks, Hugging Face,
  Vercel, Supabase, Linear, Notion, Figma, Postman, Doppler, New Relic, Sentry,
  Google `GOCSPX-`, Azure `AccountKey=`, age. Headers and files: `Authorization:
  Bearer`, `.npmrc` `_authToken`, Docker `config.json` auth, `.netrc`.
- **Language-based detection.** `code-assignment` extracts an
  identifier-then-literal assignment across Python, JavaScript/TypeScript, Go
  (`:=`), Ruby, PHP, Java, C#, Rust, shell, Dockerfile, YAML, TOML, INI, JSON,
  `.env` and Terraform/HCL. Six syntax-specific rules cover PHP `define()`, Ruby
  `ENV[...] =`, SQL `IDENTIFIED BY`, Ansible Vault and Kubernetes `Secret.data`.
- `isRealCredentialValue()` — the guard that makes the above usable. Rejects
  environment lookups, placeholders, schema vocabulary, code punctuation
  (`/regex/`, `foo()`, `{…}`), whitespace and self-assignment.
- `isNotSelfReference()` and a per-rule `accept()` hook, so a rule can inspect
  the whole match rather than only its captured value.
- `prefilter` on expensive rules: text without the trigger words skips the
  grammar entirely (prose cost 20.7 ms → 8.9 ms per 80 KB).

### Fixed

- **`password-assignment` had no value validation**, so `password =
  process.env.DB_PASSWORD`, `token: 'required'` and `api_key: "<your-key>"` were
  all reported. It now shares the literal guard and sits last, as a fallback.
- **`openai-key` shadowed `anthropic-key`**: the generic `sk-` rule came first, so
  `sk-ant-…` was mislabelled. Reordered.
- **Duplicate findings**: one value matched by several rules was reported
  repeatedly. Each value is now reported once, and a specific rule takes the
  label over a generic grammar.

### Changed

- `detect()` accepts `groups` (multi-alternative capture) and `accept`.
- `test/patterns.test.js` adds 74 tests: every provider shape, 20 language forms,
  a 20-case false-positive corpus, and a dogfood scan that fails if the catalog
  fires on this repository's own source and docs.

## [0.1.2] — 2026-11-14

**Re-release. No functional change.** This is the same tree as 0.1.1.

0.1.1's tag was force-moved three times while its own release was being finished,
which makes it a mutable reference: two people cloning on different days could
get different commits under the same version. Rather than ship that, 0.1.2
republishes the identical code under a tag that is never rewritten.

- **Prefer `0.1.2`.** If you pinned `0.1.1`, move to `0.1.2`; the contents match
  the final `0.1.1` tree.
- 109 tests passing.

## [0.1.1] — 2026-11-14

Eight upgrades, all verified against the published `@deepseek-ai/*` type
declarations before implementation. One is a correctness fix that made the plugin
unusable with tools that need a real secret.

### Added

- **`pii_run` — local secret injection.** The gap that made redaction unusable:
  a `{{API_KEY_1}}` argument could not be rewritten at `tools/pre-execute`
  (arguments are already logged) and `tools/execute` may only replace the
  signal, so `bash` executed the literal placeholder. `pii_run` substitutes
  inside the tool body and passes values as environment variables, never in
  `argv`. Output is scrubbed on the way back.
- **`llm/stream` tripwire.** A frozen request that still contains a vault value
  is refused instead of sent. Closes the retro-logged-secret path that
  `agent/pre-step` cannot reach.
- **Redaction cache.** Keyed by immutable message id and invalidated on vault
  revision. Measured: **17.1 ms → 0.3 ms** per step on an 80 KB history.
- **Entropy detection** (`entropyDetection`, opt-in). High-entropy tokens near a
  credential keyword, for credentials no regex knows.
- **`pii_secret edit`** — rename or change a value without rewriting the
  placeholder that the transcript already contains.
- **Vault rotation** (`vault.rotate(newPassphrase)`) — re-seals under a fresh
  scrypt salt, format unchanged, old key zeroed only after the new file lands.
- **Audit log** (`auditLog`, opt-in) — append-only JSONL of decisions with
  fingerprints only. A broken log path never breaks redaction; a caller mistake
  cannot smuggle a value into it.
- **OS keyring support** (`useKeyring`) — macOS Keychain and libsecret via
  `execFile`, falling back down the existing chain.
- **Per-tool scopes** (`autoAllow`) — pre-authorise named secrets for named
  tools so a repetitive loop stops prompting.

### Fixed

- **Scopes matched the wrong thing.** They were keyed on the classified action
  (`terminal`) instead of the tool name (`bash`), and compared against the braced
  placeholder, so `API_KEY_*` never matched. Both fixed; the bare stem now
  matches too.
- **Cyclic payloads hung the tripwire.** `flattenStrings` had no cycle guard, so
  an object that referenced itself looped until the string budget never drained.
- **The audit log raced teardown.** Writes were queued but not flushed, so a
  write could land after the vault directory was removed (`ENOTEMPTY`). Disposal
  is now async and drains both queues, and `vault.flush()` exposes the same
  guarantee to any caller — an atomic write that finishes after cleanup leaves a
  stray tmp file, not just a test failure.
- **`auditLog` was opt-out in practice.** It was tested as `=== false`, so any
  caller passing a partial config (before schema defaults apply) had files
  written on its behalf. Now opt-in (`=== true`), as documented.
- **Rotation looked broken with an env passphrase.** `_ensureKey` prefers
  `DSH_PII_SECRETS_PASSPHRASE` over an explicit provider, so rotating while the
  env var held the old value made the next unlock fail. Behaviour unchanged and
  now documented under Rotation.

- **`pii_run` asked twice.** Its arguments can look like a path, so the
  capability gate treated it as read-capable and prompted *in addition to* its own
  per-secret prompt. The tool gate now defers to the in-tool gate.
- **`pii_run` rejected the bare stem.** Commands reference `$API_KEY_1` but
  `secrets` had to be `{{API_KEY_1}}`. Both now resolve.
- **`@deepseek-ai/schemastery` was imported but never declared**, and two
  `peerDependenciesMeta` entries named packages absent from `peerDependencies`
  (which npm ignores). Both corrected; `dsh-shell` declared optional.
- **Documentation had drifted:** version and test badges still read 0.1.0 / 77,
  the seam table still called `llm/stream` unused, the architecture diagram
  omitted the tripwire and `pii_run`, and SECURITY.md's invariants said redaction
  never happens at `llm/stream` without noting the detection-only handler.

### Changed

- `auditLog` defaults to `false`: a plugin install should not create files.
- `pii_secret list` doc string now points the model at `pii_run` instead of
  inviting it to type values into commands.

## [0.1.0] — 2026-11-13

First release.

### Added

- **Encrypted local vault** — AES-256-GCM with a scrypt-derived key
  (N=2^15, r=8, p=1). Atomic writes (temp → `fsync` → `rename`, mode `0600`)
  and a versioned JSON envelope.
- **Hot-reloadable secret store** — add, edit and remove secrets with no restart.
  The next request sees the change.
- **Outbound redaction** at `agent/pre-step`: managed secret values are replaced
  with stable placeholders (`{{AWS_PROD_KEY_1}}`) before a request is built.
- **Tool-result scrubbing** at `tools/post-execute`, so a secret printed by a
  tool never reaches the model.
- **Capability-based exposure gate** at `tools/pre-execute`:
  - terminal tools (`bash`, `shell`, `run_code`) ask, because their output may
    contain anything;
  - path-reading tools (`read`, `grep`) ask when they name a path;
  - `publish` / `upload` / `deploy` present a multi-select checklist of the whole
    vault;
  - other tools are gated only when a secret literal appears in the arguments.
- **One-step exposure prompt** with a Select All option, masked by default.
  Default is deny; ambiguity, a thrown adapter or a timeout all deny.
- **Unknown-secret detection** — 17 built-in patterns covering AWS, GitHub,
  OpenAI, Anthropic, Slack, Google, Stripe, private-key blocks, JWTs, credential
  URLs, password assignments, email, US SSN, payment cards (Luhn-validated),
  E.164 phone numbers and IBANs.
- **Three policy modes** — `detect` (log fingerprints only), `gate` (prompt),
  `block` (refuse).
- **Dual UI** — a TUI adapter over the harness `userQuestions` seam or
  `inquirer`, and a browser checklist with a per-row eye toggle (`web/client.js`).
- **Agent-facing CRUD** — a `pii_secret` tool with `list` (metadata only, never
  values), `add` and `remove`.
- **Passphrase sources**, in priority order: environment variable
  (`DSH_PII_SECRETS_PASSPHRASE`), an OS keyring command run via `execFile`
  (`keyCommand`), or an interactive provider.
- 77 tests covering crypto, redaction, policy, Cordis wiring, the DOM component,
  and named regression tests for every defect found in review.

### Fixed during initial review

Recovered before the first release; each has a named regression test.

- **Terminal commands that would print secrets were not gated.** `git log`,
  `cat .env` and `upload .env` name a *source*, not a value, so an
  arguments-only check let them through. Gating is now capability-based.
- **An adapter resolving to `undefined`** threw a `TypeError` out of the gate
  (`selected`, `remember`, `reveal` were read unguarded).
- **`detectDeep` called with `includeRaw: false`** on the gate path, leaving the
  withhold branch with no value to substitute.
- **A wrong passphrase poisoned the instance** by caching the derived key, so a
  corrected passphrase could never succeed without a restart.
- **A write after a failed unlock would have destroyed the vault** by
  re-encrypting under a fresh salt. Writes are now refused (`NOT_LOADED`).
- **`lock()` cleared the live store**, so a hot reload left other fibers
  redacting against an empty vault.
- **A malformed envelope threw a raw `TypeError`** instead of a `VaultError`.
- **Cyclic or shared-reference payloads overflowed the stack** in the redactor,
  detector and gate.
- **`redact()` returned a non-string** for non-string input, violating its
  contract.
- **A 1-character secret matched every tool call**, making the plugin prompt on
  everything. Secrets below 4 characters now opt out of argument matching while
  still being redacted outbound.
- **The browser eye toggle could never fetch a value** — `revealable` was
  hardcoded and no reveal transport was passed. The TUI had no reveal at all,
  and `describeFinding` read a field the policy strips.
- **`store.size` was logged before the async load settled**, reporting `0`.
- Indentation corruption and dead code in `src/index.js`.

### Security

- The passphrase is never persisted.
- Fail-closed by default across every decision path.
- Raw secret values never appear in a UI payload.

[Unreleased]: https://github.com/0xShahriar/dsh-pii-secrets/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/0xShahriar/dsh-pii-secrets/releases/tag/v0.1.3
[0.1.2]: https://github.com/0xShahriar/dsh-pii-secrets/releases/tag/v0.1.2
[0.1.1]: https://github.com/0xShahriar/dsh-pii-secrets/releases/tag/v0.1.1
[0.1.0]: https://github.com/0xShahriar/dsh-pii-secrets/releases/tag/v0.1.0