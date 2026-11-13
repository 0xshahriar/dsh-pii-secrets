# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is `0`, a **minor** bump may contain breaking changes.

## [Unreleased]

Nothing yet.

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

[Unreleased]: https://github.com/0xShahriar/dsh-pii-secrets/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/0xShahriar/dsh-pii-secrets/releases/tag/v0.1.0