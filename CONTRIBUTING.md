# Contributing to dsh-pii-secrets

Thanks for taking the time to contribute. This project handles credentials, so
the bar for correctness is higher than usual: a bug here can leak a user's
secrets rather than merely showing a wrong number.

## Table of contents

- [Code of Conduct](#code-of-conduct)
- [Ways to contribute](#ways-to-contribute)
- [Development setup](#development-setup)
- [Project layout](#project-layout)
- [Design rules](#design-rules)
- [Making a change](#making-a-change)
- [Commit messages](#commit-messages)
- [Pull request checklist](#pull-request-checklist)
- [Reporting bugs](#reporting-bugs)
- [Reporting security issues](#reporting-security-issues)

---

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By
participating you agree to uphold it.

## Ways to contribute

| Type | Start here |
| --- | --- |
| Bug report | [Open an issue](https://github.com/0xShahriar/dsh-pii-secrets/issues/new/choose) |
| Pattern request | A new detector in `src/redact.js` + a test |
| Documentation | Any `.md` file — typos welcome |
| Feature | Open an issue first so we can agree on the seams |

## Development setup

```sh
git clone https://github.com/0xShahriar/dsh-pii-secrets.git
cd dsh-pii-secrets
npm test
```

No install step is required for the tests: they use only Node built-ins plus a
small stub for `@deepseek-ai/schemastery` (see `test/schemastery-stub.js`).

```sh
npm test                      # full suite
node --test --import ./test/register.mjs test/engine.test.js   # a single file
```

## Project layout

```
src/vault.js     encryption, KDF, atomic writes, the live SecretStore
src/redact.js    pattern catalog, substitution, masking
src/policy.js    the single decision point (classify -> decide -> apply)
src/ui.js        prompt adapters (user-questions, inquirer, web RPC)
src/audit.js     append-only JSONL decision log (fingerprints, never values)
src/keyring.js   OS keyring backends via execFile (Keychain, libsecret)
src/index.js     Cordis wiring; keep it thin
web/client.js    browser checklist + eye toggle
```

Note that `src/index.js` holds the only seam that can *refuse* a request
(`llm/stream`). Keep it detection-only — that seam cannot rewrite anything.

Rule of thumb: **policy is pure**. `src/policy.js` must not import Cordis, so it
can be tested without a harness. Wiring belongs in `src/index.js`.

## Design rules

These are invariants, not preferences. A pull request that breaks one needs a
very good argument.

1. **Managed secrets never prompt.** If a value is in the vault, redact it
   silently. The only question is whether a human may *see* it.
2. **One step, always.** Every exposure prompt is a single round-trip. No
   wizards, no "are you sure?" after the checklist.
3. **Fail closed.** A missing UI, a thrown adapter, a timeout — all resolve to
   *do not expose*.
4. **No raw secrets in UI payloads.** Prompts carry masked text; raw values live
   behind a per-row accessor.
5. **Redact upstream.** `llm/stream` cannot rewrite a request. Use
   `agent/pre-step` and `tools/post-execute`.
6. **Never overwrite an undecryptable vault.** Data loss is worse than a failed
   write.
7. **Every fix gets a named regression test** in `test/regressions.test.js`.

## Making a change

1. Fork and branch from `main`: `git checkout -b fix/short-description`.
2. Write a failing test first. For a bug, name the defect in the test title
   (`regression: <what broke>`).
3. Make the smallest change that passes.
4. Run the full suite: `npm test`.
5. Update `CHANGELOG.md` under `## [Unreleased]`.

### Adding a secret pattern

Add an entry to `PATTERNS` in `src/redact.js`. Every rule must be global, and
three fields keep the catalog quiet:

| Field | Use it when |
| --- | --- |
| `validate` | The shape alone over-matches. Reuse `isRealCredentialValue` for anything that captures an assignment value. |
| `accept` | You need the whole match, not just the captured group (e.g. to reject `x = x`). |
| `prefilter` | Your regex is expensive. A cheap `test()` on the trigger words skips it for unrelated text. |

Add the rule's positive shape **and** a false-positive case to
`test/patterns.test.js`; that suite also scans this repo and fails if the catalog
fires on our own source or docs.

```js
{
  id: 'my-service-key',       // stable, kebab-case, used in logs
  kind: 'api-token',          // cloud-credential | api-token | private-key |
                              // token | credential-url | password | pii
  label: 'My Service Key',    // shown to the user
  re: /\bmysvc_[A-Za-z0-9]{32}\b/g,   // MUST be global (/g)
  group: 1,                   // optional: capture group holding the secret
  validate: (v) => true,      // optional predicate (see luhn)
}
```

Then add a case to the `detect finds predefined credential patterns` table in
`test/engine.test.js`. Bias toward **fewer false positives**: a pattern that
fires on ordinary prose trains users to click through prompts.

## Commit messages

Conventional Commits, imperative mood:

```
fix(policy): gate read-capable tools on path arguments
feat(redact): add Stripe restricted-key pattern
docs: clarify the passphrase recovery behaviour
test: lock down cyclic-structure handling
```

Scope is the module (`policy`, `vault`, `redact`, `ui`, `client`, `wiring`,
`docs`).

## Pull request checklist

- [ ] `npm test` passes (report the counts in the description)
- [ ] New behaviour has a test; a bug fix has a named regression test
- [ ] No new dependency unless discussed in an issue first
- [ ] `CHANGELOG.md` updated
- [ ] Documentation updated if behaviour or configuration changed
- [ ] No real secrets, tokens or `.env` contents in the diff

## Reporting bugs

Include:

- What you did, what you expected, what happened.
- The **error code** (`VaultError.code`) rather than a passphrase or secret.
- Your `node -v` and `dsh --version`.

**Never paste a real secret into an issue.** Redact it; a fingerprint is enough
to correlate (`detect()` prints these).

## Reporting security issues

Do **not** open a public issue. Follow [SECURITY.md](SECURITY.md).