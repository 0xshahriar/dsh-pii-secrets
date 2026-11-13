<div align="center">

# dsh-pii-secrets

**PII Secrets Manager for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)**

Keep secrets on your machine. Swap them for placeholders before any request
reaches an LLM provider. Pause the actions that would leak them.

[![Version](https://img.shields.io/badge/version-0.1.2-blue.svg)](#)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%E2%89%A520-brightgreen.svg)](#requirements)
[![Tests](https://img.shields.io/badge/tests-109%20passing-brightgreen.svg)](#testing)
[![dsh](https://img.shields.io/badge/dsh-%E2%89%A50.2.0-purple.svg)](#requirements)

[Architecture](#architecture) · [Behaviour](#behaviour) · [Install](#install) ·
[Configuration](#configuration) · [Testing](#testing) · [Security](#security-model)

</div>

---

## Why this exists

Every prompt you send to a hosted model is a copy of your working directory's
worst day: `.env` files pasted into a chat, a `git log -p` that prints an old
API key, a stack trace with a database URL. Once it leaves the machine, you
cannot recall it.

`dsh-pii-secrets` adds a local, encrypted vault and three interception points to
`dsh` so that the actual secret value never leaves the process:

- **Managed secrets** are replaced with stable placeholders — silently, always.
- **Unknown secrets** that match a pattern pause the action once for a decision.
- **Any** action that would display or ship a secret asks first, defaulting to
  *no*.

---

## Table of contents

- [Why this exists](#why-this-exists)
- [Architecture](#architecture)
  - [Why these seams](#why-these-seams)
  - [Project layout](#project-layout)
- [Behaviour](#behaviour)
  - [1. Known secrets — silent protection](#1-known-secrets--silent-protection)
  - [2. Forced exposure — one-step pause](#2-forced-exposure--one-step-pause)
  - [3. Unknown secrets — masked with an eye toggle](#3-unknown-secrets--masked-with-an-eye-toggle)
  - [4. Policy modes](#4-policy-modes)
- [Requirements](#requirements)
- [Install](#install)
- [Configuration](#configuration)
  - [What each new option is for](#what-each-new-option-is-for)
  - [Scopes — pre-authorising a repetitive loop](#scopes--pre-authorising-a-repetitive-loop)
- [Agent-facing tools](#agent-facing-tools)
  - [`pii_secret` — CRUD](#pii_secret--crud)
  - [`pii_run` — using a secret without leaking it](#pii_run--using-a-secret-without-leaking-it)
- [Rotation](#rotation)
- [Testing](#testing)
- [Security model](#security-model)
- [Known limitations](#known-limitations)
- [Contributing](#contributing)
- [License](#license)

---

## Architecture

```
                        ┌──────────────────────────────┐
  agent/pre-step   ───► │  ExposurePolicy              │ ◄──► SecretStore (hot)
  (outbound model       │   classify()  managed/unknown │           ▲
   request messages)    │   decide()    one-step gate   │           │ CRUD
                        │   protectOutbound()           │      ┌────┴─────┐
  tools/pre-execute ───►│   gateToolCall()              │      │  Vault   │
  (every tool call)     │   scrubToolResult()           │      │ AES-256  │
                        └───────────┬───────────────────┘      │  -GCM    │
  tools/post-execute ───────────────┘                          └────┬─────┘
                                                                    │
                        ┌──────────────────────────────┐       vault.json
  pii_secret tool  ────►│  UI adapters (one step)       │      (encrypted)
                        │  UserQuestions / Inquirer /   │
                        │  Web (checklist + eye icon)   │
                        └──────────────────────────────┘
```

### Why these seams

Redaction happens at **`agent/pre-step`**, not at `llm/stream`. This was
verified against the real `@deepseek-ai/dsh-agent` and `@deepseek-ai/dsh-llm`
type declarations:

| Seam | Can it redact? | Why |
| --- | --- | --- |
| `llm/stream` | **No** (detect only) | Loop-built requests "arrive deep-frozen (mutation throws) … listeners read it, never rewrite it", and its `next()` takes no argument — it returns the adapter's chunk stream, not the request. It is used as a **tripwire**: a request that still contains a vault value is refused, never forwarded. |
| `agent/pre-step` | **Yes** | A waterfall that may replace the messages entering a step: `PreStepDecision = { kind: 'reject' } \| { kind: 'enter', messages }`. |
| `tools/post-execute` | **Yes** | Scrubs tool output before the model reads it. |

So the plugin redacts the earliest *mutable* copy of anything bound for a
provider, then scrubs tool results so a secret printed by a tool never even
reaches the model. `llm/stream` carries a **detection-only** handler: it reads the
frozen request and refuses it if a vault value is still present, but never
rewrites. That constraint is documented in `src/index.js` so nobody "fixes" it
back into a rewrite later.

### Project layout

| Path | Role |
| --- | --- |
| `src/vault.js` | AES-256-GCM envelope, scrypt KDF, atomic writes, live `SecretStore` |
| `src/redact.js` | Regex pattern catalog, placeholder substitution, masking, Luhn check |
| `src/policy.js` | `ExposurePolicy` — the single decision point for every surface |
| `src/ui.js` | One-step prompt adapters: user-questions, inquirer, web RPC |
| `src/keyring.js` | OS keyring backends (Keychain, libsecret) via `execFile` |
| `src/audit.js` | Append-only JSONL decision log; fingerprints, never values |
| `src/index.js` | Cordis wiring: four seams plus the `pii_secret` / `pii_run` tools |
| `web/client.js` | Browser half: multi-select checklist, Select All, eye toggle |
| `test/` | 109 tests across crypto, redaction, policy, wiring, DOM, upgrades, regressions |

---

## Behaviour

### 1. Known secrets — silent protection

A value already in the vault is swapped for its stable placeholder with **no
prompt at all**:

```diff
- use AKIAIOSFODNN7EXAMPLE
+ use {{AWS_PROD_KEY_1}}
```

CRUD is hot: the next request sees the change. No restart, no re-read.

### 2. Forced exposure — one-step pause

The exposure surface for a tool is almost never its arguments: `git log`,
`cat .env` and `upload .env` all name a *source*, not a value. So a call is
gated on its **capability**, not only on a literal match:

| Tool | Gate |
| --- | --- |
| `bash` / `shell` / `run_code` | asks (output may print anything) |
| `read` / `grep` with a path | asks |
| `publish` / `upload` / `deploy` | **multi-select checklist of the whole vault** |
| everything else | only if a secret literal appears in the arguments |

Multiple secrets are always a multi-select checklist with Select All. The
default is **deny**.

### 3. Unknown secrets — masked with an eye toggle

Values matching a pattern but not in the vault prompt once, **hidden by
default**. Reveal is per-row, on demand. If you decline, the value is replaced
with a generic placeholder:

```
mail a@b.com  →  mail {{REDACTED_EMAIL_897fff}}
```

### 4. Policy modes

```yaml
unknownSecretPolicy: gate   # detect | gate | block
```

| Mode | Behaviour |
| --- | --- |
| `detect` | Log fingerprints only — never values, never prompt |
| `gate` | One-step prompt (default) |
| `block` | Refuse without asking |

Built-in patterns cover AWS keys, GitHub/OpenAI/Anthropic/Slack/Google/Stripe
tokens, private-key blocks, JWTs, credential URLs, password assignments, email,
US SSN, payment cards (Luhn-validated), E.164 phone numbers and IBANs.

---

## Requirements

| Requirement | Version |
| --- | --- |
| Node.js | ≥ 20 (uses `node:test`, `crypto.scrypt`) |
| DeepSeek Harness | ≥ 0.2.0 (`engines.dsh`) |
| `@deepseek-ai/cordis` | ~4.1.0 (peer) |
| `@deepseek-ai/dsh-shell` | any (`ctx.shell`) — optional; only needed for `pii_run` |

---

## Install

```sh
dsh plugin --profile web add ./dsh-pii-secrets
```

Unlock the vault with a passphrase. It is never stored:

```sh
export DSH_PII_SECRETS_PASSPHRASE='…'
```

Or configure an OS keyring command, executed via `execFile` (no shell, so the
string cannot inject):

```yaml
- id: pii-secrets
  name: dsh-pii-secrets
  config:
    vaultPath: pii-secrets.vault.json
    keyCommand: secret-tool lookup service dsh-pii
```

---

## Configuration

Every field is optional; the defaults are shown.

```yaml
- insert:
    - id: pii-secrets
      name: dsh-pii-secrets
      config:
        vaultPath: pii-secrets.vault.json  # relative paths resolve against $DSH_HOME
        unknownSecretPolicy: gate          # detect | gate | block
        piiLevel: all                      # all | none
        gateTools: true                    # pause tools that could expose secrets
        redactRequests: true               # redact outbound model requests
        redactToolResults: true            # scrub tool output before the model reads it
        keyCommand: ""                     # optional OS keyring command
        exposureTimeoutMs: 120000          # web prompt timeout, then deny
        # ── 0.1.1 additions ──
        useKeyring: true                   # read the passphrase from the OS keyring
        keyringService: dsh-pii-secrets    # keyring service/entry name
        blockUnredactedHistory: true       # refuse a request that still holds a vault value
        allowLocalExecution: true          # offer pii_run (local secret injection)
        entropyDetection: false            # opt-in: catch credentials no regex knows
        auditLog: false                    # opt-in: JSONL decision log, fingerprints only
        cacheSize: 4096                    # redaction cache entries per session
        autoAllow: {}                      # per-tool scopes, e.g. { bash: ['DEV_*'] }
```

### What each new option is for

| Option | Default | Why you would change it |
| --- | --- | --- |
| `useKeyring` | `true` | Turn off if a locked OS keyring makes unlocking slow or prompts. |
| `blockUnredactedHistory` | `true` | A secret logged *before* it was vaulted stays in the transcript; this refuses such a request rather than leaking it. Disable only if you accept that. |
| `allowLocalExecution` | `true` | Registers `pii_run`. Set `false` if you do not want the plugin offering command execution. |
| `entropyDetection` | `false` | Finds unknown high-entropy credentials near keywords. Costs false positives, so it is opt-in. |
| `auditLog` | `false` | Writes `<vault>.audit.jsonl`. Fingerprints and decisions, never values. |
| `autoAllow` | `{}` | Pre-authorise named secrets for named tools so a repetitive loop stops prompting. |

### Scopes — pre-authorising a repetitive loop

```yaml
autoAllow:
  bash: ['DEV_*']       # the bash tool may use vaulted DEV_* secrets silently
  pii_run: ['API_KEY_*'] # pii_run may inject API_KEY_* without a prompt
```

Globs match the label, the placeholder, or the bare stem, case-insensitively.
Anything not listed still goes through the one-step prompt, and publishing or
uploading always asks for every item regardless of scope.

---

## Agent-facing tools

### `pii_secret` — CRUD

| Action | Arguments | Returns |
| --- | --- | --- |
| `list` | — | Labels, placeholders, tags, timestamps. **Never values.** |
| `add` | `label`, `value`, `tags?` | The new entry's id and placeholder |
| `edit` | `id`, `label?`, `value?`, `tags?` | The id and the **unchanged** placeholder |
| `remove` | `id` | The removed id, or `null` |

Every operation is effective immediately — no restart, no re-read. `edit` never
rewrites the placeholder, so a transcript that already contains `{{API_KEY_1}}`
keeps resolving after a rename.

### `pii_run` — using a secret without leaking it

Redaction alone is not enough to *use* a secret. A tool argument containing
`{{API_KEY_1}}` cannot be rewritten at `tools/pre-execute` (arguments are already
logged) and `tools/execute` may only replace the signal — so a plain `bash` call
would execute the literal placeholder.

`pii_run` closes that gap by substituting **inside the tool body**, after the
arguments are logged:

```jsonc
// The model calls this — no secret value anywhere in the request
{ "command": "curl -H \"Authorization: Bearer $API_KEY_1\" https://api.example.com",
  "secrets": ["{{API_KEY_1}}"] }
```

The value arrives as the environment variable `API_KEY_1`, never in `argv`
(which `ps` exposes to other users), and the result is scrubbed on the way back
so a command that echoes its environment cannot hand the value to the model.
Each secret is approved by the same one-step gate unless a scope covers it.

> `inline: true` splices values into the command string itself for tools that
> cannot read environment variables. Off by default because argv is readable.

---

## Rotation

```js
await vault.rotate(newPassphrase) // re-seals under a fresh scrypt salt
```

The on-disk format is unchanged, so old files keep working and no migration is
needed; the data is re-encrypted in place and the previous key is zeroed only
after the new file lands.

> **Update wherever the passphrase lives.** The unlock chain is
> `DSH_PII_SECRETS_PASSPHRASE` → OS keyring → `keyCommand`. If you rotate while
> an env var still holds the old passphrase, the next unlock will use the old
> value and fail. Rotate the stored copy too.

---

## Testing

```sh
npm test
```

```
ℹ tests 109
ℹ pass 109
ℹ fail 0
```

| Suite | Covers |
| --- | --- |
| `engine.test.js` | Crypto round-trip, permissions, atomic writes, pattern catalog |
| `policy.test.js` | Managed/unknown classification, gating, fail-closed behaviour |
| `plugin.test.js` | Cordis wiring, waterfall protocol, decision shapes |
| `client.test.js` | DOM checklist, Select All, eye toggle, fail-closed cancel |
| `upgrades.test.js` | Entropy detection, redaction cache, tripwire, scopes, rotation, audit, keyring, `pii_run` |
| `regressions.test.js` | One named test per bug fixed during review |

> **Note:** `test/schemastery-stub.js` exists only because some sandboxes cannot
> install the real `@deepseek-ai/schemastery` dependency chain. It implements the
> exact surface the plugin uses. The plugin itself imports the real package.

---

## Security model

**What this protects against**

- A managed secret reaching a hosted model provider, in a prompt or a tool result.
- A secret logged *before* it was vaulted being sent, via the `llm/stream` tripwire.
- A tool silently printing or shipping a secret you registered.
- A secret value being typed onto a command line that `ps` exposes, via `pii_run`.
- Accidental commits of PII/credentials appearing in the transcript.

**How**

- **AES-256-GCM** with a **scrypt**-derived key (N=2^15, r=8, p=1). The GCM tag
  authenticates: a wrong passphrase or a modified file fails loudly rather than
  returning partial plaintext.
- **Atomic writes** — temp file, `fsync`, `rename`, mode `0600`. A crash never
  leaves a half-written vault.
- **Fail closed** — a missing, erroring, or timing-out prompt resolves to
  "do not expose".
- **No raw values in UI payloads** — the prompt carries masked text only; raw
  values sit behind a per-row accessor the UI calls on click.
- **Detection-only tripwire** — the one seam that sees the final frozen request
  can refuse it but never rewrites it, so a retro-logged secret fails loudly
  instead of shipping.
- **Secrets never in `argv`** — `pii_run` passes them as environment variables,
  scrubs its own output, and refuses to run without at least one secret.
- **Keyring over files** — the passphrase can come from the OS keyring, read with
  `execFile` (no shell) and never written to disk by this plugin.

---

## Known limitations

Honest limits, stated plainly:

- **Metadata is not secret.** Labels and tags live in the clear inside the
  encrypted envelope; only the payload is encrypted.
- **The passphrase is the perimeter.** Anyone who can set
  `DSH_PII_SECRETS_PASSPHRASE` as you can decrypt the vault. The file is `0600`,
  but a process running as you can read it.
- **A wrong passphrase is recoverable, but cautious.** A failed unlock drops the
  cached key, so correcting the passphrase works without a restart — and a vault
  that failed to decrypt is never overwritten, because that would destroy every
  stored secret.
- **Detection is heuristic.** The catalog catches common shapes, not semantics.
  Put real secrets in the vault — vault substitution is exact, the regexes are
  best-effort.
- **Secrets shorter than 4 characters** are still redacted outbound, but cannot
  be located by substring match in tool arguments (a 1-character secret matches
  everything).
- **Tool bodies that open their own sockets** are gated on their arguments at
  `tools/pre-execute`, not on the bytes they later send.
- **Your local transcript is not encrypted.** The vault protects what leaves the
  machine. dsh writes the session log in the clear, so a secret typed into a
  prompt is on your disk before redaction runs. `blockUnredactedHistory` stops it
  from being *sent*, not from being *stored*.
- **A secret vaulted late is in history.** `agent/pre-step` rewrites inbox
  messages only; tool results already in the log are not re-scrubbed. Adding a
  secret after it appeared in the transcript leaves it there — hence the
  tripwire, which refuses such a request instead of sending it.
- **`pii_run` executes locally.** A command you approve can still send data over
  the network. The scrub stops the *value* reaching the model, not a determined
  exfiltration by the command itself. Scope it narrowly.

---

## Contributing

Issues and pull requests are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) and
our [Code of Conduct](CODE_OF_CONDUCT.md). For security reports, read
[SECURITY.md](SECURITY.md) first: please do not open a public issue.

## License

[MIT](LICENSE) © Md. Shahriar Alam Shaon ([@0xShahriar](https://github.com/0xShahriar))