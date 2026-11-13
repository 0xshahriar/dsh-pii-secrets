<div align="center">

# dsh-pii-secrets

**PII Secrets Manager for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)**

Keep secrets on your machine. Swap them for placeholders before any request
reaches an LLM provider. Pause the actions that would leak them.

[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)](#)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%E2%89%A520-brightgreen.svg)](#requirements)
[![Tests](https://img.shields.io/badge/tests-77%20passing-brightgreen.svg)](#testing)
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
- [Agent-facing CRUD](#agent-facing-crud)
- [Testing](#testing)
- [Security model](#security-model)
- [Known limitations](#known-limitations)
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
| `llm/stream` | **No** | Loop-built requests "arrive deep-frozen (mutation throws) … listeners read it, never rewrite it", and its `next()` takes no argument — it returns the adapter's chunk stream, not the request. |
| `agent/pre-step` | **Yes** | A waterfall that may replace the messages entering a step: `PreStepDecision = { kind: 'reject' } \| { kind: 'enter', messages }`. |
| `tools/post-execute` | **Yes** | Scrubs tool output before the model reads it. |

So the plugin redacts the earliest *mutable* copy of anything bound for a
provider, then scrubs tool results so a secret printed by a tool never even
reaches the model. `llm/stream` is documented read-only in `src/index.js` so
nobody "fixes" it back later.

### Project layout

| Path | Role |
| --- | --- |
| `src/vault.js` | AES-256-GCM envelope, scrypt KDF, atomic writes, live `SecretStore` |
| `src/redact.js` | Regex pattern catalog, placeholder substitution, masking, Luhn check |
| `src/policy.js` | `ExposurePolicy` — the single decision point for every surface |
| `src/ui.js` | One-step prompt adapters: user-questions, inquirer, web RPC |
| `src/index.js` | Cordis wiring: the three seams plus the agent-facing CRUD tool |
| `web/client.js` | Browser half: multi-select checklist, Select All, eye toggle |
| `test/` | 77 tests across crypto, redaction, policy, wiring, DOM, regressions |

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
```

---

## Agent-facing CRUD

The model gets a `pii_secret` tool with three actions:

| Action | Arguments | Returns |
| --- | --- | --- |
| `list` | — | Labels, placeholders, tags, timestamps. **Never values.** |
| `add` | `label`, `value`, `tags?` | The new entry's id and placeholder |
| `remove` | `id` | The removed id, or `null` |

Every operation is effective immediately — no restart, no re-read.

---

## Testing

```sh
npm test
```

```
ℹ tests 77
ℹ pass 77
ℹ fail 0
```

| Suite | Covers |
| --- | --- |
| `engine.test.js` | Crypto round-trip, permissions, atomic writes, pattern catalog |
| `policy.test.js` | Managed/unknown classification, gating, fail-closed behaviour |
| `plugin.test.js` | Cordis wiring, waterfall protocol, decision shapes |
| `client.test.js` | DOM checklist, Select All, eye toggle, fail-closed cancel |
| `regressions.test.js` | One named test per bug fixed during review |

> **Note:** `test/schemastery-stub.js` exists only because some sandboxes cannot
> install the real `@deepseek-ai/schemastery` dependency chain. It implements the
> exact surface the plugin uses. The plugin itself imports the real package.

---

## Security model

**What this protects against**

- A managed secret reaching a hosted model provider, in a prompt or a tool result.
- A tool silently printing or shipping a secret you registered.
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

---

## Contributing

Issues and pull requests are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) and
our [Code of Conduct](CODE_OF_CONDUCT.md). For security reports, read
[SECURITY.md](SECURITY.md) first: please do not open a public issue.

## License

[MIT](LICENSE) © Md. Shahriar Alam Shaon ([@0xShahriar](https://github.com/0xShahriar))