# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | ✅ Yes |
| < 0.1.0 | ❌ No |

This is a `0.x` project: breaking changes are possible in minor releases, but
security fixes are backported to the latest `0.1.x` only.

## Reporting a vulnerability

**Please do not open a public issue.**

Report privately via either channel:

1. **[GitHub Private Vulnerability Reporting](https://github.com/0xShahriar/dsh-pii-secrets/security/advisories/new)** (preferred)
2. **Email:** sadjoker.localhost@gmail.com

Please include:

- A description of the issue and its impact.
- Steps to reproduce, or a proof-of-concept.
- Affected version/commit.
- Whether the issue is already public.

### What to expect

| Stage | Target |
| --- | --- |
| Acknowledgement | within 72 hours |
| Initial assessment | within 7 days |
| Fix or mitigation plan | within 30 days |
| Public advisory | after a fix ships |

Credit will be given in the advisory unless you ask otherwise.

### Please do not include

- Real secret values. A `detect()` fingerprint is enough to correlate.
- Vault files, even encrypted ones.
- Your `DSH_PII_SECRETS_PASSPHRASE`.

## Threat model

### In scope

| Threat | Control |
| --- | --- |
| A managed secret reaching a hosted LLM provider | Redaction at `agent/pre-step`; scrub at `tools/post-execute` |
| A tool printing or shipping a registered secret | Capability gate at `tools/pre-execute`, default deny |
| Unmanaged credentials appearing in a transcript | Pattern detection with a one-step, masked prompt |
| Vault theft from disk | AES-256-GCM + scrypt; file mode `0600` |
| Vault tampering | GCM authentication tag: modified data fails to decrypt |
| Data loss from a crash mid-write | Atomic write (temp → `fsync` → `rename`) |
| Data loss after a failed unlock | Writes refused (`NOT_LOADED`) rather than re-encrypting |
| Prompt spoofing (UI inventing ids) | Selection filtered against real finding ids |

### Out of scope

These are documented limitations, not vulnerabilities:

- **An attacker who can read your environment.** Anyone who can set
  `DSH_PII_SECRETS_PASSPHRASE` as you, or read your process memory, can decrypt
  the vault. The passphrase *is* the perimeter.
- **Semantic secret detection.** The pattern catalog is heuristic. A secret that
  looks like prose will not be detected. Register real secrets in the vault.
- **A tool that opens its own network socket.** Tool bodies are gated on their
  arguments at `tools/pre-execute`, not on the bytes they later send. If a tool
  can read a file you name in its arguments, gating is capability-based, not
  content-based.
- **Metadata confidentiality.** Labels, tags and placeholders are inside the
  encrypted envelope but not themselves secret.
- **A compromised `dsh` host or a malicious plugin.** Plugins run with your
  permissions; this plugin cannot sandbox them.
- **Secrets shorter than 4 characters** in tool *arguments* (still redacted
  outbound; a 1-character secret cannot be located by substring match).

## Hardening recommendations

```sh
# 1. Keep the passphrase out of shell history.
read -rs DSH_PII_SECRETS_PASSPHRASE && export DSH_PII_SECRETS_PASSPHRASE

# 2. Prefer an OS keyring over an environment variable.
#    config: keyCommand: secret-tool lookup service dsh-pii

# 3. Check the vault's permissions.
ls -l "$DSH_HOME/pii-secrets.vault.json"   # expect -rw------- (0600)

# 4. Keep the vault out of version control.
echo '*.vault.json' >> .gitignore
```

Recommended config for high-risk workflows:

```yaml
unknownSecretPolicy: block   # refuse rather than prompt
piiLevel: all
```

## Design invariants

Any change that weakens one of these is a security regression:

1. Managed secrets are redacted **silently** — never prompted.
2. Every exposure prompt is **one step**.
3. Ambiguity or failure resolves to **deny** (fail closed).
4. **No raw secret** appears in a UI payload; masked text only.
5. An undecryptable vault is **never overwritten**.
6. Redaction happens **upstream** (`agent/pre-step`), never at `llm/stream`,
   which cannot rewrite a request.

## Acknowledgements

Thanks to everyone who reports issues responsibly. Named credit is given in the
relevant advisory unless you prefer to stay anonymous.