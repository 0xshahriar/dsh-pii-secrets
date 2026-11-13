---
name: Bug report
about: Something behaved incorrectly, or a secret was exposed when it should not have been
title: 'bug: '
labels: bug
---

<!--
STOP. If this is a SECURITY issue — a secret leaked, a gate failed open, the
vault was written over — do NOT file a public issue.
See SECURITY.md and report privately instead.

Never paste a real secret. A detect() fingerprint is enough to correlate.
-->

## What happened

A clear description of the bug.

## What you expected

What should have happened instead.

## Steps to reproduce

1.
2.
3.

## Which surface

- [ ] Outbound model request (`agent/pre-step`)
- [ ] Tool call gating (`tools/pre-execute`)
- [ ] Tool-result scrubbing (`tools/post-execute`)
- [ ] Vault / encryption
- [ ] TUI prompt
- [ ] Web prompt
- [ ] `pii_secret` CRUD tool

## Configuration

```yaml
# your pii-secrets config block, with anything sensitive removed
```

## Environment

| Field | Value |
| --- | --- |
| `node -v` | |
| `dsh --version` | |
| OS | |
| Installed via | npm / github / local `file:` |

## Relevant output

```
# error message or the VaultError code (e.g. BAD_PASSPHRASE, NOT_LOADED).
# Redact any secret value.
```

## Checklist

- [ ] I have not included any real secret, token, or `.env` contents
- [ ] I searched existing issues first
- [ ] This is not a security vulnerability (those go through SECURITY.md)
