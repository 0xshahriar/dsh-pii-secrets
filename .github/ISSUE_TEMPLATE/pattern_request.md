---
name: Secret pattern request
about: Suggest a new regex pattern for a credential or PII format
title: 'pattern: '
labels: pattern, enhancement
---

## What should be detected

Name the credential or PII format, and link to its documented shape if one
exists.

## Example

A **fake** example that matches the format:

```
mysvc_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

## Suggested regex

```js
/\bmysvc_[A-Za-z0-9]{32}\b/g
```

## Metadata

| Field | Value |
| --- | --- |
| `id` | `my-service-key` (kebab-case, stable) |
| `kind` | `api-token` / `cloud-credential` / `private-key` / `token` / `credential-url` / `password` / `pii` |
| `label` | My Service Key |
| `pii` | yes / no (drives the `piiLevel` filter) |
| `validate` | optional predicate, e.g. Luhn |

## False-positive risk

What ordinary text could this pattern accidentally match? Patterns that fire on
prose train users to click through prompts, so a narrow pattern is preferred.

## Checklist

- [ ] The regex is global (`/g`)
- [ ] The example above is fake, not a real credential
- [ ] I checked `src/redact.js` — the pattern is not already there
