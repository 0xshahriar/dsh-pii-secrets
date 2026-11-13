# Pull request

## Summary

What does this change, and why?

Closes #

## Type of change

- [ ] Bug fix (adds a named regression test in `test/regressions.test.js`)
- [ ] New feature
- [ ] New secret pattern
- [ ] Documentation
- [ ] Refactor (no behaviour change)

## Design invariants

This project handles credentials. Confirm your change keeps these intact
(see `SECURITY.md`):

- [ ] Managed secrets are still redacted **silently** — never prompted
- [ ] Every exposure prompt is still **one step**
- [ ] Failure or ambiguity still resolves to **deny** (fail closed)
- [ ] **No raw secret** reaches a UI payload (masked text only)
- [ ] An undecryptable vault is still **never overwritten**
- [ ] Redaction still happens at `agent/pre-step`, not `llm/stream`

## Testing

```
ℹ tests <n>
ℹ pass <n>
ℹ fail 0
```

- [ ] `npm test` passes
- [ ] I added or updated a test for this change

## Checklist

- [ ] `CHANGELOG.md` updated under `## [Unreleased]`
- [ ] Documentation updated if behaviour or configuration changed
- [ ] No new dependency (or it was agreed in an issue first)
- [ ] **No real secrets, tokens, or `.env` contents in the diff**
