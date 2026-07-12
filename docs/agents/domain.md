# Domain Docs

How engineering skills should consume this repository's domain documentation.

## Before exploring, read these

- `CONTEXT.md` at the repository root.
- Relevant ADRs under `docs/adr/`.

If these files do not exist, proceed silently. Create them lazily through domain-modeling when terminology or decisions are resolved.

## Layout

This is a single-context repository:

```
/
├── CONTEXT.md
├── docs/
│   └── adr/
└── src/
```

## Use the glossary's vocabulary

Use canonical terms from `CONTEXT.md` in issues, specifications, hypotheses, tests, and code.

If a required concept is absent, reconsider whether new language is necessary or record the gap for domain-modeling.

## Flag ADR conflicts

Explicitly identify output that contradicts an existing ADR instead of silently overriding it.
