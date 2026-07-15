---
title: 'NNNN. Short title of the decision'
weight: 999
# This is the copy-me scaffold, not a real decision: keep it reachable via the
# explicit link in the ADR index Conventions section, but out of the auto-built
# navigation sidebar, the site search, and the generated llms.txt outline.
excludeSearch: true
llms: false
sidebar:
  exclude: true
---

- **Status:** Proposed | Accepted | Superseded by NNNN | Deprecated
- **Date:** YYYY-MM-DD
- **Shipped in:** `<commit>` (and/or a version tag)

## Context

The forces at play: the problem, the constraints, what made this a real choice.
State the facts and pressures neutrally — enough that a reader who wasn't here
understands why a decision was needed at all. Link to the code, the schema, or a
`docs/` design doc rather than restating them.

## Decision

What we chose, in the active voice ("We do X"). One or two paragraphs. Be concrete
about the mechanism, not just the intent.

## Consequences

What follows — good and bad. The invariants this establishes, the tradeoffs
accepted, the things now easier or harder, anything a future change must not break
without knowing why.

## Alternatives considered

The options weighed and rejected, each with the reason it lost. Omit the section if
there were none worth recording. (This is often the most valuable part: it stops a
rejected idea from quietly reopening.)

## References

- `file:line` anchors, related ADRs, `docs/` design docs, and commit hashes
  beyond the "Shipped in" one when their messages carry extra rationale. Do not
  cite deleted `todo/` files: everything decision-relevant must be *in* the ADR;
  the shipping commit's history holds the todo's full text if archaeology is
  ever needed.
