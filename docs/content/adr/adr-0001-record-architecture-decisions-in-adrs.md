---
title: '0001. Record architecture decisions in ADRs'
weight: 1
---

- **Status:** Accepted
- **Date:** 2026-07-12

## Context

By the pre-1.0 mark, certel had accumulated many non-obvious design decisions —
`alert_repeat_interval` lives on the target not the notifier, `unreachable` is
critical not emergency, fan-out is delivery-only, `min_severity` is a stateless
floor, the SQLite outbox state model, per-notifier concurrency. The *reasoning*
behind each was real and deliberate, but it lived in three places that all decay:
commit messages (unindexed), `todo/` prose files (deleted once the feature
shipped), and `docs/alternatives.md` (one topic only). A contributor had no
single place to read to understand the design and its trade-offs, and nothing
stopped a future change from quietly undoing a deliberate choice.

The candidate formats:

- **ADR** — one short doc per decision (context / decision / consequences),
  append-only, superseded-not-edited. Low ceremony.
- **TSD** (Technical/Software Design Doc) — one or a few long docs describing the
  whole system. Good for onboarding; heavy to keep current.
- **FRD** (Functional Requirements Document) — the product contract from the
  user's point of view: the *what*, not the *why*.

## Decision

We adopt **ADRs as the primary format**, laid out under
`docs/content/adr/adr-NNNN-title.md` with the conventions in this section's
[index](_index.md): monotonic four-digit numbering, a
`Proposed/Accepted/Superseded/Deprecated` status line, and an append-only rule
(a changed decision gets a new superseding ADR; the old one stays).

certel's design is, concretely, a pile of individual "we chose X over Y" calls —
the exact unit an ADR captures. ADRs also pair naturally with how the reasoning
is produced: each resolved `todo/` design lock graduates into one ADR. We
deliberately stand up **no TSD or FRD**, because their jobs are already covered:
the big-picture/onboarding role by the [README](https://github.com/antonkomarev/certel) plus the two
standing design docs ([`alternatives.md`](../alternatives.md),
[`metrics.md`](../metrics.md)), and the feature/scope contract by the README and
[`config.example.yaml`](https://github.com/antonkomarev/certel/blob/main/config.example.yaml). This chooses the primary
format; it does not forbid the others (see the alternatives below).

## Consequences

- Every deliberate, reversible-by-the-uninformed decision gets a discoverable home.
- The `todo/` → ADR lifecycle is explicit (see the README): forward-looking work
  items graduate into backward-looking records when they ship.
- The bar stays sustainable by *excluding* mechanical fixes and hardening from
  ADRs — those stay in git history. The failure mode being avoided is a
  heavyweight process nobody updates.
- Existing long-form design docs are cross-referenced, never copied, so there is
  one source of truth per topic.

## Alternatives considered

- **A single TSD for the whole system.** Rejected as the primary format: it would
  go stale as one big document, and the README already carries the big picture. A
  short overview in this directory's README is cheaper than a parallel design doc
  to maintain.
- **An FRD.** Not adopted now: it would restate the feature contract the README
  and `config.example.yaml` already pin, and it captures the *what*, whereas the
  gap here is the *why*. Not rejected outright — a formal 1.0+ scope contract,
  acceptance testing, or external stakeholders could earn it a place later, as a
  complement to the ADRs.
- **Leaving the rationale in commit messages and `todo/` files.** Rejected — that
  is the status quo this ADR exists to fix: unindexed and deleted-on-ship.

## References

- [`docs/alternatives.md`](../alternatives.md), [`docs/metrics.md`](../metrics.md).
