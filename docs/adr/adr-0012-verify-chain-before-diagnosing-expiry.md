# 0012. Verify the chain before diagnosing expiry

- **Status:** Accepted
- **Date:** 2026-07-10

## Context

Servers routinely present expired *extraneous* certificates that a real verifier
simply ignores — the AddTrust External CA Root (expired 2020), the ISRG Root X1
cross-sign via DST Root X3, a stale `fullchain.pem`. Diagnosing expiry by scanning
the raw presented chain *before* verification therefore reports `expired`/critical
for a host `x509.Verify` accepts and every browser considers healthy — and keeps
firing until someone rewrites the server's chain file. For a certificate monitor
this is the worst possible failure mode: false criticals train people to ignore
alerts. At the same time, "expired" is the more actionable diagnosis than a
generic "invalid" when a cert genuinely lapsed.

## Decision

Run `verify` **first**; if it succeeds, decide status solely from the verified
chain's expiry (`VerifiedNotAfter`) — an expired cert can never be in a verified
chain, so `expired` cannot false-positive. Only if verification *fails* do we fall
back to `earliestExpired(peers)` over the presented chain, to prefer the `expired`
diagnosis over a generic `invalid`. For `insecure` targets (no trust anchor to
attribute intermediates to) the expired check and thresholds are based on the
**leaf only**.

## Consequences

- Invariant: for a verified target, `expired` derives only from the verified chain's
  expiry, never from an extraneous peer cert.
- Genuinely expired leaves/intermediates still classify as `expired` (verification fails
  → the fallback diagnosis is retained).
- `insecure` mode's leaf-only expiry/threshold basis is a documented, deliberate
  narrowing.

## References

- `internal/probe/probe.go` (`evaluate`, `verify`, `earliestExpired`, `VerifiedNotAfter`).
