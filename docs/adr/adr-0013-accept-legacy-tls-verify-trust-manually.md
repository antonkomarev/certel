# 0013. Accept TLS ≥ 1.0, verify trust manually; the `weak_signature` status

- **Status:** Accepted
- **Date:** 2026-07-09

## Context

With Go's client default minimum (TLS 1.2), TLS 1.0/1.1-only endpoints — old
appliances, embedded management interfaces, legacy mail servers, exactly the fleet
a self-hosted monitor gets pointed at — fail the handshake and report a permanent
`unreachable`, so their certificates (which also expire, and are the whole point
of monitoring) are never inspected. A read-only prober that transmits nothing
sensitive and verifies the chain manually has little to lose by accepting a lower
floor.

## Decision

Set `MinVersion: tls.VersionTLS10`; trust is verified manually regardless of the
negotiated version, so accepting a legacy handshake does not weaken the verdict.
Separately, a chain that fails verification *only* because it carries a SHA-1 (or
older) signature is classified as a distinct **`weak_signature`** status rather than
`invalid`, and its expiry is still surfaced from the presented chain. Because the
algorithm error is buried in an `UnknownAuthorityError`'s unexported hint, the chain
is inspected directly rather than unwrapping the error. The TLS floor is stated in
the README rather than left implicit in the `crypto/tls` defaults.

## Consequences

- Legacy endpoints become inspectable; their expiry is *classified* instead of masked as
  `unreachable`.
- `weak_signature` is a probe failure (`ssl_probe_success == 0`), distinct from
  `invalid`, and maps to `critical` — "live but legacy," not failing now
  ([0008](adr-0008-severity-ladder-and-status-mapping.md)).

## Alternatives considered

- **A per-target `min_tls_version` knob with the Go default unchanged.** Noted as a
  fallback if lowering the floor globally felt wrong; the global floor was chosen instead
  because manual verification makes the negotiated version irrelevant to the verdict.

## References

- `internal/probe/probe.go` (`tls.Config`, `MinVersion`, `evaluate`),
  `internal/probe/result.go` (`weak_signature`), README.
