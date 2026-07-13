# Security Policy

certel is a security-adjacent tool: it probes TLS endpoints and
handles webhook credentials. We take reports about its own security seriously.

## Supported versions

Until 1.0, only the latest release receives security fixes.

## Reporting a vulnerability

Please **do not open a public issue** for anything you believe is a
vulnerability (e.g. certificate verification being weaker than documented,
credential leakage into logs or the database, injection via server-controlled
data such as certificate fields or STARTTLS banners).

Instead, use GitHub's private vulnerability reporting: **Security → Report a
vulnerability** on the repository. We will acknowledge the report within a
few days and keep you informed of the fix's progress. Please include a
reproduction (a config snippet and, where relevant, a malicious-server
sketch) and the version affected.

## Scope notes for reporters

- `insecure: true` intentionally skips chain-of-trust and hostname
  verification (expiry is still checked). Reports that boil down to "insecure
  mode is insecure" are working as documented.
- The monitor talks to the servers listed in its own config and to the
  configured alert webhook — it exposes no inbound API beyond read-only
  `/metrics` and `/healthz`. Anything that lets a *probed server* influence
  more than its own check result (or the alert payload text) is in scope and
  interesting.
