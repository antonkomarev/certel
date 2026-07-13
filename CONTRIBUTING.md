# Contributing to certel

Thanks for taking the time to contribute! This document covers the local
setup, the checks a change must pass, and what we look for in pull requests.

## Development setup

You need Go (the version pinned in [go.mod](go.mod)) and `make`. There is no
cgo — the SQLite driver is pure Go — so a plain Go toolchain is enough on any
platform.

```sh
make build   # binaries land in bin/ (version stamped from git describe)
make test    # go test ./...
make vet     # go vet ./...
```

To watch alerts flow end to end, run the bundled webhook receiver and point
`alert.url` at it (the `config.example.yaml` placeholder already does):

```sh
go run ./cmd/notification-sink # listen on :9999, print alerts, respond 200
cp config.example.yaml config.yaml
bin/certel monitor -config config.yaml
```

## Checks your change must pass

CI runs the following on every pull request; running them locally first saves
a round trip:

```sh
gofmt -l .        # must print nothing
go vet ./...
go test -race ./...
golangci-lint run ./...   # config in .golangci.yml
```

Install golangci-lint with
`go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest`.

## Guidelines

- **Keep the scope of the project in mind**: a single self-contained binary
  configured by a single YAML file. Features that require external services
  beyond the alert webhook and an optional Prometheus scrape need a strong
  case.
- **Add tests** for behavior changes. Probe logic is tested against local
  in-process listeners (see `internal/probe/*_test.go`) — no network access
  is required to run the suite.
- **Compatibility is a contract**:
  - `Host.Key()` format is persisted in the database — changing it breaks
    alert-state restoration for existing users.
  - The `ssl_*` metric names mirror ssl_exporter — do not rename them.
  - Config file fields are public API; renames need a deprecation path.
- **Commit messages**: a short imperative subject line ("Add FTP STARTTLS
  probe"), with a body explaining *why* when it is not obvious.
- One logical change per pull request. Refactoring and behavior changes go
  in separate commits at minimum, ideally separate PRs.

## Reporting bugs and proposing features

Use the issue templates. For bugs, include the output of
`certel version`, your (redacted) config, and relevant log lines.
For security issues, do **not** open a public issue — see
[SECURITY.md](SECURITY.md).
