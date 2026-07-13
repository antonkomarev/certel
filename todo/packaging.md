# Packaging — distributable artifacts with completions bundled

**Where:** new packaging config at repo root (nfpm `nfpm.yaml` and/or goreleaser `.goreleaser.yaml`), a Homebrew formula (tap or homebrew-core), the `Makefile` (an `install` target), and the README install section.

**What we want.** `apt install certel` / `brew install certel` (or the equivalent) drops the binary on `PATH` *and* the shell completion into the OS completion dir, so `certel <Tab>` works with zero user setup. Today the only "install" is `make build` → `bin/`, or Docker; completion must be wired by hand (the README one-liner).

**Why the completion piece is already easy.** `certel completion <bash|zsh|fish>` exists and prints a static script per shell — exactly the primitive every packaging tool expects. All three targets below just call it and place the output:

- bash → `/usr/share/bash-completion/completions/certel`
- zsh  → `/usr/share/zsh/site-functions/_certel`
- fish → `/usr/share/fish/vendor_completions.d/certel.fish`

These dirs are on the default completion search path, so a file landing there works after opening a new shell — no rc edits.

**Options, by effort/payoff:**

1. **`make install` target** — cheapest. `install -Dm755 bin/certel` to `/usr/local/bin`, then `certel completion <shell>` into the completion dirs. Helps source installs only; `/usr/share` usually needs sudo. Good stopgap before release packaging.
2. **Homebrew formula** — best "brew install → completion works" for macOS (the dev's shell). Use `generate_completions_from_executable(bin/"certel", "completion")` — Homebrew runs all three shells and installs to its prefix. Needs a tap or a homebrew-core PR.
3. **goreleaser / nfpm** — the proper release path: builds `.deb`/`.rpm`/Homebrew in one shot, completions included via the standard option, plus versioned release artifacts (also stamps `certel version`). Most config, closes everything at once.

**Deliverable:** at least one install channel where the completion script ships automatically; README install steps updated; the "when packaging lands" notes in the README Shell-completion section resolved.

**Priority:** low. Depends on wanting real releases; nothing is broken without it. If picking one first, `make install` is the quick win and Homebrew is the highest-value for the dev's own machine.
