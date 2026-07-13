package main

import (
	_ "embed"
	"fmt"
	"io"
	"os"
)

// The completion scripts are static: certel's command set is fixed, so the
// scripts are hand-written rather than generated. Each offers the top-level
// command names as first-argument completions and nothing more — no flag or
// target-name completion.
//
//go:embed completions/certel.bash
var completionBash string

//go:embed completions/certel.zsh
var completionZsh string

//go:embed completions/certel.fish
var completionFish string

// runCompletion prints the completion script for the named shell. It returns a
// process exit code: 0 on success, 2 on a usage error (missing or unknown
// shell), matching the CLI's usage/exit-code convention.
func runCompletion(args []string) int {
	if len(args) != 1 {
		completionUsage(os.Stderr)
		return 2
	}
	switch args[0] {
	case "bash":
		fmt.Fprint(os.Stdout, completionBash)
	case "zsh":
		fmt.Fprint(os.Stdout, completionZsh)
	case "fish":
		fmt.Fprint(os.Stdout, completionFish)
	case "-h", "-help", "--help", "help":
		completionUsage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "certel completion: unknown shell %q\n\n", args[0])
		completionUsage(os.Stderr)
		return 2
	}
	return 0
}

func completionUsage(w io.Writer) {
	fmt.Fprint(w, `usage: certel completion <bash|zsh|fish>

Print a shell completion script that completes certel's command names.

Install (zsh, one-off):
  certel completion zsh > "${fpath[1]}/_certel"
or source it from ~/.zshrc:
  source <(certel completion zsh)
`)
}
