package main

import (
	"strings"
	"testing"
)

func TestRunCompletionSupportedShells(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish"} {
		if got := runCompletion([]string{shell}); got != 0 {
			t.Errorf("completion %s: exit = %d, want 0", shell, got)
		}
	}
}

func TestRunCompletionUsageErrors(t *testing.T) {
	cases := [][]string{
		{},                // no shell
		{"powershell"},    // unknown shell
		{"bash", "extra"}, // too many args
	}
	for _, args := range cases {
		if got := runCompletion(args); got != 2 {
			t.Errorf("completion %v: exit = %d, want 2", args, got)
		}
	}
}

// The scripts are what actually gets installed, so guard that each embeds the
// full command set — a command added to main's switch but forgotten here would
// silently ship an incomplete completion.
func TestCompletionScriptsCoverCommands(t *testing.T) {
	commands := []string{"monitor", "check", "validate-config", "healthcheck", "version", "completion", "help"}
	scripts := map[string]string{"bash": completionBash, "zsh": completionZsh, "fish": completionFish}
	for shell, script := range scripts {
		for _, cmd := range commands {
			if !strings.Contains(script, cmd) {
				t.Errorf("%s completion script is missing command %q", shell, cmd)
			}
		}
	}
}
