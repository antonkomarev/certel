package main

import (
	"os"
	"path/filepath"
	"testing"
)

const validYAML = `notifiers:
  default:
    url: https://example.com/alert
    body: {status: "${alert.Status}"}
target_defaults:
  notifiers: [default]
targets:
  - address: example.com
`

// writeConfig drops a config file into a temp dir and returns its path.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunValidateConfigValid(t *testing.T) {
	path := writeConfig(t, validYAML)
	if got := runValidateConfig([]string{path}); got != 0 {
		t.Errorf("exit = %d, want 0", got)
	}
}

func TestRunValidateConfigInvalid(t *testing.T) {
	// No targets: config.Validate rejects it.
	path := writeConfig(t, `notifiers:
  default:
    url: https://example.com/alert
    body: {text: x}
`)
	if got := runValidateConfig([]string{path}); got != 1 {
		t.Errorf("exit = %d, want 1", got)
	}
}

func TestRunValidateConfigBrokenBody(t *testing.T) {
	// Passes config validation but the body references an unknown alert field,
	// so ParseBody must reject it — the same failure the monitor would hit at
	// startup.
	path := writeConfig(t, `notifiers:
  default:
    url: https://example.com/alert
    body: {text: "${alert.NoSuchField}"}
target_defaults:
  notifiers: [default]
targets:
  - address: example.com
`)
	if got := runValidateConfig([]string{path}); got != 1 {
		t.Errorf("exit = %d, want 1", got)
	}
}

func TestRunValidateConfigMissingFile(t *testing.T) {
	if got := runValidateConfig([]string{filepath.Join(t.TempDir(), "absent.yaml")}); got != 1 {
		t.Errorf("exit = %d, want 1", got)
	}
}

func TestRunValidateConfigTooManyArgs(t *testing.T) {
	if got := runValidateConfig([]string{"a.yaml", "b.yaml"}); got != 2 {
		t.Errorf("exit = %d, want 2", got)
	}
}
