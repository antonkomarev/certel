package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeListenConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestListenAddressExplicit(t *testing.T) {
	path := writeListenConfig(t, "server:\n  listen: \":9000\"\n")
	got, err := ListenAddress(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != ":9000" {
		t.Errorf("listen = %q, want :9000", got)
	}
}

func TestListenAddressDefault(t *testing.T) {
	path := writeListenConfig(t, "targets:\n  - address: example.com\n")
	got, err := ListenAddress(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != defaultListen {
		t.Errorf("listen = %q, want %q", got, defaultListen)
	}
}

// The point of ListenAddress: a config that Load would reject — an
// unexpandable ${env.VAR} header, no targets — must still yield the address, so
// the healthcheck works without the monitor's secrets.
func TestListenAddressIgnoresInvalidRest(t *testing.T) {
	path := writeListenConfig(t, `server:
  listen: ":7777"
notifiers:
  default:
    url: https://example.com/alert
    headers:
      Authorization: Bearer ${env.CERTEL_TEST_SURELY_UNSET_TOKEN}
`)
	got, err := ListenAddress(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != ":7777" {
		t.Errorf("listen = %q, want :7777", got)
	}
}

func TestListenAddressMissingFile(t *testing.T) {
	if _, err := ListenAddress(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Error("expected error for a missing file")
	}
}

func TestListenAddressMalformedYAML(t *testing.T) {
	path := writeListenConfig(t, "server: [broken\n")
	_, err := ListenAddress(path)
	if err == nil {
		t.Fatal("expected error for malformed YAML")
	}
	if !strings.Contains(err.Error(), "parsing") {
		t.Errorf("error %q does not mention parsing", err)
	}
}
