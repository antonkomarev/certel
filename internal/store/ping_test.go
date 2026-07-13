package store

import (
	"path/filepath"
	"testing"
)

func TestPing(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "certel.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Ping(); err != nil {
		t.Errorf("ping on an open store: %v", err)
	}
	s.Close()
	if err := s.Ping(); err == nil {
		t.Error("ping on a closed store: expected error, got nil")
	}
}
