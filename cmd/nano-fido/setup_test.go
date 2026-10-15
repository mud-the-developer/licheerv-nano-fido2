package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitialPINPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		valid       bool
	}{
		{"four digits", "1234", true},
		{"four unicode characters", "가나다라", true},
		{"short digits", "123", false},
		{"three unicode characters", "가나다", false},
		{"embedded NUL", "12\x0034", false},
		{"invalid UTF8", "\xff234", false},
		{"maximum bytes", strings.Repeat("a", 63), true},
		{"too many bytes", strings.Repeat("a", 64), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if validInitialPIN([]byte(tc.value)) != tc.valid {
				t.Fatal("wrong PIN policy")
			}
		})
	}
}

func TestInitializationNeverOverwritesExistingVault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.enc")
	if err := requireNewVault(path); err != nil {
		t.Fatal(err)
	}
	original := []byte("synthetic existing ciphertext")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := requireNewVault(path); err == nil {
		t.Fatal("existing vault allowed for initialization")
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != string(original) {
		t.Fatal("existing vault changed", err)
	}
}

func TestReadyMarkerIsExclusive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ready")
	if err := writeReady(path); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path)
	if err != nil || len(first) == 0 {
		t.Fatal("missing readiness", err)
	}
	if err := writeReady(path); err == nil {
		t.Fatal("ready marker overwritten")
	}
	second, err := os.ReadFile(path)
	if err != nil || string(first) != string(second) {
		t.Fatal("ready marker changed", err)
	}
}
