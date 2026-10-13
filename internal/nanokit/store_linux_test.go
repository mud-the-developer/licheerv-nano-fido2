package nanokit

import (
	"os"
	"path/filepath"
	"testing"
)

// These tests require actual Linux permission, rename and directory-fsync semantics.
func TestStoreLifecycle(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	s := Store{Path: filepath.Join(dir, "vault.enc")}
	if b, err := s.Read(); err != nil || b != nil {
		t.Fatal("missing vault", err)
	}
	for _, value := range []string{"first synthetic ciphertext", "second synthetic ciphertext"} {
		if err := s.Save([]byte(value)); err != nil {
			t.Fatal(err)
		}
		if b, err := s.Read(); err != nil || string(b) != value {
			t.Fatal("readback", err)
		}
		file, err := os.Stat(s.Path)
		if err != nil || file.Mode().Perm() != 0600 || !privateOwner(file) {
			t.Fatal("file mode/owner", err)
		}
		parent, err := os.Stat(dir)
		if err != nil || parent.Mode().Perm() != 0700 || !privateOwner(parent) {
			t.Fatal("directory mode/owner", err)
		}
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, ".vault-*")); len(matches) != 0 {
		t.Fatal("temporary file leaked")
	}
}
func TestEmptySaveRejected(t *testing.T) {
	s := Store{Path: filepath.Join(t.TempDir(), "vault")}
	if err := s.Save(nil); err == nil {
		t.Fatal("empty save accepted")
	}
}
func TestUnsafeVaultRejected(t *testing.T) {
	s := Store{Path: filepath.Join(t.TempDir(), "vault")}
	if err := os.WriteFile(s.Path, []byte("synthetic"), 0644); err != nil {
		t.Fatal(err)
	}
	// Creation modes are masked by root's 0077 umask on the Nano.
	// Explicitly establish the unsafe fixture instead of weakening the check.
	if err := os.Chmod(s.Path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read(); err == nil {
		t.Fatal("unsafe permissions accepted")
	}
}
func TestEmptyExistingRejected(t *testing.T) {
	s := Store{Path: filepath.Join(t.TempDir(), "vault")}
	if err := os.WriteFile(s.Path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read(); err == nil {
		t.Fatal("empty vault accepted")
	}
}
func TestSymlinkRejected(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	s := Store{Path: filepath.Join(dir, "link")}
	if err := os.Symlink(target, s.Path); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read(); err == nil {
		t.Fatal("symlink accepted")
	}
}
