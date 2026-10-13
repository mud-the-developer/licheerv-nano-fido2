// Original experimental integration helpers. Not a certified authenticator.
package nanokit

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const ReportSize = 64

// A gadget read is one HID report, not a byte-stream fragment.
func ReadReport(r io.Reader) ([]byte, error) {
	b := make([]byte, ReportSize)
	n, err := r.Read(b)
	if err != nil {
		return nil, err
	}
	if n != len(b) {
		return nil, fmt.Errorf("short HID report: %d", n)
	}
	return b, nil
}

func WriteReport(w io.Writer, b []byte) error {
	if len(b) != ReportSize {
		return errors.New("invalid report size")
	}
	n, err := w.Write(b)
	if err != nil {
		return err
	}
	if n != len(b) {
		return io.ErrShortWrite
	}
	return nil
}

// Store expects a root-owned directory on Linux. Its bytes are already
// encrypted by the upstream vault; this helper performs no encryption.
type Store struct{ Path string }

func (s Store) Read() ([]byte, error) {
	st, err := os.Lstat(s.Path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || !privateOwner(st) {
		return nil, errors.New("vault must be an owned regular 0600 file")
	}
	if st.Size() < 1 || st.Size() > 16*1024*1024 {
		return nil, errors.New("invalid vault size; do not reset it")
	}
	return os.ReadFile(s.Path)
}

func (s Store) Save(b []byte) error {
	if len(b) == 0 {
		return errors.New("refusing an empty vault")
	}
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode().Perm() != 0700 || !privateOwner(st) {
		return errors.New("vault directory must be an owned real 0700 directory")
	}
	f, err := os.CreateTemp(dir, ".vault-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	defer f.Close()
	if err = f.Chmod(0600); err != nil {
		return err
	}
	if n, e := f.Write(b); e != nil {
		return e
	} else if n != len(b) {
		return io.ErrShortWrite
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, s.Path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
