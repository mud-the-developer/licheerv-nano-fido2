package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"crypto/rand"
	"github.com/bulwarkid/virtual-fido/fido_client"
	"github.com/bulwarkid/virtual-fido/identities"
)

func requireNewVault(path string) error {
	_, err := os.Lstat(path)
	if err == nil {
		return errors.New("vault already exists; initialization never overwrites it")
	}
	if !os.IsNotExist(err) {
		return err
	}
	return nil
}

func validInitialPIN(pin []byte) bool {
	return len(pin) <= 63 && utf8.Valid(pin) && utf8.RuneCount(pin) >= 4 && !strings.ContainsRune(string(pin), 0)
}

func loadInitialPIN(path string) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > 63 {
		return nil, errors.New("PIN file must be a regular 0600 file of at most 63 bytes")
	}
	pin, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err = os.Remove(path); err != nil {
		return nil, err
	}
	if !validInitialPIN(pin) {
		for i := range pin {
			pin[i] = 0
		}
		return nil, errors.New("PIN must contain at least four UTF-8 characters and at most 63 bytes")
	}
	return pin, nil
}

func newClient(s *support) *fido_client.DefaultFIDOClient {
	key, err := identities.CreateCAPrivateKey()
	must(err)
	ca, err := identities.CreateSelfSignedCA(key)
	must(err)
	var wrap [32]byte
	_, err = rand.Read(wrap[:])
	must(err)
	return fido_client.NewDefaultClient(ca, key, wrap, true, s, s)
}

func writeReady(path string) error {
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(path)
		}
	}()
	value := strconv.Itoa(os.Getpid()) + "\n"
	n, err := io.WriteString(f, value)
	if err != nil {
		return err
	}
	if n != len(value) {
		return io.ErrShortWrite
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("ready marker close: %w", err)
	}
	ok = true
	return nil
}
