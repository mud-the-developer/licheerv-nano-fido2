package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bulwarkid/virtual-fido/ctap"
)

func TestGateRejectsResetAndAllowsNextAssertion(t *testing.T) {
	gate := ctapGate{inner: ctap.NewCTAPServer(nil)}
	for _, tc := range []struct {
		request []byte
		status  byte
	}{
		{nil, 0x12}, {[]byte{7}, 1}, {[]byte{0xff}, 1}, {[]byte{8}, 0x30},
	} {
		if response := gate.HandleMessage(tc.request); !bytes.Equal(response, []byte{tc.status}) {
			t.Fatal("wrong gate status")
		}
	}
}
func TestMissingButtonFailsClosed(t *testing.T) {
	if waitButton(filepath.Join(t.TempDir(), "missing"), time.Now().Add(time.Second)) {
		t.Fatal("missing button accepted")
	}
}
func TestAlreadyHeldButtonDoesNotApprove(t *testing.T) {
	path := filepath.Join(t.TempDir(), "value")
	if err := os.WriteFile(path, []byte("0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if waitButton(path, time.Now().Add(45*time.Millisecond)) {
		t.Fatal("already-held button approved without release")
	}
}
