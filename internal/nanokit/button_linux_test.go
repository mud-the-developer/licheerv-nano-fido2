package nanokit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUserButtonRejectsRegularFileAndMissingDevice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-an-input-device")
	if err := os.WriteFile(path, make([]byte, 24), 0600); err != nil {
		t.Fatal(err)
	}
	if WaitUserButton(path, time.Now().Add(time.Second)) {
		t.Fatal("regular file approved")
	}
	if WaitUserButton(path+"-missing", time.Now().Add(time.Second)) {
		t.Fatal("missing device approved")
	}
}

func TestUserButtonPressCannotApproveTwice(t *testing.T) {
	state := userButtonState{released: true}
	if approve, fail := state.event(1, UserButtonCode, 1); !approve || fail {
		t.Fatal("fresh press rejected")
	}
	if approve, fail := state.event(1, UserButtonCode, 1); approve || fail {
		t.Fatal("held press reused")
	}
}
