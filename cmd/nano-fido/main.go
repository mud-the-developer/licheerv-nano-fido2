// Experimental Linux HID-gadget adapter. Not a certified authenticator.
// The pinned upstream integration and its software tests live in this repository.
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bulwarkid/virtual-fido/ctap"
	"github.com/bulwarkid/virtual-fido/ctap_hid"
	"github.com/bulwarkid/virtual-fido/fido_client"
	"github.com/bulwarkid/virtual-fido/identities"
	"github.com/bulwarkid/virtual-fido/internal/nanokit"
	"github.com/bulwarkid/virtual-fido/u2f"
	"github.com/bulwarkid/virtual-fido/util"
)

type support struct {
	store  nanokit.Store
	pass   string
	button string
	lines  <-chan string
}

func (s *support) SaveData(b []byte) {
	if e := s.store.Save(b); e != nil {
		panic("vault write failed")
	}
}
func (s *support) RetrieveData() []byte {
	b, e := s.store.Read()
	if e != nil {
		panic("vault read failed; do not delete the vault")
	}
	return b
}
func (s *support) Passphrase() string { return s.pass }

// Active-low button: release, then a fresh stable press is required.
// The GPIO must already be safely mapped and configured as input.
func waitButton(path string, deadline time.Time) bool {
	released := false
	stable := 0
	for time.Now().Before(deadline) {
		b, e := os.ReadFile(path)
		if e != nil {
			return false
		}
		switch strings.TrimSpace(string(b)) {
		case "1":
			released = true
			stable = 0
		case "0":
			if released {
				stable++
				if stable >= 3 {
					return true
				}
			}
		default:
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}
func (s *support) ApproveClientAction(
	action fido_client.ClientAction,
	p fido_client.ClientActionRequestParams) bool {
	fmt.Printf("Request %d: RP=%q user=%q\n", action, p.RelyingParty, p.UserName)
	deadline := time.Now().Add(30 * time.Second)
	if s.button != "" {
		fmt.Println("Release, then press the configured physical button.")
		return waitButton(s.button, deadline)
	}
	var random [4]byte
	if _, e := rand.Read(random[:]); e != nil {
		return false
	}
	token := hex.EncodeToString(random[:])
	fmt.Printf("TEST ONLY: type %s within 30 seconds: ", token)
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	for {
		select {
		case line, ok := <-s.lines:
			if !ok {
				return false
			}
			if strings.TrimSpace(line) == token {
				return true
			}
		case <-timer.C:
			return false
		}
	}
}
func loadPass(path string) (string, error) {
	st, e := os.Lstat(path)
	if e != nil {
		return "", e
	}
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > 4096 {
		return "", errors.New("pass file must be a regular 0600 file")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return "", e
	}
	if e = os.Remove(path); e != nil {
		return "", e
	}
	if len(b) < 16 {
		return "", errors.New("use a vault passphrase >=16 bytes")
	}
	pass := string(b)
	for i := range b {
		b[i] = 0
	}
	return pass, nil // Go strings are not guaranteed to be securely erased.
}

// Unsupported CTAP commands are rejected, not forwarded to a panic path.
type ctapGate struct{ inner *ctap.CTAPServer }

func (g ctapGate) HandleMessage(b []byte) []byte {
	if len(b) == 0 {
		return []byte{0x12}
	}
	switch b[0] {
	case 1, 2, 4, 6, 8:
		return g.inner.HandleMessage(b)
	default:
		return []byte{0x01}
	}
}

func must(e error) {
	if e != nil {
		log.Fatal(e)
	}
}
func main() {
	defer func() {
		if recover() != nil {
			fmt.Fprintln(os.Stderr, "Stopped after an upstream/state error.")
			fmt.Fprintln(os.Stderr, "Keep the vault. Do not auto-reset or auto-restart.")
			os.Exit(1)
		}
	}()
	hid := flag.String("hid", "/dev/hidg0", "confirmed FIDO gadget node")
	vault := flag.String("vault", "/var/lib/nano-fido/vault.enc", "encrypted vault")
	pf := flag.String("pass-file", "", "0600 file on tmpfs; consumed once")
	button := flag.String("button-value", "", "verified active-low GPIO value file")
	terminal := flag.Bool("terminal-approval", false, "TEST ONLY: not physical presence")
	flag.Parse()
	if os.Geteuid() != 0 {
		log.Fatal("this prototype expects root")
	}
	if (*button == "") == (!*terminal) {
		log.Fatal("choose exactly one: --button-value OR --terminal-approval")
	}
	pass, e := loadPass(*pf)
	must(e)
	s := &support{store: nanokit.Store{Path: *vault}, pass: pass, button: *button}
	if *terminal {
		st, e := os.Stdin.Stat()
		must(e)
		if st.Mode()&os.ModeCharDevice == 0 {
			log.Fatal("interactive TTY required")
		}
		ch := make(chan string)
		s.lines = ch
		go func() {
			defer close(ch)
			scan := bufio.NewScanner(os.Stdin)
			scan.Buffer(make([]byte, 512), 512)
			for scan.Scan() {
				ch <- scan.Text()
			}
		}()
	}
	util.SetLogOutput(io.Discard)
	// Upstream otherwise buffers disabled debug/unsafe logs, including PIN data.
	// Route every level to the discard sink before loading any sensitive state.
	util.SetLogLevel(util.LogLevelUnsafe)
	key, e := identities.CreateCAPrivateKey()
	must(e)
	ca, e := identities.CreateSelfSignedCA(key)
	must(e)
	var wrap [32]byte
	_, e = rand.Read(wrap[:])
	must(e)
	client := fido_client.NewDefaultClient(ca, key, wrap, true, s, s)
	// Persists initial random state; does not choose/set a FIDO PIN.
	client.EnablePIN()
	server := ctap_hid.NewCTAPHIDServer(
		ctapGate{ctap.NewCTAPServer(client)}, u2f.NewU2FServer(client))
	f, e := os.OpenFile(*hid, os.O_RDWR, 0)
	must(e)
	defer f.Close()
	var writeMu sync.Mutex
	server.SetResponseHandler(func(b []byte) {
		writeMu.Lock()
		defer writeMu.Unlock()
		if nanokit.WriteReport(f, b) != nil {
			log.Fatal("HID write failed; reconnect and restart manually")
		}
	})
	fmt.Println("Experimental Nano FIDO adapter ready; disposable accounts only.")
	for {
		b, e := nanokit.ReadReport(f)
		must(e)
		server.HandleMessage(b)
		// Synchronous upstream processing is a known CANCEL/concurrency limit.
	}
}
