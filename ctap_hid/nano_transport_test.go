package ctap_hid

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"testing"

	"github.com/bulwarkid/virtual-fido/cose"
	"github.com/bulwarkid/virtual-fido/ctap"
	"github.com/bulwarkid/virtual-fido/fido_client"
	"github.com/bulwarkid/virtual-fido/identities"
	"github.com/bulwarkid/virtual-fido/webauthn"
	"github.com/fxamacker/cbor/v2"
)

type packetCollector struct {
	mu      sync.Mutex
	packets [][]byte
}

func (c *packetCollector) handle(p []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.packets = append(c.packets, append([]byte(nil), p...))
}
func (c *packetCollector) reset() { c.mu.Lock(); defer c.mu.Unlock(); c.packets = nil }
func (c *packetCollector) snapshot() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.packets...)
}

// Host framing is independent of the authenticator's createResponsePackets helper.
func hostReports(cid uint32, command byte, payload []byte) [][]byte {
	first := make([]byte, 64)
	binary.LittleEndian.PutUint32(first, cid)
	first[4] = command
	binary.BigEndian.PutUint16(first[5:7], uint16(len(payload)))
	n := copy(first[7:], payload)
	packets := [][]byte{first}
	for seq, remaining := byte(0), payload[n:]; len(remaining) > 0; seq++ {
		packet := make([]byte, 64)
		binary.LittleEndian.PutUint32(packet, cid)
		packet[4] = seq
		n = copy(packet[5:], remaining)
		remaining = remaining[n:]
		packets = append(packets, packet)
	}
	return packets
}
func exchange(t *testing.T, server *CTAPHIDServer, collector *packetCollector, cid uint32, command byte, payload []byte) []byte {
	t.Helper()
	collector.reset()
	for _, report := range hostReports(cid, command, payload) {
		server.HandleMessage(report)
	}
	var result []byte
	total, seq, initialized := 0, byte(0), false
	for _, report := range collector.snapshot() {
		if len(report) != 64 || binary.LittleEndian.Uint32(report[:4]) != cid {
			t.Fatal("wrong HID packet length or channel")
		}
		if report[4] == byte(ctapHIDCommandKeepalive) {
			continue
		}
		if report[4]&0x80 != 0 {
			if initialized || report[4] != command {
				t.Fatalf("unexpected HID command: %02x", report[4])
			}
			initialized = true
			total = int(binary.BigEndian.Uint16(report[5:7]))
			result = append(result, report[7:]...)
		} else {
			if !initialized || report[4] != seq {
				t.Fatal("invalid HID continuation sequence")
			}
			seq++
			result = append(result, report[5:]...)
		}
	}
	if !initialized || len(result) < total {
		t.Fatal("missing or incomplete HID response")
	}
	return result[:total]
}
func openChannel(t *testing.T, server *CTAPHIDServer, collector *packetCollector) uint32 {
	t.Helper()
	nonce := []byte("12345678")
	response := exchange(t, server, collector, 0xffffffff, 0x86, nonce)
	if len(response) != 17 || !bytes.Equal(response[:8], nonce) || response[12] != 2 || response[16]&4 == 0 {
		t.Fatal("invalid INIT response")
	}
	return binary.LittleEndian.Uint32(response[8:12])
}
func TestNanoHIDEmptyPingFragmentationAndAssignedInit(t *testing.T) {
	server := NewCTAPHIDServer(&dummyHandler{}, &dummyHandler{})
	collector := &packetCollector{}
	server.SetResponseHandler(collector.handle)
	cid := openChannel(t, server, collector)
	if result := exchange(t, server, collector, cid, 0x81, nil); len(result) != 0 {
		t.Fatal("empty PING did not return an empty response")
	}
	for _, n := range []int{1, 57, 58, 116, 1024, 7609} {
		payload := bytes.Repeat([]byte{0x5a}, n)
		if !bytes.Equal(exchange(t, server, collector, cid, 0x81, payload), payload) {
			t.Fatal("fragmented PING mismatch", n)
		}
	}
	response := exchange(t, server, collector, cid, 0x86, []byte("87654321"))
	if binary.LittleEndian.Uint32(response[8:12]) != cid {
		t.Fatal("assigned-channel INIT allocated a different channel")
	}
}
func TestNanoHIDMalformedMessagesFailClosed(t *testing.T) {
	server := NewCTAPHIDServer(&dummyHandler{}, &dummyHandler{})
	collector := &packetCollector{}
	server.SetResponseHandler(collector.handle)
	cid := openChannel(t, server, collector)
	cases := []struct {
		cid      uint32
		command  byte
		payload  []byte
		expected byte
	}{
		{0xffffffff, 0x86, nil, 3},
		{0xffffffff, 0x86, []byte("1234567"), 3},
		{0xffffffff, 0x86, []byte("123456789"), 3},
		{0xffffffff, 0x84, nil, 1},
		{cid, 0x88, nil, 1},
		{0x12345678, 0x81, nil, 0x0b},
	}
	for _, tc := range cases {
		collector.reset()
		for _, report := range hostReports(tc.cid, tc.command, tc.payload) {
			server.HandleMessage(report)
		}
		packets := collector.snapshot()
		if len(packets) != 1 || packets[0][4] != 0xbf || packets[0][7] != tc.expected {
			t.Fatal("wrong HID error", tc.command)
		}
	}
	collector.reset()
	server.HandleMessage(nil)
	if len(collector.snapshot()) != 0 {
		t.Fatal("unaddressable short packet generated response")
	}
	for _, n := range []int{4, 7, 63, 65} {
		collector.reset()
		server.HandleMessage(make([]byte, n))
		packets := collector.snapshot()
		if len(packets) != 1 || packets[0][7] != 3 {
			t.Fatal("invalid report size accepted", n)
		}
	}
	collector.reset()
	report := hostReports(cid, 0x81, nil)[0]
	binary.BigEndian.PutUint16(report[5:7], 7610)
	server.HandleMessage(report)
	if packets := collector.snapshot(); len(packets) != 1 || packets[0][7] != 3 {
		t.Fatal("oversized transaction accepted")
	}
}

type hidMemoryStore struct{ blob []byte }

func (s *hidMemoryStore) SaveData(b []byte)    { s.blob = append([]byte(nil), b...) }
func (s *hidMemoryStore) RetrieveData() []byte { return append([]byte(nil), s.blob...) }
func (s *hidMemoryStore) Passphrase() string   { return "synthetic-hid-test-passphrase" }

type hidApproval struct{ allow bool }

func (a *hidApproval) ApproveClientAction(_ fido_client.ClientAction, _ fido_client.ClientActionRequestParams) bool {
	return a.allow
}
func TestNanoHIDRealRegistrationAndAuthentication(t *testing.T) {
	key, err := identities.CreateCAPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	ca, err := identities.CreateSelfSignedCA(key)
	if err != nil {
		t.Fatal(err)
	}
	var wrap [32]byte
	if _, err := rand.Read(wrap[:]); err != nil {
		t.Fatal(err)
	}
	client := fido_client.NewDefaultClient(ca, key, wrap, true, &hidApproval{true}, &hidMemoryStore{})
	client.EnablePIN()
	server := NewCTAPHIDServer(ctap.NewCTAPServer(client), &dummyHandler{})
	collector := &packetCollector{}
	server.SetResponseHandler(collector.handle)
	cid := openChannel(t, server, collector)
	info := exchange(t, server, collector, cid, 0x90, []byte{4})
	if len(info) < 2 || info[0] != 0 {
		t.Fatal("GetInfo failed over HID")
	}
	hash := sha256.Sum256([]byte("synthetic framed registration challenge"))
	request, err := cbor.Marshal(map[int]any{
		1: hash[:],
		2: webauthn.PublicKeyCredentialRPEntity{ID: "example.test", Name: "Example"},
		3: webauthn.PublicKeyCrendentialUserEntity{ID: []byte("alice"), Name: "alice"},
		4: []webauthn.PublicKeyCredentialParams{{Type: "public-key", Algorithm: -7}},
	})
	if err != nil {
		t.Fatal(err)
	}
	created := exchange(t, server, collector, cid, 0x90, append([]byte{1}, request...))
	if len(created) < 2 || created[0] != 0 {
		t.Fatal("MakeCredential failed over HID")
	}
	var registration struct {
		AuthData []byte `cbor:"2,keyasint"`
	}
	if err := cbor.Unmarshal(created[1:], &registration); err != nil {
		t.Fatal(err)
	}
	if len(registration.AuthData) < 55 {
		t.Fatal("truncated registration")
	}
	n := int(binary.BigEndian.Uint16(registration.AuthData[53:55]))
	if len(registration.AuthData) <= 55+n {
		t.Fatal("missing credential key")
	}
	id := registration.AuthData[55 : 55+n]
	public, err := cose.UnmarshalCOSEPublicKey(registration.AuthData[55+n:])
	if err != nil {
		t.Fatal(err)
	}
	request, err = cbor.Marshal(map[int]any{1: "example.test", 2: hash[:], 3: []webauthn.PublicKeyCredentialDescriptor{{Type: "public-key", ID: id}}})
	if err != nil {
		t.Fatal(err)
	}
	response := exchange(t, server, collector, cid, 0x90, append([]byte{2}, request...))
	if len(response) < 2 || response[0] != 0 {
		t.Fatal("GetAssertion failed over HID")
	}
	var assertion struct {
		AuthData  []byte `cbor:"2,keyasint"`
		Signature []byte `cbor:"3,keyasint"`
	}
	if err := cbor.Unmarshal(response[1:], &assertion); err != nil {
		t.Fatal(err)
	}
	if !public.Verify(append(append([]byte(nil), assertion.AuthData...), hash[:]...), assertion.Signature) {
		t.Fatal("invalid HID authentication signature")
	}
}
