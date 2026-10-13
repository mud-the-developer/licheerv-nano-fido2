package ctap_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"io"
	"os"
	"testing"

	"github.com/bulwarkid/virtual-fido/cose"
	"github.com/bulwarkid/virtual-fido/ctap"
	"github.com/bulwarkid/virtual-fido/fido_client"
	"github.com/bulwarkid/virtual-fido/identities"
	"github.com/bulwarkid/virtual-fido/util"
	"github.com/bulwarkid/virtual-fido/webauthn"
	"github.com/fxamacker/cbor/v2"
)

// All credentials, PINs and encrypted vaults here are synthetic, in-memory test data.
func TestMain(m *testing.M) {
	util.SetLogOutput(io.Discard)
	util.SetLogLevel(util.LogLevelUnsafe)
	os.Exit(m.Run())
}

type memoryStore struct {
	blob   []byte
	pass   string
	writes int
}

func (s *memoryStore) SaveData(b []byte)    { s.blob = append([]byte(nil), b...); s.writes++ }
func (s *memoryStore) RetrieveData() []byte { return append([]byte(nil), s.blob...) }
func (s *memoryStore) Passphrase() string {
	if s.pass != "" {
		return s.pass
	}
	return "synthetic-test-vault-passphrase"
}

type approver struct {
	allow bool
	calls int
}

func (a *approver) ApproveClientAction(_ fido_client.ClientAction, _ fido_client.ClientActionRequestParams) bool {
	a.calls++
	return a.allow
}
func authenticator(t *testing.T, store *memoryStore, approval *approver) (*fido_client.DefaultFIDOClient, *ctap.CTAPServer) {
	t.Helper()
	key, err := identities.CreateCAPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	ca, err := identities.CreateSelfSignedCA(key)
	if err != nil {
		t.Fatal(err)
	}
	var wrappingKey [32]byte
	if _, err := rand.Read(wrappingKey[:]); err != nil {
		t.Fatal(err)
	}
	client := fido_client.NewDefaultClient(ca, key, wrappingKey, true, approval, store)
	client.EnablePIN()
	return client, ctap.NewCTAPServer(client)
}
func call(t *testing.T, server *ctap.CTAPServer, command byte, args any) []byte {
	t.Helper()
	request := []byte{command}
	if args != nil {
		encoded, err := cbor.Marshal(args)
		if err != nil {
			t.Fatal(err)
		}
		request = append(request, encoded...)
	}
	response := server.HandleMessage(request)
	if len(response) == 0 {
		t.Fatal("missing CTAP status")
	}
	return response
}
func status(t *testing.T, response []byte, expected byte) {
	t.Helper()
	if len(response) == 0 || response[0] != expected {
		t.Fatalf("CTAP status: got %x, want %02x", response[0], expected)
	}
}
func makeArgs(rp, user string, hash []byte) map[int]any {
	return map[int]any{
		1: hash,
		2: webauthn.PublicKeyCredentialRPEntity{ID: rp, Name: "Synthetic relying party"},
		3: webauthn.PublicKeyCrendentialUserEntity{ID: []byte(user), Name: user, DisplayName: user},
		4: []webauthn.PublicKeyCredentialParams{{Type: "public-key", Algorithm: -7}},
		7: map[string]bool{"rk": true},
	}
}

type registration struct {
	AuthData  []byte `cbor:"2,keyasint"`
	Statement struct {
		Signature    []byte   `cbor:"sig"`
		Certificates [][]byte `cbor:"x5c"`
	} `cbor:"3,keyasint"`
}

func register(t *testing.T, server *ctap.CTAPServer, args map[int]any) ([]byte, *cose.SupportedCOSEPublicKey) {
	t.Helper()
	response := call(t, server, 1, args)
	status(t, response, 0)
	var result registration
	if err := cbor.Unmarshal(response[1:], &result); err != nil {
		t.Fatal(err)
	}
	if len(result.AuthData) < 55 || result.AuthData[32]&0x41 != 0x41 {
		t.Fatal("invalid attested authenticator data")
	}
	rp := args[2].(webauthn.PublicKeyCredentialRPEntity).ID
	rpHash := sha256.Sum256([]byte(rp))
	if !bytes.Equal(result.AuthData[:32], rpHash[:]) {
		t.Fatal("wrong RP binding")
	}
	n := int(binary.BigEndian.Uint16(result.AuthData[53:55]))
	if n == 0 || len(result.AuthData) <= 55+n {
		t.Fatal("missing credential ID or key")
	}
	id := append([]byte(nil), result.AuthData[55:55+n]...)
	key, err := cose.UnmarshalCOSEPublicKey(result.AuthData[55+n:])
	if err != nil {
		t.Fatal(err)
	}
	if !key.Verify(append(append([]byte(nil), result.AuthData...), args[1].([]byte)...), result.Statement.Signature) {
		t.Fatal("invalid registration attestation signature")
	}
	if len(result.Statement.Certificates) != 1 {
		t.Fatal("missing attestation certificate")
	}
	cert, err := x509.ParseCertificate(result.Statement.Certificates[0])
	if err != nil {
		t.Fatal(err)
	}
	if !key.ECDSA.Equal(cert.PublicKey) {
		t.Fatal("certificate does not bind the credential key")
	}
	return id, key
}

type assertion struct {
	Credential webauthn.PublicKeyCredentialDescriptor `cbor:"1,keyasint"`
	AuthData   []byte                                 `cbor:"2,keyasint"`
	Signature  []byte                                 `cbor:"3,keyasint"`
	User       *struct {
		ID          []byte `cbor:"id"`
		Name        string `cbor:"name"`
		DisplayName string `cbor:"displayName"`
	} `cbor:"4,keyasint"`
	Count *uint32 `cbor:"5,keyasint"`
}

func checkAssertion(t *testing.T, response []byte, rp string, hash []byte, id []byte, key *cose.SupportedCOSEPublicKey, counter uint32) assertion {
	t.Helper()
	status(t, response, 0)
	var result assertion
	if err := cbor.Unmarshal(response[1:], &result); err != nil {
		t.Fatal(err)
	}
	if len(result.AuthData) != 37 || result.AuthData[32]&1 == 0 {
		t.Fatal("missing user presence or invalid authData")
	}
	rpHash := sha256.Sum256([]byte(rp))
	if !bytes.Equal(result.AuthData[:32], rpHash[:]) || !bytes.Equal(result.Credential.ID, id) {
		t.Fatal("wrong credential or RP")
	}
	if binary.BigEndian.Uint32(result.AuthData[33:]) != counter {
		t.Fatal("signature counter not persisted/incremented")
	}
	if !key.Verify(append(append([]byte(nil), result.AuthData...), hash...), result.Signature) {
		t.Fatal("invalid authentication signature")
	}
	return result
}

func TestNanoRegistrationAuthenticationAndReload(t *testing.T) {
	store, approval := &memoryStore{}, &approver{allow: true}
	client, server := authenticator(t, store, approval)
	hash := sha256.Sum256([]byte("synthetic registration challenge"))
	id, key := register(t, server, makeArgs("example.test", "alice", hash[:]))
	request := map[int]any{1: "example.test", 2: hash[:], 3: []webauthn.PublicKeyCredentialDescriptor{{Type: "public-key", ID: id}}}
	checkAssertion(t, call(t, server, 2, request), "example.test", hash[:], id, key, 1)
	sealingKey := append([]byte(nil), client.SealingEncryptionKey()...)
	client, server = authenticator(t, store, approval)
	if !bytes.Equal(sealingKey, client.SealingEncryptionKey()) {
		t.Fatal("device identity changed after reload")
	}
	checkAssertion(t, call(t, server, 2, request), "example.test", hash[:], id, key, 2)
	request[1] = "other.test"
	status(t, call(t, server, 2, request), 0x2e)
	args := makeArgs("example.test", "alice", hash[:])
	args[5] = []webauthn.PublicKeyCredentialDescriptor{{Type: "public-key", ID: id}}
	status(t, call(t, server, 1, args), 0x19)
	if len(client.Identities()) != 1 {
		t.Fatal("excludeList created a duplicate credential")
	}
}

func TestNanoResidentEnumerationAndRPIsolationAfterReload(t *testing.T) {
	store, approval := &memoryStore{}, &approver{allow: true}
	_, server := authenticator(t, store, approval)
	hash := sha256.Sum256([]byte("synthetic resident challenge"))
	id1, key1 := register(t, server, makeArgs("example.test", "alice", hash[:]))
	id2, key2 := register(t, server, makeArgs("example.test", "bob", hash[:]))
	otherID, otherKey := register(t, server, makeArgs("other.test", "carol", hash[:]))
	_, server = authenticator(t, store, approval)
	first := checkAssertion(t, call(t, server, 2, map[int]any{1: "example.test", 2: hash[:]}), "example.test", hash[:], id1, key1, 1)
	if first.Count == nil || *first.Count != 2 || first.User == nil || string(first.User.ID) != "alice" || first.User.Name != "" {
		t.Fatal("resident count or UV privacy incorrect")
	}
	second := checkAssertion(t, call(t, server, 8, nil), "example.test", hash[:], id2, key2, 1)
	if second.User == nil || string(second.User.ID) != "bob" {
		t.Fatal("wrong second resident user")
	}
	status(t, call(t, server, 8, nil), 0x30)
	checkAssertion(t, call(t, server, 2, map[int]any{1: "other.test", 2: hash[:], 3: []any{}}), "other.test", hash[:], otherID, otherKey, 1)
	call(t, server, 2, map[int]any{1: "example.test", 2: hash[:]})
	status(t, call(t, server, 4, nil), 0)
	status(t, call(t, server, 8, nil), 0x30)
}

func TestNanoDeniedPresenceDoesNotMutateVault(t *testing.T) {
	store, approval := &memoryStore{}, &approver{allow: true}
	_, server := authenticator(t, store, approval)
	hash := sha256.Sum256([]byte("synthetic denied challenge"))
	id, _ := register(t, server, makeArgs("example.test", "alice", hash[:]))
	before := append([]byte(nil), store.blob...)
	approval.allow = false
	status(t, call(t, server, 1, makeArgs("example.test", "bob", hash[:])), 0x27)
	status(t, call(t, server, 2, map[int]any{1: "example.test", 2: hash[:], 3: []webauthn.PublicKeyCredentialDescriptor{{Type: "public-key", ID: id}}}), 0x27)
	if !bytes.Equal(before, store.blob) {
		t.Fatal("denied request changed persistent state")
	}
}

func TestNanoMalformedRequestsAndResetFailClosed(t *testing.T) {
	store, approval := &memoryStore{}, &approver{allow: true}
	_, server := authenticator(t, store, approval)
	for _, request := range [][]byte{nil, {1, 0xff}, {1, 0xa0}, {2, 0xa0}, {7}, {0xff}} {
		response := server.HandleMessage(request)
		if len(response) == 0 || response[0] == 0 {
			t.Fatal("malformed/unsupported command accepted")
		}
	}
	status(t, call(t, server, 6, map[int]any{1: 1, 2: 5}), 0x14)
	hash := sha256.Sum256([]byte("synthetic malformed challenge"))
	args := makeArgs("example.test", "alice", hash[:])
	args[1] = []byte{1}
	status(t, call(t, server, 1, args), 2)
	args = makeArgs("example.test", "alice", hash[:])
	args[7] = map[string]bool{"uv": true}
	status(t, call(t, server, 1, args), 0x2b)
	if approval.calls != 0 {
		t.Fatal("invalid requests reached approval")
	}
}

// This host side uses Go's standard crypto/ecdh and AES/HMAC, independently of upstream helpers.
type pinPeer struct {
	key    cose.COSEEC2Key
	secret []byte
}

func peer(t *testing.T, server *ctap.CTAPServer) pinPeer {
	t.Helper()
	response := call(t, server, 6, map[int]any{1: 1, 2: 2})
	status(t, response, 0)
	var agreement struct {
		Key cose.COSEEC2Key `cbor:"1,keyasint"`
	}
	if err := cbor.Unmarshal(response[1:], &agreement); err != nil {
		t.Fatal(err)
	}
	key := agreement.Key
	if key.KeyType != 2 || key.Algorithm != -25 || key.Curve != 1 || len(key.X) != 32 || len(key.Y) != 32 {
		t.Fatal("non-conforming PIN key agreement")
	}
	remote, err := ecdh.P256().NewPublicKey(append(append([]byte{4}, key.X...), key.Y...))
	if err != nil {
		t.Fatal(err)
	}
	local, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := local.ECDH(remote)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(shared)
	pub := local.PublicKey().Bytes()
	return pinPeer{cose.COSEEC2Key{KeyType: 2, Algorithm: -25, Curve: 1, X: pub[1:33], Y: pub[33:65]}, digest[:]}
}
func cbc(t *testing.T, key, data []byte, encrypt bool) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, len(data))
	if encrypt {
		cipher.NewCBCEncrypter(block, make([]byte, 16)).CryptBlocks(out, data)
	} else {
		cipher.NewCBCDecrypter(block, make([]byte, 16)).CryptBlocks(out, data)
	}
	return out
}
func mac(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)[:16]
}
func setPIN(t *testing.T, server *ctap.CTAPServer, pin string) []byte {
	t.Helper()
	p := peer(t, server)
	padded := make([]byte, 64)
	copy(padded, pin)
	enc := cbc(t, p.secret, padded, true)
	return call(t, server, 6, map[int]any{1: 1, 2: 3, 3: p.key, 4: mac(p.secret, enc), 5: enc})
}
func token(t *testing.T, server *ctap.CTAPServer, pin string) ([]byte, byte) {
	t.Helper()
	p := peer(t, server)
	hash := sha256.Sum256([]byte(pin))
	response := call(t, server, 6, map[int]any{1: 1, 2: 5, 3: p.key, 6: cbc(t, p.secret, hash[:16], true)})
	if response[0] != 0 {
		return nil, response[0]
	}
	var result struct {
		Token []byte `cbor:"2,keyasint"`
	}
	if err := cbor.Unmarshal(response[1:], &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Token) < 16 || len(result.Token)%16 != 0 {
		t.Fatal("invalid encrypted PIN token")
	}
	return cbc(t, p.secret, result.Token, false), 0
}

func TestNanoPINProtocolAndTokenInvalidation(t *testing.T) {
	store, approval := &memoryStore{}, &approver{allow: true}
	_, server := authenticator(t, store, approval)
	status(t, setPIN(t, server, "1234"), 0)
	oldToken, code := token(t, server, "1234")
	if code != 0 {
		t.Fatal("PIN token exchange failed", code)
	}
	hash := sha256.Sum256([]byte("synthetic PIN challenge"))
	args := makeArgs("example.test", "alice", hash[:])
	status(t, call(t, server, 1, args), 0x36)
	args[8], args[9] = mac(oldToken, hash[:]), 1
	id, key := register(t, server, args)
	response := call(t, server, 2, map[int]any{1: "example.test", 2: hash[:], 6: mac(oldToken, hash[:]), 7: 1})
	assertion := checkAssertion(t, response, "example.test", hash[:], id, key, 1)
	if assertion.AuthData[32]&4 == 0 || assertion.User.Name != "alice" {
		t.Fatal("PIN-verified assertion lost UV/user information")
	}
	p := peer(t, server)
	padded := make([]byte, 64)
	copy(padded, "5678")
	newEnc := cbc(t, p.secret, padded, true)
	oldHash := sha256.Sum256([]byte("1234"))
	oldEnc := cbc(t, p.secret, oldHash[:16], true)
	status(t, call(t, server, 6, map[int]any{1: 1, 2: 4, 3: p.key, 4: mac(p.secret, append(newEnc, oldEnc...)), 5: newEnc, 6: oldEnc}), 0)
	status(t, call(t, server, 1, args), 0x33)
	newToken, code := token(t, server, "5678")
	if code != 0 || bytes.Equal(oldToken, newToken) {
		t.Fatal("changing PIN did not replace its token")
	}
	_, server = authenticator(t, store, approval)
	if _, code := token(t, server, "5678"); code != 0 {
		t.Fatal("PIN hash did not survive reload")
	}
}

func TestNanoPINRetriesPersistIncludingBlockedZero(t *testing.T) {
	store, approval := &memoryStore{}, &approver{allow: true}
	client, server := authenticator(t, store, approval)
	status(t, setPIN(t, server, "1234"), 0)
	for failures := 1; failures <= 8; failures++ {
		if failures == 4 || failures == 7 {
			client, server = authenticator(t, store, approval)
		}
		_, code := token(t, server, "0000")
		expected := byte(0x31)
		if failures == 3 || failures == 6 {
			expected = 0x34
		}
		if failures == 8 {
			expected = 0x32
		}
		if code != expected || client.PINRetries() != int32(8-failures) {
			t.Fatal("wrong PIN failure status or retry counter", failures, code)
		}
		if failures == 3 {
			if _, code := token(t, server, "1234"); code != 0x34 {
				t.Fatal("three-failure session lock bypassed")
			}
		}
	}
	client, server = authenticator(t, store, approval)
	if client.PINRetries() != 0 {
		t.Fatal("restart reset the blocked zero")
	}
	if _, code := token(t, server, "1234"); code != 0x32 {
		t.Fatal("blocked PIN accepted after restart")
	}
	status(t, call(t, server, 6, map[int]any{1: 1, 2: 1}), 0)
}

func TestNanoPINPolicyAndInvalidAgreement(t *testing.T) {
	_, server := authenticator(t, &memoryStore{}, &approver{allow: true})
	for _, pin := range []string{"123", "가나다", "\xff\xff\xff\xff"} {
		status(t, setPIN(t, server, pin), 0x37)
	}
	status(t, setPIN(t, server, "가나다라"), 0)
	bad := cose.COSEEC2Key{KeyType: 2, Algorithm: -25, Curve: 1, X: make([]byte, 32), Y: make([]byte, 32)}
	status(t, call(t, server, 6, map[int]any{1: 1, 2: 5, 3: bad, 6: make([]byte, 16)}), 2)
	p := peer(t, server)
	status(t, call(t, server, 6, map[int]any{1: 1, 2: 5, 3: p.key, 6: []byte{1}}), 2)
}

func TestNanoLegacyVaultMigrationAndCorruptionDoNotReset(t *testing.T) {
	store, approval := &memoryStore{}, &approver{allow: true}
	_, _ = authenticator(t, store, approval)
	state, err := identities.DecryptFIDOState(store.blob, store.Passphrase())
	if err != nil {
		t.Fatal(err)
	}
	state.PINRetries = nil
	store.blob, err = identities.EncryptFIDOState(*state, store.Passphrase())
	if err != nil {
		t.Fatal(err)
	}
	client, _ := authenticator(t, store, approval)
	if client.PINRetries() != 8 {
		t.Fatal("legacy vault migration failed")
	}
	corrupted := append([]byte(nil), store.blob...)
	corrupted[len(corrupted)/2] ^= 1
	invalidRetries := int32(9)
	state.PINRetries = &invalidRetries
	invalidState, err := identities.EncryptFIDOState(*state, store.Passphrase())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		blob []byte
		pass string
	}{
		{"wrong-passphrase", store.blob, "synthetic-wrong-passphrase"},
		{"corrupted-ciphertext", corrupted, ""},
		{"invalid-retry-state", invalidState, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			broken := &memoryStore{blob: append([]byte(nil), tc.blob...), pass: tc.pass}
			before := append([]byte(nil), broken.blob...)
			func() {
				defer func() {
					if recover() == nil {
						t.Error("invalid vault did not fail closed")
					}
				}()
				authenticator(t, broken, approval)
			}()
			if !bytes.Equal(before, broken.blob) || broken.writes != 0 {
				t.Fatal("failed restore overwrote the vault")
			}
		})
	}
}
