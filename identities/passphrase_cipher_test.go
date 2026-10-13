package identities

import (
	"bytes"
	"encoding/json"
	"runtime/debug"
	"testing"

	"github.com/bulwarkid/virtual-fido/crypto"
	"golang.org/x/crypto/scrypt"
)

func TestSessionCipherFreshKeysAndLegacyFormat(t *testing.T) {
	const pass = "synthetic-cipher-test-passphrase"
	cipher, err := NewPassphraseCipher(pass, nil)
	if err != nil {
		t.Fatal(err)
	}
	first, err := cipher.Encrypt([]byte("synthetic state"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := cipher.Encrypt([]byte("synthetic state"))
	if err != nil {
		t.Fatal(err)
	}
	one, err := parseEncryptedBlob(first)
	if err != nil {
		t.Fatal(err)
	}
	two, err := parseEncryptedBlob(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(one.Salt, two.Salt) || bytes.Equal(one.EncryptionKey, two.EncryptionKey) || bytes.Equal(one.KeyNonce, two.KeyNonce) || bytes.Equal(one.DataNonce, two.DataNonce) || bytes.Equal(one.EncryptedData, two.EncryptedData) {
		t.Fatal("session salt or per-save key/nonce freshness is incorrect")
	}
	// Independent decoding with the original wrapping/encryption algorithm.
	wrappingKey, err := scrypt.Key([]byte(pass), one.Salt, 32768, 8, 1, 32)
	debug.FreeOSMemory()
	if err != nil {
		t.Fatal(err)
	}
	dataKey, err := crypto.Decrypt(wrappingKey, one.EncryptionKey, one.KeyNonce)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := crypto.Decrypt(dataKey, one.EncryptedData, one.DataNonce)
	if err != nil || string(plaintext) != "synthetic state" {
		t.Fatal("legacy format changed", err)
	}
	for _, encoded := range [][]byte{first, second} {
		if _, plaintext, err := OpenPassphraseCipher(encoded, pass); err != nil || string(plaintext) != "synthetic state" {
			t.Fatal("reload failed", err)
		}
	}
}

func TestSessionCipherReadsOriginalEncoder(t *testing.T) {
	const pass = "synthetic-legacy-test-passphrase"
	salt := bytes.Repeat([]byte{1}, 16)
	wrappingKey, err := scrypt.Key([]byte(pass), salt, 32768, 8, 1, 32)
	debug.FreeOSMemory()
	if err != nil {
		t.Fatal(err)
	}
	dataKey := bytes.Repeat([]byte{2}, 32)
	wrapped, keyNonce, err := crypto.Encrypt(wrappingKey, dataKey)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, dataNonce, err := crypto.Encrypt(dataKey, []byte("synthetic legacy state"))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(PassphraseEncryptedBlob{Salt: salt, EncryptionKey: wrapped, KeyNonce: keyNonce, EncryptedData: ciphertext, DataNonce: dataNonce})
	if err != nil {
		t.Fatal(err)
	}
	if _, plaintext, err := OpenPassphraseCipher(encoded, pass); err != nil || string(plaintext) != "synthetic legacy state" {
		t.Fatal("original-format vault cannot be read", err)
	}
	if _, _, err := OpenPassphraseCipher(encoded, "synthetic-wrong-passphrase"); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
}

func TestEncryptedBlobLengthsFailClosed(t *testing.T) {
	cipher, err := NewPassphraseCipher("synthetic-test-passphrase", nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := cipher.Encrypt([]byte("synthetic"))
	if err != nil {
		t.Fatal(err)
	}
	base, err := parseEncryptedBlob(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"salt", "key_nonce", "data_nonce", "encryption_key", "encrypted_data"} {
		t.Run(field, func(t *testing.T) {
			blob := *base
			switch field {
			case "salt":
				blob.Salt = []byte{1}
			case "key_nonce":
				blob.KeyNonce = nil
			case "data_nonce":
				blob.DataNonce = nil
			case "encryption_key":
				blob.EncryptionKey = nil
			case "encrypted_data":
				blob.EncryptedData = nil
			}
			bad, err := json.Marshal(blob)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := OpenPassphraseCipher(bad, "synthetic-test-passphrase"); err == nil {
				t.Fatal("malformed blob accepted")
			}
		})
	}
}
