package identities

import (
	"encoding/json"
	"fmt"
	"runtime/debug"

	"github.com/bulwarkid/virtual-fido/crypto"
	"golang.org/x/crypto/scrypt"
)

// PassphraseCipher caches only the 32-byte wrapping key for one unlocked session.
// The vault format and scrypt N=32768, r=8, p=1 are unchanged. Every save still
// uses a fresh random data key and fresh AES-GCM nonces. This is not secure RAM.
type PassphraseCipher struct {
	salt []byte
	key  []byte
}

func NewPassphraseCipher(passphrase string, salt []byte) (*PassphraseCipher, error) {
	if salt == nil {
		salt = crypto.RandomBytes(16)
	}
	if len(salt) != 16 {
		return nil, fmt.Errorf("invalid vault salt length")
	}
	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	// scrypt's temporary 32 MiB workspace is no longer reachable after Key
	// returns. Reclaim it now, rather than letting consecutive KDF calls keep
	// two workspaces resident and trigger OOM on the 128 MiB Nano.
	debug.FreeOSMemory()
	if err != nil {
		return nil, fmt.Errorf("could not derive vault wrapping key: %w", err)
	}
	return &PassphraseCipher{salt: append([]byte(nil), salt...), key: key}, nil
}

func parseEncryptedBlob(data []byte) (*PassphraseEncryptedBlob, error) {
	var blob PassphraseEncryptedBlob
	if err := json.Unmarshal(data, &blob); err != nil {
		return nil, fmt.Errorf("invalid encrypted vault JSON: %w", err)
	}
	if len(blob.Salt) != 16 || len(blob.EncryptionKey) != 48 || len(blob.KeyNonce) != 12 || len(blob.DataNonce) != 12 || len(blob.EncryptedData) < 16 {
		return nil, fmt.Errorf("invalid encrypted vault field lengths")
	}
	return &blob, nil
}

func (cipher *PassphraseCipher) Encrypt(data []byte) ([]byte, error) {
	dataKey := crypto.GenerateSymmetricKey()
	wrappedKey, keyNonce, err := crypto.Encrypt(cipher.key, dataKey)
	if err != nil {
		return nil, fmt.Errorf("could not wrap vault data key: %w", err)
	}
	ciphertext, dataNonce, err := crypto.Encrypt(dataKey, data)
	if err != nil {
		return nil, fmt.Errorf("could not encrypt vault data: %w", err)
	}
	return json.Marshal(PassphraseEncryptedBlob{
		Salt: cipher.salt, EncryptionKey: wrappedKey, KeyNonce: keyNonce,
		EncryptedData: ciphertext, DataNonce: dataNonce,
	})
}

func OpenPassphraseCipher(data []byte, passphrase string) (*PassphraseCipher, []byte, error) {
	blob, err := parseEncryptedBlob(data)
	if err != nil {
		return nil, nil, err
	}
	cipher, err := NewPassphraseCipher(passphrase, blob.Salt)
	if err != nil {
		return nil, nil, err
	}
	dataKey, err := crypto.Decrypt(cipher.key, blob.EncryptionKey, blob.KeyNonce)
	if err != nil {
		return nil, nil, fmt.Errorf("could not unwrap vault data key: %w", err)
	}
	if len(dataKey) != 32 {
		return nil, nil, fmt.Errorf("invalid vault data key length")
	}
	plaintext, err := crypto.Decrypt(dataKey, blob.EncryptedData, blob.DataNonce)
	if err != nil {
		return nil, nil, fmt.Errorf("could not decrypt vault data: %w", err)
	}
	return cipher, plaintext, nil
}

func (cipher *PassphraseCipher) EncryptFIDOState(state FIDODeviceConfig) ([]byte, error) {
	data, err := json.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("could not encode device state: %w", err)
	}
	return cipher.Encrypt(data)
}

func OpenFIDOState(data []byte, passphrase string) (*PassphraseCipher, *FIDODeviceConfig, error) {
	cipher, plaintext, err := OpenPassphraseCipher(data, passphrase)
	if err != nil {
		return nil, nil, err
	}
	var state FIDODeviceConfig
	if err := json.Unmarshal(plaintext, &state); err != nil {
		return nil, nil, fmt.Errorf("could not decode device state: %w", err)
	}
	return cipher, &state, nil
}
