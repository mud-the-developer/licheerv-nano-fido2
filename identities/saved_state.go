package identities

import (
	"encoding/json"
	"fmt"

	"github.com/bulwarkid/virtual-fido/webauthn"
)

type SavedCredentialSource struct {
	Type             string                                  `json:"type"`
	ID               []byte                                  `json:"id"`
	PrivateKey       []byte                                  `json:"private_key"`
	RelyingParty     webauthn.PublicKeyCredentialRPEntity    `json:"relying_party"`
	User             webauthn.PublicKeyCrendentialUserEntity `json:"user"`
	SignatureCounter int32                                   `json:"signature_counter"`
}

type FIDODeviceConfig struct {
	EncryptionKey          []byte `json:"encryption_key"`
	AttestationCertificate []byte `json:"attestation_certificate"`
	AttestationPrivateKey  []byte `json:"attestation_private_key"`
	AuthenticationCounter  uint32 `json:"authentication_counter"`
	PINEnabled             bool   `json:"pin_enabled,omitempty"`
	PINHash                []byte `json:"pin_hash,omitempty"`
	// A pointer distinguishes a legacy vault from a persisted zero (blocked).
	PINRetries *int32                  `json:"pin_retries,omitempty"`
	Sources    []SavedCredentialSource `json:"sources"`
}

type PassphraseEncryptedBlob struct {
	Salt          []byte `json:"salt"`
	EncryptionKey []byte `json:"encryption_key"`
	KeyNonce      []byte `json:"key_nonce"`
	EncryptedData []byte `json:"encrypted_data"`
	DataNonce     []byte `json:"data_nonce"`
}

func EncryptWithPassphrase(passphrase string, data []byte) ([]byte, error) {
	cipher, err := NewPassphraseCipher(passphrase, nil)
	if err != nil {
		return nil, err
	}
	return cipher.Encrypt(data)
}

func DecryptWithPassphrase(passphrase string, data []byte) ([]byte, error) {
	_, plaintext, err := OpenPassphraseCipher(data, passphrase)
	return plaintext, err
}

func EncryptFIDOState(savedState FIDODeviceConfig, passphrase string) ([]byte, error) {
	stateBytes, err := json.Marshal(savedState)
	if err != nil {
		return nil, fmt.Errorf("Could not encode JSON: %w", err)
	}
	blob, err := EncryptWithPassphrase(passphrase, stateBytes)
	if err != nil {
		return nil, fmt.Errorf("Could not encrypt data: %w", err)
	}
	return blob, nil
}

func DecryptFIDOState(data []byte, passphrase string) (*FIDODeviceConfig, error) {
	stateBytes, err := DecryptWithPassphrase(passphrase, data)
	if err != nil {
		return nil, fmt.Errorf("Could not decrypt data: %w", err)
	}
	state := FIDODeviceConfig{}
	err = json.Unmarshal(stateBytes, &state)
	if err != nil {
		return nil, fmt.Errorf("Could not decode JSON: %w", err)
	}
	return &state, nil
}
