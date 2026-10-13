package fido_client

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"log"

	"github.com/bulwarkid/virtual-fido/cose"
	"github.com/bulwarkid/virtual-fido/crypto"
	"github.com/bulwarkid/virtual-fido/identities"
	"github.com/bulwarkid/virtual-fido/util"
	"github.com/bulwarkid/virtual-fido/webauthn"
)

type ClientAction uint8

type ClientActionRequestParams struct {
	RelyingParty string
	UserName     string
}

const (
	ClientActionU2FRegister        ClientAction = 0
	ClientActionU2FAuthenticate    ClientAction = 1
	ClientActionFIDOMakeCredential ClientAction = 2
	ClientActionFIDOGetAssertion   ClientAction = 3
)

var clientLogger *log.Logger = util.NewLogger("[CLIENT] ", util.LogLevelDebug)

type ClientRequestApprover interface {
	ApproveClientAction(action ClientAction, params ClientActionRequestParams) bool
}

type ClientDataSaver interface {
	SaveData(data []byte)
	RetrieveData() []byte
	Passphrase() string
}

type DefaultFIDOClient struct {
	deviceEncryptionKey   []byte
	certificateAuthority  *x509.Certificate
	certPrivateKey        *cose.SupportedCOSEPrivateKey
	authenticationCounter uint32

	pinEnabled      bool
	pinToken        []byte
	pinKeyAgreement *crypto.ECDHKey
	pinRetries      int32
	pinHash         []byte

	vault           *identities.IdentityVault
	vaultCipher     *identities.PassphraseCipher
	vaultPassphrase string
	requestApprover ClientRequestApprover
	dataSaver       ClientDataSaver
}

func NewDefaultClient(
	rootAttestationCertificate *x509.Certificate,
	rootAttestationCertPrivateKey *cose.SupportedCOSEPrivateKey,
	secretEncryptionKey [32]byte,
	enablePIN bool,
	requestApprover ClientRequestApprover,
	dataSaver ClientDataSaver) *DefaultFIDOClient {
	client := &DefaultFIDOClient{
		pinEnabled:            enablePIN,
		deviceEncryptionKey:   secretEncryptionKey[:],
		certificateAuthority:  rootAttestationCertificate,
		certPrivateKey:        rootAttestationCertPrivateKey,
		authenticationCounter: 1,
		pinToken:              crypto.RandomBytes(32),
		pinKeyAgreement:       crypto.GenerateECDHKey(),
		pinRetries:            8,
		pinHash:               nil,
		vault:                 identities.NewIdentityVault(),
		requestApprover:       requestApprover,
		dataSaver:             dataSaver,
	}
	client.loadData()
	return client
}

func (client *DefaultFIDOClient) SupportsResidentKey() bool {
	return true
}

func (client *DefaultFIDOClient) NewCredentialSource(
	PubKeyCredParams []webauthn.PublicKeyCredentialParams,
	ExcludeList []webauthn.PublicKeyCredentialDescriptor,
	relyingParty *webauthn.PublicKeyCredentialRPEntity,
	user *webauthn.PublicKeyCrendentialUserEntity) *identities.CredentialSource {
	supported := false
	for _, param := range PubKeyCredParams {
		if param.Algorithm == cose.COSE_ALGORITHM_ID_ES256 && param.Type == "public-key" {
			supported = true
			break
		}
	}
	if !supported || client.CredentialExcluded(relyingParty.ID, ExcludeList) {
		return nil
	}
	newSource := client.vault.NewIdentity(relyingParty, user)
	client.saveData()
	return newSource
}

func (client *DefaultFIDOClient) CredentialExcluded(relyingPartyID string, excludeList []webauthn.PublicKeyCredentialDescriptor) bool {
	return len(excludeList) > 0 && len(client.vault.GetMatchingCredentialSources(relyingPartyID, excludeList)) > 0
}

// Selection does not change counters or storage before the user approves.
func (client *DefaultFIDOClient) GetAssertionSources(relyingPartyID string, allowList []webauthn.PublicKeyCredentialDescriptor) []*identities.CredentialSource {
	return client.vault.GetMatchingCredentialSources(relyingPartyID, allowList)
}

func (client *DefaultFIDOClient) RecordAssertion(source *identities.CredentialSource) {
	source.SignatureCounter++
	client.saveData()
}

func (client *DefaultFIDOClient) GetAssertionSource(relyingPartyID string, allowList []webauthn.PublicKeyCredentialDescriptor) *identities.CredentialSource {
	sources := client.GetAssertionSources(relyingPartyID, allowList)
	if len(sources) == 0 {
		clientLogger.Printf("ERROR: No Credentials\n\n")
		return nil
	}

	// TODO: Allow user to choose credential source
	credentialSource := sources[0]
	client.RecordAssertion(credentialSource)
	return credentialSource
}

func (client DefaultFIDOClient) ApproveAccountCreation(relyingParty string) bool {
	params := ClientActionRequestParams{
		RelyingParty: relyingParty,
	}
	return client.requestApprover.ApproveClientAction(ClientActionFIDOMakeCredential, params)
}

func (client DefaultFIDOClient) ApproveAccountLogin(credentialSource *identities.CredentialSource) bool {
	params := ClientActionRequestParams{
		RelyingParty: credentialSource.RelyingParty.ID,
		UserName:     credentialSource.User.Name,
	}
	return client.requestApprover.ApproveClientAction(ClientActionFIDOGetAssertion, params)
}

// -----------------------
// PIN Management Methods
// -----------------------

func (client *DefaultFIDOClient) EnablePIN() {
	client.pinEnabled = true
	client.saveData()
}

func (client *DefaultFIDOClient) DisablePIN() {
	client.pinEnabled = false
	client.saveData()
}

func (client *DefaultFIDOClient) SupportsPIN() bool {
	return client.pinEnabled
}

func (client *DefaultFIDOClient) PINHash() []byte {
	return client.pinHash
}

func (client *DefaultFIDOClient) SetPIN(pin []byte) {
	pinHash := crypto.HashSHA256(pin)[:16]
	client.SetPINHash(pinHash)
}

func (client *DefaultFIDOClient) SetPINHash(newHash []byte) {
	util.Assert(len(newHash) == 16, "Invalid PIN hash")
	client.pinHash = append([]byte(nil), newHash...)
	// A changed PIN invalidates previously issued authorization tokens.
	client.pinToken = crypto.RandomBytes(32)
	client.saveData()
}

func (client *DefaultFIDOClient) PINRetries() int32 {
	util.Assert(client.pinRetries >= 0 && client.pinRetries <= 8, "Invalid PIN Retries")
	return client.pinRetries
}

func (client *DefaultFIDOClient) SetPINRetries(retries int32) {
	util.Assert(retries >= 0 && retries <= 8, "Invalid PIN Retries")
	client.pinRetries = retries
	// Persist before reporting failure, including the permanently blocked zero.
	client.saveData()
}

func (client *DefaultFIDOClient) ResetPINKeyAgreement() {
	client.pinKeyAgreement = crypto.GenerateECDHKey()
}

func (client *DefaultFIDOClient) PINKeyAgreement() *crypto.ECDHKey {
	return client.pinKeyAgreement
}

func (client *DefaultFIDOClient) PINToken() []byte {
	return client.pinToken
}

// -----------------------------
// U2F Methods
// -----------------------------

func (client DefaultFIDOClient) SealingEncryptionKey() []byte {
	return client.deviceEncryptionKey
}

func (client *DefaultFIDOClient) NewPrivateKey() *ecdsa.PrivateKey {
	return crypto.GenerateECDSAKey()
}

func (client *DefaultFIDOClient) NewAuthenticationCounterId() uint32 {
	num := client.authenticationCounter
	client.authenticationCounter++
	client.saveData()
	return num
}

func (client *DefaultFIDOClient) CreateAttestationCertificiate(privateKey *cose.SupportedCOSEPrivateKey) []byte {
	cert, err := identities.CreateSelfSignedAttestationCertificate(client.certificateAuthority, client.certPrivateKey, privateKey)
	util.CheckErr(err, "Could not create attestation certificate")
	return cert.Raw
}

func (client DefaultFIDOClient) ApproveU2FRegistration(keyHandle *webauthn.KeyHandle) bool {
	params := ClientActionRequestParams{}
	return client.requestApprover.ApproveClientAction(ClientActionU2FRegister, params)
}

func (client DefaultFIDOClient) ApproveU2FAuthentication(keyHandle *webauthn.KeyHandle) bool {
	params := ClientActionRequestParams{}
	return client.requestApprover.ApproveClientAction(ClientActionU2FAuthenticate, params)
}

func (client *DefaultFIDOClient) exportData(passphrase string) []byte {
	privKeyBytes := cose.MarshalCOSEPrivateKey(client.certPrivateKey)
	identityData := client.vault.Export()
	state := identities.FIDODeviceConfig{
		EncryptionKey:          client.deviceEncryptionKey,
		AttestationCertificate: client.certificateAuthority.Raw,
		AttestationPrivateKey:  privKeyBytes,
		AuthenticationCounter:  client.authenticationCounter,
		PINEnabled:             client.pinEnabled,
		PINHash:                client.pinHash,
		PINRetries:             &client.pinRetries,
		Sources:                identityData,
	}
	if client.vaultCipher == nil || client.vaultPassphrase != passphrase {
		var err error
		client.vaultCipher, err = identities.NewPassphraseCipher(passphrase, nil)
		util.CheckErr(err, "Could not unlock state encryption")
		client.vaultPassphrase = passphrase
	}
	savedBytes, err := client.vaultCipher.EncryptFIDOState(state)
	util.CheckErr(err, "Could not encode saved state")
	return savedBytes
}

func (client *DefaultFIDOClient) importData(data []byte, passphrase string) error {
	cipher, state, err := identities.OpenFIDOState(data, passphrase)
	if err != nil {
		return fmt.Errorf("could not decrypt vault data: %w", err)
	}
	if len(state.EncryptionKey) != 32 || (len(state.PINHash) != 0 && len(state.PINHash) != 16) {
		return fmt.Errorf("invalid saved device state")
	}
	retries := int32(8) // Backward-compatible migration of the original vault format.
	if state.PINRetries != nil {
		retries = *state.PINRetries
	}
	if retries < 0 || retries > 8 {
		return fmt.Errorf("invalid saved PIN retry count")
	}
	cert, err := x509.ParseCertificate(state.AttestationCertificate)
	util.CheckErr(err, "Could not parse x509 cert")
	privateKey, err := cose.UnmarshalCOSEPrivateKey(state.AttestationPrivateKey)
	if err != nil {
		privateKeyECDSA, err := x509.ParseECPrivateKey(state.AttestationPrivateKey)
		util.CheckErr(err, "Could not parse private key")
		privateKey = &cose.SupportedCOSEPrivateKey{ECDSA: privateKeyECDSA}
	}
	client.deviceEncryptionKey = state.EncryptionKey
	client.certificateAuthority = cert
	client.certPrivateKey = privateKey
	client.authenticationCounter = state.AuthenticationCounter
	client.pinEnabled = state.PINEnabled
	client.pinHash = state.PINHash
	client.pinRetries = retries
	client.vault = identities.NewIdentityVault()
	if err := client.vault.Import(state.Sources); err != nil {
		return err
	}
	client.vaultCipher = cipher
	client.vaultPassphrase = passphrase
	return nil
}

func (client *DefaultFIDOClient) saveData() {
	data := client.exportData(client.dataSaver.Passphrase())
	client.dataSaver.SaveData(data)
}

func (client *DefaultFIDOClient) loadData() {
	data := client.dataSaver.RetrieveData()
	if data != nil {
		util.CheckErr(client.importData(data, client.dataSaver.Passphrase()), "Could not restore vault; do not reset it")
	}
}

func (client *DefaultFIDOClient) Identities() []identities.CredentialSource {
	sources := make([]identities.CredentialSource, 0)
	for _, source := range client.vault.CredentialSources {
		sources = append(sources, *source)
	}
	return sources
}

func (client *DefaultFIDOClient) DeleteIdentity(id []byte) bool {
	success := client.vault.DeleteIdentity(id)
	if success {
		client.saveData()
	}
	return success
}
