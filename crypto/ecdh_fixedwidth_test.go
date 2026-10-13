package crypto

import (
	"bytes"
	"crypto/ecdh"
	"encoding/binary"
	"math/big"
	"testing"
)

func TestPINECDHPreservesLeadingZeroes(t *testing.T) {
	remoteScalar := make([]byte, 32)
	remoteScalar[31] = 1
	remote, err := ecdh.P256().NewPrivateKey(remoteScalar)
	if err != nil {
		t.Fatal(err)
	}
	public := remote.PublicKey().Bytes()
	for i := uint32(1); i < 10000; i++ {
		scalar := make([]byte, 32)
		binary.BigEndian.PutUint32(scalar[28:], i)
		local, err := ecdh.P256().NewPrivateKey(scalar)
		if err != nil {
			t.Fatal(err)
		}
		expected, err := local.ECDH(remote.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		if expected[0] != 0 {
			continue
		}
		key := &ECDHKey{Priv: scalar}
		actual := key.ECDH(new(big.Int).SetBytes(public[1:33]), new(big.Int).SetBytes(public[33:65]))
		if len(actual) != 32 || !bytes.Equal(actual, expected) {
			t.Fatal("ECDH dropped a leading zero byte")
		}
		return
	}
	t.Fatal("deterministic leading-zero fixture not found")
}
