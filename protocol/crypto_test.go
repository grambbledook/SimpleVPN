package protocol

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func Test_ECDH(t *testing.T) {
	aliceSK := NewPrivateKey()
	bobsSK := NewPrivateKey()

	t.Log("A's PK", aliceSK)
	t.Log("B's PK", bobsSK)

	alicePK := aliceSK.PublicKey()
	bobsPK := bobsSK.PublicKey()

	t.Log("A's PK", alicePK)
	t.Log("B's PK", bobsPK)

	aliceSS, _ := aliceSK.SharedSecret(bobsPK)
	bobsSS, _ := bobsSK.SharedSecret(alicePK)

	t.Log("A's SS", aliceSS)
	t.Log("B's SS", bobsSS)

	if !bytes.Equal(aliceSS[:], bobsSS[:]) {
		t.Fatal("Shared secrets do not match")
	}
}

func Test_PrivateKey_ParsingAndDerivation(t *testing.T) {
	originalSK := "WEGlnZqW7a3J+AmKoDg+/L95sSIutu9ApEp3AY+l30o="
	originalPK := "pMo33VR8Lwi0nmi3sAFTFttomPI71LSMkEjFXws94wU="

	sk := PrivateKey{}
	err := sk.FromBase64(originalSK)
	if err != nil {
		t.Fatal("Failed to parse private key from base64 string", err)
	}

	pk := PublicKey{}
	err = pk.FromBase64(originalPK)
	if err != nil {
		t.Fatal("Failed to parse public key from base64 string", err)
	}

	derivedPK := sk.PublicKey()
	derivedEncodedPK := base64.StdEncoding.EncodeToString(derivedPK[:])

	if !bytes.Equal(pk[:], derivedPK[:]) {
		t.Fatal("Parsed public key does not match the derived one")
	}

	if derivedEncodedPK != originalPK {
		t.Fatal("Public key does not match original")
	}
}
