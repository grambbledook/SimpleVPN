package protocol

import (
	"bytes"
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
