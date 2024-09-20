package protocol

import (
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/poly1305"
	"math"
	"testing"
)

func Test_MessageSerde_MessageHandshakeInit(t *testing.T) {
	original := MessageHandshakeInit{
		Type:      HandshakeInitType,
		Sender:    math.MaxUint32,
		Ephemeral: PublicKey{1, 2, 3, 4},
		Static:    [PublicKeySize + poly1305.TagSize]byte{5, 6, 7, 8},
		Timestamp: [Tai64nTimestampSIze + poly1305.TagSize]byte{9, 10, 11, 12},
		MAC1:      [blake2s.Size128]byte{13, 14, 15, 16},
		MAC2:      [blake2s.Size128]byte{17, 18, 19, 20},
	}
	deserialised := MessageHandshakeInit{}

	runMessageSerdeTest(t, &original, &deserialised)
}

func Test_MessageSerde_MessageHandshakeResponse(t *testing.T) {
	original := MessageHandshakeResponse{
		Type:      HandshakeResponseType,
		Sender:    math.MaxUint32 / 2,
		Receiver:  math.MaxUint32 / 4,
		Ephemeral: PublicKey{1, 2, 3, 4},
		Empty:     [poly1305.TagSize]byte{5, 6, 7, 8},
		MAC1:      [blake2s.Size128]byte{9, 10, 11, 12},
		MAC2:      [blake2s.Size128]byte{13, 14, 15, 16},
	}
	deserialised := MessageHandshakeResponse{}

	runMessageSerdeTest(t, &original, &deserialised)
}

func Test_MessageSerde_HandshakeCookie(t *testing.T) {
	original := MessageHandshakeCookie{
		Type:   HandshakeCookieType,
		Nonce:  CookieNonce{1, 2, 3, 4},
		Cookie: [CookieSize + poly1305.TagSize]byte{5, 6, 7, 8},
	}
	deserialised := MessageHandshakeCookie{}

	runMessageSerdeTest(t, &original, &deserialised)
}

func Test_MessageSerde_MessageTransport(t *testing.T) {
	original := MessageTransport{
		Type:     TransportType,
		Receiver: math.MaxUint32,
		Counter:  math.MaxUint64,
		Packet:   []byte{1, 2, 3, 4},
	}
	deserialised := MessageTransport{}

	runMessageSerdeTest(t, &original, &deserialised)
}

func runMessageSerdeTest(t *testing.T, original Message, deserialised Message) {
	serialised := original.ToBytes()

	err := deserialised.FromBytes(serialised)

	assert.Nil(t, err)
	assert.Equal(t, original, deserialised)
}

func Test_PrivateKey_ParsingAndDerivation(t *testing.T) {
	originalSK := "WEGlnZqW7a3J+AmKoDg+/L95sSIutu9ApEp3AY+l30o="
	originalPK := "pMo33VR8Lwi0nmi3sAFTFttomPI71LSMkEjFXws94wU="

	sk := PrivateKey{}
	err := sk.FromBase64(originalSK)
	assert.Nil(t, err)

	pk := PublicKey{}
	err = pk.FromBase64(originalPK)
	assert.Nil(t, err)

	derivedPK := sk.PublicKey()
	derivedEncodedPK := base64.StdEncoding.EncodeToString(derivedPK[:])

	assert.Equal(t, pk, derivedPK)
	assert.Equal(t, derivedEncodedPK, originalPK)
}
