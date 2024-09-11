package protocol

import (
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/poly1305"
	"math"
	"reflect"
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

	runTest(t, &original, &deserialised)
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

	runTest(t, &original, &deserialised)
}

func Test_MessageSerde_HandshakeCookie(t *testing.T) {
	original := MessageHandshakeCookie{
		Type:   HandshakeCookieType,
		Nonce:  CookieNonce{1, 2, 3, 4},
		Cookie: [CookieSize + poly1305.TagSize]byte{5, 6, 7, 8},
	}
	deserialised := MessageHandshakeCookie{}

	runTest(t, &original, &deserialised)
}

func Test_MessageSerde_MessageTransport(t *testing.T) {
	original := MessageTransport{
		Type:     TransportType,
		Receiver: math.MaxUint32,
		Counter:  math.MaxUint64,
		Packet:   []byte{1, 2, 3, 4},
	}
	deserialised := MessageTransport{}

	runTest(t, &original, &deserialised)
}

func runTest(t *testing.T, original Message, deserialised Message) {
	serialised := original.ToBytes()

	if err := deserialised.FromBytes(serialised); err != nil {
		t.Fatal("Failed to deserialise message form a byte array", err)
	}

	if !reflect.DeepEqual(original, deserialised) {
		t.Fatal("Deserialised object does not match original")
	}
}
