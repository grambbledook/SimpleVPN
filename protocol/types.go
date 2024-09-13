package protocol

import (
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/poly1305"
)

const (
	UIntSize  = 4
	ULongSize = 8

	ReservedSpaceSize   = 3
	PublicKeySize       = 32
	PrivateKeySize      = 32
	SharedSecretSize    = 32
	Tai64nTimestampSIze = 12
	CookieNonceSize     = 24
	CookieSize          = 16
)

type (
	PublicKey    [PublicKeySize]byte
	SharedSecret [SharedSecretSize]byte
	PrivateKey   [PrivateKeySize]byte
	CookieNonce  [CookieNonceSize]byte
)

const (
	HandshakeInitSize     = 148
	HandshakeResponseSize = 92
	HandshakeCookieSize   = 64 // size of cookie reply message
	TransportHeaderSize   = 16
)

const (
	HandshakeInitType     = 1
	HandshakeResponseType = 2
	HandshakeCookieType   = 3
	TransportType         = 4
)

type MessageHandshakeInit struct {
	Type      uint32
	Sender    uint32
	Ephemeral PublicKey
	Static    [PublicKeySize + poly1305.TagSize]byte
	Timestamp [Tai64nTimestampSIze + poly1305.TagSize]byte
	MAC1      [blake2s.Size128]byte
	MAC2      [blake2s.Size128]byte
}

type MessageHandshakeResponse struct {
	Type      uint32
	Sender    uint32
	Receiver  uint32
	Ephemeral PublicKey
	Empty     [poly1305.TagSize]byte
	MAC1      [blake2s.Size128]byte
	MAC2      [blake2s.Size128]byte
}

type MessageHandshakeCookie struct {
	Type     uint32
	Receiver uint32
	Nonce    CookieNonce
	Cookie   [CookieSize + poly1305.TagSize]byte
}

type MessageTransport struct {
	Type     uint32
	Receiver uint32
	Counter  uint64
	Packet   []byte
}
