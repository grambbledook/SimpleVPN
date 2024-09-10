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
	ReservedSpace [ReservedSpaceSize]byte
	PublicKey     [PublicKeySize]byte
	SharedSecret  [SharedSecretSize]byte
	PrivateKey    [PrivateKeySize]byte
	CookieNonce   [CookieNonceSize]byte
)

const (
	HandshakeInitSize     = 148
	HandshakeResponseSize = 92
	HandshakeCookieSize   = 64 // size of cookie reply message
	TransportHeaderSize   = 16
)

const (
	HandshakeInitType     = 0x01
	HandshakeResponseType = 0x02
	HandshakeCookieType   = 0x03
	TransportType         = 0x04
)

type MessageHandshakeInit struct {
	Type      byte
	Reserved  ReservedSpace
	Sender    uint32
	Ephemeral PublicKey
	Static    [PublicKeySize + poly1305.TagSize]byte
	Timestamp [Tai64nTimestampSIze + poly1305.TagSize]byte
	MAC1      [blake2s.Size128]byte
	MAC2      [blake2s.Size128]byte
}

type MessageHandshakeResponse struct {
	Type      byte
	Reserved  ReservedSpace
	Sender    uint32
	Receiver  uint32
	Ephemeral PublicKey
	Empty     [poly1305.TagSize]byte
	MAC1      [blake2s.Size128]byte
	MAC2      [blake2s.Size128]byte
}

type MessageHandshakeCookie struct {
	Type     byte
	Reserved ReservedSpace
	Nonce    CookieNonce
	Cookie   [CookieSize + poly1305.TagSize]byte
}

type MessageTransport struct {
	Type     byte
	Reserved ReservedSpace
	Counter  uint64
	Packet   []byte
}

func (m *MessageHandshakeInit) MessageType() byte {
	return m.Type
}

func (m *MessageHandshakeResponse) MessageType() byte {
	return m.Type
}

func (m *MessageHandshakeCookie) MessageType() byte {
	return m.Type
}

func (m *MessageTransport) MessageType() byte {
	return m.Type
}
