package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/poly1305"
)

const (
	UIntSize = 4

	ReservedSpaceSize   = 3
	PublicKeySize       = 32
	PrivateKeySize      = 32
	SharedSecretSize    = 32
	Tai64nTimestampSIze = 12
)

type (
	ReservedSpace [ReservedSpaceSize]byte
	PublicKey     [PublicKeySize]byte
	SharedSecret  [SharedSecretSize]byte
	PrivateKey    [PrivateKeySize]byte
)

const (
	InitiateHandshakeMessageSize         = 148
	InitiateHandshakeResponseMessageSize = 92
)

const (
	InitiateHandshakeMessageType         = 0x01
	InitiateHandshakeResponseMessageType = 0x02
)

type InitiateHandshakeMessage struct {
	Type      byte
	Reserved  ReservedSpace
	Sender    uint32
	Ephemeral PublicKey
	Static    [PublicKeySize + poly1305.TagSize]byte
	Timestamp [Tai64nTimestampSIze + poly1305.TagSize]byte
	MAC1      [blake2s.Size128]byte
	MAC2      [blake2s.Size128]byte
}

type InitiateHandshakeResponseMessage struct {
	Type      byte
	Reserved  ReservedSpace
	Sender    uint32
	Receiver  uint32
	Ephemeral PublicKey
	Empty     [poly1305.TagSize]byte
	MAC1      [blake2s.Size128]byte
	MAC2      [blake2s.Size128]byte
}

func (m *InitiateHandshakeMessage) ToBytes() []byte {
	var buffer [InitiateHandshakeMessageSize]byte

	writer := bytes.NewBuffer(buffer[:])
	binary.Write(writer, binary.LittleEndian, m)

	return writer.Bytes()
}

func (m *InitiateHandshakeResponseMessage) ToBytes() []byte {
	var buffer [InitiateHandshakeResponseMessageSize]byte

	writer := bytes.NewBuffer(buffer[:])
	binary.Write(writer, binary.LittleEndian, m)

	return writer.Bytes()
}

func FromBytes(data []byte) (InitiateHandshakeMessage, error) {
	if len(data) < InitiateHandshakeMessageSize {
		return InitiateHandshakeMessage{}, errors.New("not enough data to read InitiateHandshakeMessage")
	}

	typ := data[0]
	l, r := UIntSize, 2*UIntSize
	sender := binary.LittleEndian.Uint32(data[l:r])

	l, r = r, r+PrivateKeySize
	ephimeral := PublicKey(data[l:r])

	l, r = r, r+PublicKeySize+poly1305.TagSize
	static := [PublicKeySize + poly1305.TagSize]byte(data[l:r])

	l, r = r, r+Tai64nTimestampSIze+poly1305.TagSize
	timestamp := [Tai64nTimestampSIze + poly1305.TagSize]byte(data[l:r])

	l, r = r, r+blake2s.Size128
	mac1 := [blake2s.Size128]byte(data[l:r])

	l, r = r, r+blake2s.Size128
	mac2 := [blake2s.Size128]byte(data[l:r])

	return InitiateHandshakeMessage{
		Type:      typ,
		Sender:    sender,
		Ephemeral: ephimeral,
		Static:    static,
		Timestamp: timestamp,
		MAC1:      mac1,
		MAC2:      mac2,
	}, nil
}
