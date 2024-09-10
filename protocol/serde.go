package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/poly1305"
)

type Message interface {
	ToBytes() []byte
	FromBytes([]byte) error
}

func (m *MessageHandshakeInit) ToBytes() []byte {
	var buffer [HandshakeInitSize]byte

	writer := bytes.NewBuffer(buffer[:])
	binary.Write(writer, binary.LittleEndian, m)

	return writer.Bytes()
}
func (m *MessageHandshakeResponse) ToBytes() []byte {
	var buffer [HandshakeCookieSize]byte

	writer := bytes.NewBuffer(buffer[:])
	binary.Write(writer, binary.LittleEndian, m)

	return writer.Bytes()
}
func (m *MessageHandshakeCookie) ToBytes() []byte {
	var buffer [HandshakeCookieSize]byte

	writer := bytes.NewBuffer(buffer[:])
	binary.Write(writer, binary.LittleEndian, m)

	return writer.Bytes()
}
func (m *MessageTransport) ToBytes() []byte {
	buffer := make([]byte, TransportHeaderSize+len(m.Packet))

	writer := bytes.NewBuffer(buffer)
	binary.Write(writer, binary.LittleEndian, m)

	return writer.Bytes()
}

func (m *MessageHandshakeInit) FromBytes(data []byte) error {
	if data[0] != HandshakeInitType {
		return errors.New("invalid message type")
	}

	if len(data) < HandshakeInitSize {
		return errors.New("not enough data to read handshake init message")
	}

	m.Type = data[0]

	l, r := UIntSize, 2*UIntSize
	m.Sender = binary.LittleEndian.Uint32(data[l:r])

	l, r = r, r+PublicKeySize
	m.Ephemeral = PublicKey(data[l:r])

	l, r = r, r+PublicKeySize+poly1305.TagSize
	m.Static = [PublicKeySize + poly1305.TagSize]byte(data[l:r])

	l, r = r, r+Tai64nTimestampSIze+poly1305.TagSize
	m.Timestamp = [Tai64nTimestampSIze + poly1305.TagSize]byte(data[l:r])

	l, r = r, r+blake2s.Size128
	m.MAC1 = [blake2s.Size128]byte(data[l:r])

	l, r = r, r+blake2s.Size128
	m.MAC2 = [blake2s.Size128]byte(data[l:r])

	return nil
}
func (m *MessageHandshakeResponse) FromBytes(data []byte) error {
	if data[0] != HandshakeResponseType {
		return errors.New("invalid message type")
	}

	if len(data) != HandshakeResponseSize {
		return errors.New("not enough data to read handshake response message")
	}

	m.Type = data[0]

	l, r := UIntSize, 2*UIntSize
	m.Sender = binary.LittleEndian.Uint32(data[l:r])

	l, r = r, r+PublicKeySize
	m.Ephemeral = PublicKey(data[l:r])

	l, r = r, r+poly1305.TagSize
	m.Empty = [poly1305.TagSize]byte(data[l:r])

	l, r = r, r+blake2s.Size128
	m.MAC1 = [blake2s.Size128]byte(data[l:r])

	l, r = r, r+blake2s.Size128
	m.MAC2 = [blake2s.Size128]byte(data[l:r])

	return nil
}
func (m *MessageHandshakeCookie) FromBytes(data []byte) error {
	if data[0] != HandshakeCookieType {
		return errors.New("invalid message type")
	}

	if len(data) != HandshakeCookieSize {
		return errors.New("not enough data to read handshake cookie message")
	}

	m.Type = data[0]

	l, r := UIntSize, UIntSize+CookieNonceSize
	m.Nonce = CookieNonce(data[l:r])

	l, r = r, r+CookieSize+poly1305.TagSize
	m.Cookie = [CookieSize + poly1305.TagSize]byte(data[l:r])

	return nil
}
func (m *MessageTransport) FromBytes(data []byte) error {
	if data[0] != TransportType {
		return errors.New("invalid message type")
	}

	if len(data) <= HandshakeCookieSize {
		return errors.New("not enough data to read transport message")
	}

	m.Type = data[0]

	l, r := UIntSize, UIntSize+ULongSize
	m.Counter = binary.LittleEndian.Uint64(data[l:r])

	l, r = r, r+CookieSize+poly1305.TagSize
	m.Packet = data[l:r]

	return nil
}
