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

	writer := bytes.NewBuffer(buffer[:0])
	err := binary.Write(writer, binary.LittleEndian, m)
	if err != nil {
		return nil
	}

	return writer.Bytes()
}
func (m *MessageHandshakeResponse) ToBytes() []byte {
	var buffer [HandshakeCookieSize]byte

	writer := bytes.NewBuffer(buffer[:0])
	binary.Write(writer, binary.LittleEndian, m)

	return writer.Bytes()
}
func (m *MessageHandshakeCookie) ToBytes() []byte {
	var buffer [HandshakeCookieSize]byte

	writer := bytes.NewBuffer(buffer[:0])
	binary.Write(writer, binary.LittleEndian, m)

	return writer.Bytes()
}
func (m *MessageTransport) ToBytes() []byte {
	buffer := make([]byte, TransportHeaderSize+len(m.Packet))

	buffer[0] = m.Type

	// skipping 3 bytes of reserved space
	l, r := UIntSize, 2*UIntSize
	binary.LittleEndian.PutUint32(buffer[l:r], m.Receiver)
	l, r = r, r+ULongSize
	binary.LittleEndian.PutUint64(buffer[l:r], m.Counter)

	copy(buffer[r:], m.Packet)
	return buffer
}

func (m *MessageHandshakeInit) FromBytes(data []byte) error {
	if data[0] != HandshakeInitType {
		return errors.New("invalid message type")
	}

	if len(data) < HandshakeInitSize {
		return errors.New("not enough data to read handshake init message")
	}

	m.Type = data[0]

	// skipping 3 bytes of reserved space
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

	// skipping 3 bytes of reserved space
	l, r := UIntSize, 2*UIntSize
	m.Sender = binary.LittleEndian.Uint32(data[l:r])

	l, r = r, r+UIntSize
	m.Receiver = binary.LittleEndian.Uint32(data[l:r])

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

	// skipping 3 bytes of reserved space
	l, r := UIntSize, 2*UIntSize
	m.Receiver = binary.LittleEndian.Uint32(data[l:r])

	l, r = r, r+CookieNonceSize
	m.Nonce = CookieNonce(data[l:r])

	l, r = r, r+CookieSize+poly1305.TagSize
	m.Cookie = [CookieSize + poly1305.TagSize]byte(data[l:r])

	return nil
}
func (m *MessageTransport) FromBytes(data []byte) error {
	if data[0] != TransportType {
		return errors.New("invalid message type")
	}

	if len(data) < TransportHeaderSize {
		return errors.New("not enough data to read transport message")
	}

	m.Type = data[0]

	// skipping 3 bytes of reserved space
	l, r := UIntSize, 2*UIntSize
	m.Receiver = binary.LittleEndian.Uint32(data[l:r])

	l, r = r, r+ULongSize
	m.Counter = binary.LittleEndian.Uint64(data[l:r])

	l, r = r, len(data)
	m.Packet = data[l:]

	return nil
}
