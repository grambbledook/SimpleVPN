package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
)

func (sk *PrivateKey) FromBase64(str string) error {
	if err := decodeFromBase64(sk[:], str); err != nil {
		return err
	}
	sk.clamp()
	return nil
}

func (sk *PublicKey) FromBase64(str string) error {
	return decodeFromBase64(sk[:], str)
}

func decodeFromBase64(dst []byte, str string) error {
	key, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return err
	}
	copy(dst[:], key)

	return nil
}

type Message interface {
	ToBytes() []byte
	FromBytes([]byte) error
}

func (m *MessageHandshakeInit) ToBytes() []byte {
	var buffer [MessageHandshakeInitSize]byte

	writer := bytes.NewBuffer(buffer[:0])
	err := binary.Write(writer, binary.LittleEndian, m)
	if err != nil {
		return nil
	}

	return writer.Bytes()
}
func (m *MessageHandshakeResponse) ToBytes() []byte {
	var buffer [MessageHandshakeCookieSize]byte

	writer := bytes.NewBuffer(buffer[:0])
	binary.Write(writer, binary.LittleEndian, m)

	return writer.Bytes()
}
func (m *MessageHandshakeCookie) ToBytes() []byte {
	var buffer [MessageHandshakeCookieSize]byte

	writer := bytes.NewBuffer(buffer[:0])
	binary.Write(writer, binary.LittleEndian, m)

	return writer.Bytes()
}
func (m *MessageTransport) ToBytes() []byte {
	buffer := make([]byte, MessageTransportHeaderSize+len(m.Packet))

	binary.LittleEndian.PutUint32(buffer[0:], m.Type)

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

	if len(data) < MessageHandshakeInitSize {
		return errors.New("not enough data to read handshake init message")
	}

	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, m); err != nil {
		return err
	}
	return nil
}
func (m *MessageHandshakeResponse) FromBytes(data []byte) error {
	if data[0] != HandshakeResponseType {
		return errors.New("invalid message type")
	}

	if len(data) != MessageHandshakeResponseSize {
		return errors.New("not enough data to read handshake response message")
	}

	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, m); err != nil {
		return err
	}
	return nil
}
func (m *MessageHandshakeCookie) FromBytes(data []byte) error {
	if data[0] != HandshakeCookieType {
		return errors.New("invalid message type")
	}

	if len(data) != MessageHandshakeCookieSize {
		return errors.New("not enough data to read handshake cookie message")
	}

	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, m); err != nil {
		return err
	}
	return nil
}
func (m *MessageTransport) FromBytes(data []byte) error {
	if data[0] != TransportType {
		return errors.New("invalid message type")
	}

	if len(data) < MessageTransportHeaderSize {
		return errors.New("not enough data to read transport message")
	}

	l, r := 0, UIntSize
	m.Type = binary.LittleEndian.Uint32(data[l:r])

	l, r = r, r+UIntSize
	m.Receiver = binary.LittleEndian.Uint32(data[l:r])

	l, r = r, r+ULongSize
	m.Counter = binary.LittleEndian.Uint64(data[l:r])

	l, r = r, len(data)
	m.Packet = data[l:]

	return nil
}
