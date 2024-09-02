package protocol

import (
	"golang.org/x/crypto/chacha20poly1305"
	"time"
)

const (
	CONSTRUCTION = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	IDENTIFIER   = "WireGuard v1 zx2c4 Jason@zx2c4.com"
)

var (
	// InitialKeyChain - Initial keychain
	InitialKeyChain = HASH([]byte(CONSTRUCTION))

	// InitialHash - Initial hash
	InitialHash = HASH(InitialKeyChain[:], []byte(IDENTIFIER))

	// ZeroNonce Empty nonce
	ZeroNonce [chacha20poly1305.NonceSize]byte
)

func (r *Peer) InitiateHandshake(i *Peer) (InitiateHandshakeMessage, error) {
	handshake := Handshake{
		Chain: InitialKeyChain,
		Hash:  InitialHash,
	}

	handshake.Hash = HASH(InitialHash[:], r.PublicKey[:])
	handshake.Epriv, handshake.Epub = DHGenerate()

	KDF1(&handshake.Chain, handshake.Chain[:], handshake.Epub[:])
	handshake.Hash = HASH(handshake.Chain[:], handshake.Epub[:])

	message := InitiateHandshakeMessage{
		Type:      InitiateHandshakeMessageType,
		Ephemeral: handshake.Epub,
	}

	ss, err := handshake.Epriv.SharedSecret(r.PublicKey)
	if err != nil {
		return InitiateHandshakeMessage{}, err
	}

	key := [chacha20poly1305.KeySize]byte{}
	KDF2(&handshake.Chain, &key, handshake.Chain[:], ss[:])

	aead, _ := chacha20poly1305.New(key[:])
	aead.Seal(message.Static[:0], ZeroNonce[:], i.PublicKey[:], handshake.Hash[:])

	handshake.Hash = HASH(handshake.Hash[:], message.Static[:])

	ss, err = i.PrivateKey.SharedSecret(r.PublicKey)
	if err != nil {
		return InitiateHandshakeMessage{}, err
	}

	KDF2(&handshake.Chain, &key, handshake.Chain[:], ss[:])

	now := Now(time.Now())
	aead, _ = chacha20poly1305.New(key[:])
	aead.Seal(message.Timestamp[:0], ZeroNonce[:], now[:], handshake.Hash[:])
	return message, nil
}
