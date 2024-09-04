package protocol

import (
	"errors"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"time"
)

const (
	CONSTRUCTION = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	IDENTIFIER   = "WireGuard v1 zx2c4 Jason@zx2c4.com"
)

var (
	// InitialKeyChain - Initial keychain
	InitialKeyChain [blake2s.Size]byte

	// InitialHash - Initial hash
	InitialHash [blake2s.Size]byte

	// ZeroNonce Empty nonce
	ZeroNonce [chacha20poly1305.NonceSize]byte

	// PreSharedKey - Pre-shared key
	PreSharedKey = [SharedSecretSize]byte{}
)

func init() {
	HASH(&InitialKeyChain, []byte(CONSTRUCTION))
	HASH(&InitialHash, InitialKeyChain[:], []byte(IDENTIFIER))
}

func (t *Tunnel) initialise() {
	t.Handshake.Chain = InitialKeyChain
	t.Handshake.Hash = InitialHash

	t.Handshake.PrecomputedStaticStatic, _ = t.Local.PrivateKey.SharedSecret(t.Remote.PublicKey)
}

func (t *Tunnel) InitiateHandshake() (InitiateHandshakeMessage, error) {
	local, remote := t.Local, t.Remote
	HASH(&t.Handshake.Hash, InitialHash[:], remote.PublicKey[:])

	t.Handshake.LocalEphemeralSecret, t.Handshake.LocalEphemeralPublic = DHGenerate()
	KDF1(&t.Handshake.Chain, t.Handshake.Chain[:], t.Handshake.LocalEphemeralPublic[:])
	HASH(&t.Handshake.Hash, t.Handshake.Chain[:], t.Handshake.LocalEphemeralPublic[:])

	message := InitiateHandshakeMessage{
		Type:      InitiateHandshakeMessageType,
		Ephemeral: t.Handshake.LocalEphemeralPublic,
	}

	ss, err := t.Handshake.LocalEphemeralSecret.SharedSecret(remote.PublicKey)
	if err != nil {
		return InitiateHandshakeMessage{}, err
	}

	key := [chacha20poly1305.KeySize]byte{}
	KDF2(&t.Handshake.Chain, &key, t.Handshake.Chain[:], ss[:])

	aead, _ := chacha20poly1305.New(key[:])
	aead.Seal(message.Static[:0], ZeroNonce[:], local.PublicKey[:], t.Handshake.Hash[:])

	HASH(&t.Handshake.Hash, t.Handshake.Hash[:], message.Static[:])

	ss, err = local.PrivateKey.SharedSecret(remote.PublicKey)
	if err != nil {
		return InitiateHandshakeMessage{}, err
	}

	KDF2(&t.Handshake.Chain, &key, t.Handshake.Chain[:], ss[:])

	now := Now(time.Now())
	aead, _ = chacha20poly1305.New(key[:])
	aead.Seal(message.Timestamp[:0], ZeroNonce[:], now[:], t.Handshake.Hash[:])
	return message, nil
}

func (t *Tunnel) ProcessInitiateHandshakeMessage(message InitiateHandshakeMessage) error {
	t.Handshake.InitiatorIndex = message.Sender
	t.Handshake.RemoteEphemeralPublic = message.Ephemeral

	hash := [blake2s.Size]byte{}
	chainKey := [chacha20poly1305.KeySize]byte{}

	HASH(&hash, InitialHash[:], t.Remote.PublicKey[:])
	KDF1(&chainKey, InitialKeyChain[:], t.Handshake.RemoteEphemeralPublic[:])

	HASH(&hash, chainKey[:], t.Handshake.RemoteEphemeralPublic[:])

	ss, err := t.Remote.PrivateKey.SharedSecret(t.Handshake.RemoteEphemeralPublic)
	if err != nil {
		return err
	}

	key := [chacha20poly1305.KeySize]byte{}
	KDF2(&chainKey, &key, chainKey[:], ss[:])

	pk := PublicKey{}
	aead, _ := chacha20poly1305.New(key[:])
	_, err = aead.Open(pk[:], ZeroNonce[:], message.Static[:], hash[:])
	if err != nil {
		return errors.New("failed to decrypt the static key")
	}

	HASH(&hash, hash[:], message.Static[:])

	ss, err = t.Local.PrivateKey.SharedSecret(t.Remote.PublicKey)
	if err != nil {
		return err
	}
	KDF2(&chainKey, &key, chainKey[:], ss[:])

	ts := Tai64n{}
	aead, _ = chacha20poly1305.New(key[:])
	_, err = aead.Open(ts[:], ZeroNonce[:], message.Timestamp[:], hash[:])
	if err != nil {
		return errors.New("failed to decrypt the timestamp")
	}

	if ts.After(t.Handshake.LastTimestamp) {
		return errors.New("timestamp is invalid")
	}

	t.Handshake.LastTimestamp = ts
	return nil
}

func (t *Tunnel) CreateInitiateHandshakeResponse() (InitiateHandshakeResponseMessage, error) {
	remote := t.Remote

	t.Handshake.LocalEphemeralSecret, t.Handshake.LocalEphemeralPublic = DHGenerate()
	KDF1(&t.Handshake.Chain, t.Handshake.Chain[:], t.Handshake.RemoteEphemeralPublic[:])
	HASH(&t.Handshake.Hash, t.Handshake.Hash[:], t.Handshake.RemoteEphemeralPublic[:])
	message := InitiateHandshakeResponseMessage{
		Ephemeral: t.Handshake.LocalEphemeralPublic,
	}

	ss, err := t.Handshake.LocalEphemeralSecret.SharedSecret(t.Handshake.RemoteEphemeralPublic)
	if err != nil {
		return InitiateHandshakeResponseMessage{}, err
	}
	KDF1(&t.Handshake.Chain, t.Handshake.Chain[:], ss[:])

	ss, err = t.Handshake.LocalEphemeralSecret.SharedSecret(remote.PublicKey)
	if err != nil {
		return InitiateHandshakeResponseMessage{}, err
	}
	KDF1(&t.Handshake.Chain, t.Handshake.Chain[:], ss[:])

	tau := [blake2s.Size]byte{}
	key := [chacha20poly1305.KeySize]byte{}
	KDF3(&t.Handshake.Chain, &tau, &key, t.Handshake.Chain[:], PreSharedKey[:])

	HASH(&t.Handshake.Hash, t.Handshake.Hash[:], tau[:])
	aead, _ := chacha20poly1305.New(key[:])
	aead.Seal(message.Empty[:0], ZeroNonce[:], nil, t.Handshake.Hash[:])

	HASH(&t.Handshake.Hash, t.Handshake.Hash[:], message.Empty[:])
	return message, nil
}
