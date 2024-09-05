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
	t.Handshake.PrecomputedStaticStatic, _ = t.Local.PrivateKey.SharedSecret(t.Remote.PublicKey)
}

func (t *Tunnel) InitiateHandshake() (InitiateHandshakeMessage, error) {
	local, remote := t.Local, t.Remote
	// 1-H H := HASH(C || Spubr)
	HASH(&t.Handshake.Hash, InitialHash[:], remote.PublicKey[:])

	t.Handshake.LocalEphemeralSecret, t.Handshake.LocalEphemeralPublic = DHGenerate()
	// 1-C C := KDF1(C, Epubi)
	KDF1(&t.Handshake.ChainKey, InitialKeyChain[:], t.Handshake.LocalEphemeralPublic[:])
	// 2-H H := HASH(H || Epubi)
	HASH(&t.Handshake.Hash, t.Handshake.Hash[:], t.Handshake.LocalEphemeralPublic[:])

	message := InitiateHandshakeMessage{
		Type:      InitiateHandshakeMessageType,
		Ephemeral: t.Handshake.LocalEphemeralPublic,
	}

	// es := DH(Eprivi, Spubr)
	ss, err := t.Handshake.LocalEphemeralSecret.SharedSecret(remote.PublicKey)
	if err != nil {
		return InitiateHandshakeMessage{}, err
	}

	key := [chacha20poly1305.KeySize]byte{}
	// 2-C C, k := KDF2(C,DH(Eprivi, Spubr))
	KDF2(&t.Handshake.ChainKey, &key, t.Handshake.ChainKey[:], ss[:])

	aead, _ := chacha20poly1305.New(key[:])
	aead.Seal(message.Static[:0], ZeroNonce[:], local.PublicKey[:], t.Handshake.Hash[:])

	// 3-H H: = HASH(H || msg.Static)
	HASH(&t.Handshake.Hash, t.Handshake.Hash[:], message.Static[:])

	// Handshake.precomputedStaticStatic
	ss, err = local.PrivateKey.SharedSecret(remote.PublicKey)
	if err != nil {
		return InitiateHandshakeMessage{}, err
	}
	// 3-C C, k := KDF2(C,DH(Sprivi, Spubr))
	KDF2(&t.Handshake.ChainKey, &key, t.Handshake.ChainKey[:], ss[:])

	now := Now(time.Now())
	aead, _ = chacha20poly1305.New(key[:])
	aead.Seal(message.Timestamp[:0], ZeroNonce[:], now[:], t.Handshake.Hash[:])

	// 4-H H = HASH(H || msg.Timestamp)
	HASH(&t.Handshake.Hash, t.Handshake.Hash[:], message.Timestamp[:])
	return message, nil
}

func (t *Tunnel) ProcessInitiateHandshakeMessage(message InitiateHandshakeMessage) error {
	t.Handshake.InitiatorIndex = message.Sender
	t.Handshake.RemoteEphemeralPublic = message.Ephemeral

	hash := [blake2s.Size]byte{}
	chainKey := [chacha20poly1305.KeySize]byte{}

	// 1-H H := HASH(C || Spubr)
	HASH(&hash, InitialHash[:], t.Local.PublicKey[:])

	// 1-C C := KDF1(C,Epubi)
	KDF1(&chainKey, InitialKeyChain[:], t.Handshake.RemoteEphemeralPublic[:])

	// 2-H H := HASH(H || Epubi)
	HASH(&hash, hash[:], t.Handshake.RemoteEphemeralPublic[:])

	// se := DH(Sprivr, Epubi)
	ss, err := t.Local.PrivateKey.SharedSecret(t.Handshake.RemoteEphemeralPublic)
	if err != nil {
		return err
	}

	key := [chacha20poly1305.KeySize]byte{}
	// 2-C C, k := KDF2(C,DH(Sprivr, Epubi))
	KDF2(&chainKey, &key, chainKey[:], ss[:])

	pk := PublicKey{}
	aead, _ := chacha20poly1305.New(key[:])
	_, err = aead.Open(pk[:], ZeroNonce[:], message.Static[:], hash[:])
	if err != nil {
		return errors.New("failed to decrypt the static key")
	}

	// 3-H H := HASH(H || msg.Static)
	HASH(&hash, hash[:], message.Static[:])

	// Handshake.precomputedStaticStatic
	ss, err = t.Local.PrivateKey.SharedSecret(t.Remote.PublicKey)
	if err != nil {
		return err
	}

	// 3-C C, k := KDF2(C,DH(Sprivr, Spubi))
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

	// 4-H H := HASH(H || msg.Timestamp)
	HASH(&hash, hash[:], message.Timestamp[:])

	t.Handshake.LastTimestamp = ts
	t.Handshake.Hash = hash
	t.Handshake.ChainKey = chainKey
	return nil
}

func (t *Tunnel) CreateInitiateHandshakeResponse() (InitiateHandshakeResponseMessage, error) {
	remote := t.Remote

	t.Handshake.LocalEphemeralSecret, t.Handshake.LocalEphemeralPublic = DHGenerate()
	KDF1(&t.Handshake.ChainKey, t.Handshake.ChainKey[:], t.Handshake.RemoteEphemeralPublic[:])
	HASH(&t.Handshake.Hash, t.Handshake.Hash[:], t.Handshake.RemoteEphemeralPublic[:])
	message := InitiateHandshakeResponseMessage{
		Ephemeral: t.Handshake.LocalEphemeralPublic,
	}

	ss, err := t.Handshake.LocalEphemeralSecret.SharedSecret(t.Handshake.RemoteEphemeralPublic)
	if err != nil {
		return InitiateHandshakeResponseMessage{}, err
	}
	KDF1(&t.Handshake.ChainKey, t.Handshake.ChainKey[:], ss[:])

	ss, err = t.Handshake.LocalEphemeralSecret.SharedSecret(remote.PublicKey)
	if err != nil {
		return InitiateHandshakeResponseMessage{}, err
	}
	KDF1(&t.Handshake.ChainKey, t.Handshake.ChainKey[:], ss[:])

	tau := [blake2s.Size]byte{}
	key := [chacha20poly1305.KeySize]byte{}
	KDF3(&t.Handshake.ChainKey, &tau, &key, t.Handshake.ChainKey[:], PreSharedKey[:])

	HASH(&t.Handshake.Hash, t.Handshake.Hash[:], tau[:])
	aead, _ := chacha20poly1305.New(key[:])
	aead.Seal(message.Empty[:0], ZeroNonce[:], nil, t.Handshake.Hash[:])

	HASH(&t.Handshake.Hash, t.Handshake.Hash[:], message.Empty[:])
	return message, nil
}
