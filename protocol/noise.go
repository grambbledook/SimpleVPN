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
	InitialKeyChain [blake2s.Size]byte
	InitialHash     [blake2s.Size]byte
	ZeroNonce       [chacha20poly1305.NonceSize]byte
	PreSharedKey    = [SharedSecretSize]byte{}
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

	hash := [blake2s.Size]byte{}
	chainKey := [chacha20poly1305.KeySize]byte{}

	// 1-H H := HASH(C || Spubr)
	HASH(&hash, InitialHash[:], t.Local.PublicKey[:])

	// 1-C C := KDF1(C,Epubi)
	KDF1(&chainKey, InitialKeyChain[:], message.Ephemeral[:])

	// 2-H H := HASH(H || Epubi)
	HASH(&hash, hash[:], message.Ephemeral[:])

	// se := DH(Sprivr, Epubi)
	ss, err := t.Local.PrivateKey.SharedSecret(message.Ephemeral)
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

	t.Handshake.InitiatorIndex = message.Sender
	t.Handshake.RemoteEphemeralPublic = message.Ephemeral
	return nil
}

func (t *Tunnel) CreateInitiateHandshakeResponse() (InitiateHandshakeResponseMessage, error) {
	remote := t.Remote

	hash := [blake2s.Size]byte{}
	chainKey := [chacha20poly1305.KeySize]byte{}

	t.Handshake.LocalEphemeralSecret, t.Handshake.LocalEphemeralPublic = DHGenerate()

	message := InitiateHandshakeResponseMessage{
		Ephemeral: t.Handshake.LocalEphemeralPublic,
	}

	HASH(&hash, t.Handshake.Hash[:], message.Ephemeral[:])
	KDF1(&chainKey, t.Handshake.ChainKey[:], message.Ephemeral[:])

	ss, err := t.Handshake.LocalEphemeralSecret.SharedSecret(t.Handshake.RemoteEphemeralPublic)
	if err != nil {
		return InitiateHandshakeResponseMessage{}, err
	}
	KDF1(&chainKey, chainKey[:], ss[:])

	ss, err = t.Handshake.LocalEphemeralSecret.SharedSecret(remote.PublicKey)
	if err != nil {
		return InitiateHandshakeResponseMessage{}, err
	}
	KDF1(&chainKey, chainKey[:], ss[:])

	tau := [blake2s.Size]byte{}
	key := [chacha20poly1305.KeySize]byte{}
	KDF3(&chainKey, &tau, &key, chainKey[:], PreSharedKey[:])

	HASH(&hash, hash[:], tau[:])
	aead, _ := chacha20poly1305.New(key[:])
	aead.Seal(message.Empty[:0], ZeroNonce[:], nil, hash[:])

	HASH(&hash, hash[:], message.Empty[:])

	t.Handshake.Hash = hash
	t.Handshake.ChainKey = chainKey
	return message, nil
}

func (t *Tunnel) ProcessInitiateHandshakeResponseMessage(message InitiateHandshakeResponseMessage) interface{} {
	local, _ := t.Local, t.Remote

	hash := [blake2s.Size]byte{}
	chainKey := [chacha20poly1305.KeySize]byte{}

	// 1-C C := KDF1(C,Epubr)
	KDF1(&chainKey, t.Handshake.ChainKey[:], message.Ephemeral[:])

	// 1-H H := HASH(H || Epubr)
	HASH(&hash, t.Handshake.Hash[:], message.Ephemeral[:])

	ss, err := t.Handshake.LocalEphemeralSecret.SharedSecret(message.Ephemeral)
	if err != nil {
		return err
	}
	// 2-C C, k := KDF2(C,DH(Eprivi, Epubr))
	KDF1(&chainKey, chainKey[:], ss[:])

	ss, err = local.PrivateKey.SharedSecret(message.Ephemeral)
	if err != nil {
		return err
	}
	// 3-C C, k := KDF2(C,DH(Eprivi, Spubr))
	KDF1(&chainKey, chainKey[:], ss[:])

	tau := [blake2s.Size]byte{}
	key := [chacha20poly1305.KeySize]byte{}
	// 4-C C, tau, k := KDF3(C, Q)
	KDF3(&chainKey, &tau, &key, chainKey[:], PreSharedKey[:])

	// 2-H H := HASH(H || tau)
	HASH(&hash, hash[:], tau[:])

	aead, _ := chacha20poly1305.New(key[:])
	_, err = aead.Open(nil, ZeroNonce[:], message.Empty[:], hash[:])
	if err != nil {
		return errors.New("failed to open the msg.empty field")
	}

	HASH(&hash, hash[:], message.Empty[:])

	t.Handshake.Hash = hash
	t.Handshake.ChainKey = chainKey
	t.Handshake.RemoteEphemeralPublic = message.Ephemeral

	return nil
}
