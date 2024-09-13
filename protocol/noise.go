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

func setZeroes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (t *Tunnel) Initialise() {
	t.Handshake.PrecomputedStaticStatic, _ = t.Local.PrivateKey.SharedSecret(t.Remote.PublicKey)
}

func (t *Tunnel) InitiateHandshake() (MessageHandshakeInit, error) {
	local, remote := t.Local, t.Remote
	// 1-H H := HASH(C || Spubr)
	HASH(&t.Handshake.Hash, InitialHash[:], remote.PublicKey[:])

	t.Handshake.LocalEphemeralSecret, t.Handshake.LocalEphemeralPublic = DHGenerate()
	// 1-C C := KDF1(C, Epubi)
	KDF1(&t.Handshake.ChainKey, InitialKeyChain[:], t.Handshake.LocalEphemeralPublic[:])
	// 2-H H := HASH(H || Epubi)
	HASH(&t.Handshake.Hash, t.Handshake.Hash[:], t.Handshake.LocalEphemeralPublic[:])

	message := MessageHandshakeInit{
		Type:      HandshakeInitType,
		Ephemeral: t.Handshake.LocalEphemeralPublic,
	}

	// es := DH(Eprivi, Spubr)
	ss, err := t.Handshake.LocalEphemeralSecret.SharedSecret(remote.PublicKey)
	if err != nil {
		return MessageHandshakeInit{}, err
	}

	var key [chacha20poly1305.KeySize]byte
	// 2-C C, k := KDF2(C,DH(Eprivi, Spubr))
	KDF2(&t.Handshake.ChainKey, &key, t.Handshake.ChainKey[:], ss[:])

	aead, _ := chacha20poly1305.New(key[:])
	aead.Seal(message.Static[:0], ZeroNonce[:], local.PublicKey[:], t.Handshake.Hash[:])

	// 3-H H: = HASH(H || msg.Static)
	HASH(&t.Handshake.Hash, t.Handshake.Hash[:], message.Static[:])

	// Handshake.precomputedStaticStatic
	ss, err = local.PrivateKey.SharedSecret(remote.PublicKey)
	if err != nil {
		return MessageHandshakeInit{}, err
	}
	// 3-C C, k := KDF2(C,DH(Sprivi, Spubr))
	KDF2(&t.Handshake.ChainKey, &key, t.Handshake.ChainKey[:], ss[:])

	now := Now(time.Now())
	aead, _ = chacha20poly1305.New(key[:])
	aead.Seal(message.Timestamp[:0], ZeroNonce[:], now[:], t.Handshake.Hash[:])

	// 4-H H = HASH(H || msg.Timestamp)
	HASH(&t.Handshake.Hash, t.Handshake.Hash[:], message.Timestamp[:])
	t.Handshake.Status = InitiateHandshakeMessageSent
	return message, nil
}

func (t *Tunnel) ProcessInitiateHandshakeMessage(message MessageHandshakeInit) error {

	var hash [blake2s.Size]byte
	var chainKey [chacha20poly1305.KeySize]byte

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

	var key [chacha20poly1305.KeySize]byte
	// 2-C C, k := KDF2(C,DH(Sprivr, Epubi))
	KDF2(&chainKey, &key, chainKey[:], ss[:])

	var pk PublicKey
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

	var ts Tai64n
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
	t.Handshake.Status = InitiateHandshakeMessageReceived
	return nil
}

func (t *Tunnel) CreateInitiateHandshakeResponse() (MessageHandshakeResponse, error) {
	remote := t.Remote

	var hash [blake2s.Size]byte
	var chainKey [chacha20poly1305.KeySize]byte

	t.Handshake.LocalEphemeralSecret, t.Handshake.LocalEphemeralPublic = DHGenerate()

	message := MessageHandshakeResponse{
		Type:      HandshakeResponseType,
		Ephemeral: t.Handshake.LocalEphemeralPublic,
	}

	HASH(&hash, t.Handshake.Hash[:], message.Ephemeral[:])
	KDF1(&chainKey, t.Handshake.ChainKey[:], message.Ephemeral[:])

	ss, err := t.Handshake.LocalEphemeralSecret.SharedSecret(t.Handshake.RemoteEphemeralPublic)
	if err != nil {
		return MessageHandshakeResponse{}, err
	}
	KDF1(&chainKey, chainKey[:], ss[:])

	ss, err = t.Handshake.LocalEphemeralSecret.SharedSecret(remote.PublicKey)
	if err != nil {
		return MessageHandshakeResponse{}, err
	}
	KDF1(&chainKey, chainKey[:], ss[:])

	var tau [blake2s.Size]byte
	var key [chacha20poly1305.KeySize]byte
	KDF3(&chainKey, &tau, &key, chainKey[:], PreSharedKey[:])

	HASH(&hash, hash[:], tau[:])
	aead, _ := chacha20poly1305.New(key[:])
	aead.Seal(message.Empty[:0], ZeroNonce[:], nil, hash[:])

	HASH(&hash, hash[:], message.Empty[:])

	t.Handshake.Hash = hash
	t.Handshake.ChainKey = chainKey
	t.Handshake.Status = InitiateHandshakeResponseMessageSent
	return message, nil
}

func (t *Tunnel) ProcessInitiateHandshakeResponseMessage(message MessageHandshakeResponse) error {
	local, _ := t.Local, t.Remote

	var hash [blake2s.Size]byte
	var chainKey [chacha20poly1305.KeySize]byte

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

	var tau [blake2s.Size]byte
	var key [chacha20poly1305.KeySize]byte
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
	t.Handshake.Status = InitiateHandshakeResponseMessageReceived
	return nil
}

func (t *Tunnel) BeginSymmetricSession() error {
	var send [chacha20poly1305.KeySize]byte
	var receive [chacha20poly1305.KeySize]byte

	if t.Handshake.Status == InitiateHandshakeResponseMessageReceived {
		KDF2(&send, &receive, t.Handshake.ChainKey[:], nil)
	} else if t.Handshake.Status == InitiateHandshakeResponseMessageSent {
		KDF2(&receive, &send, t.Handshake.ChainKey[:], nil)
	} else {
		return errors.New("wrong handshake status")
	}

	setZeroes(t.Handshake.Hash[:])
	setZeroes(t.Handshake.ChainKey[:])
	setZeroes(t.Handshake.LocalEphemeralSecret[:])
	setZeroes(t.Handshake.LocalEphemeralPublic[:])
	setZeroes(t.Handshake.RemoteEphemeralPublic[:])

	t.Keypair = Keypair{}
	t.Keypair.SendKey, _ = chacha20poly1305.New(send[:])
	t.Keypair.ReceiveKey, _ = chacha20poly1305.New(receive[:])
	t.Nonce = 0

	t.Handshake.Status = Completed

	// Don't forget to keep track of prev keys to handle refreshes and reconnects.
	return nil
}
