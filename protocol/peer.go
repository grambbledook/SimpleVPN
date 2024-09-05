package protocol

import "golang.org/x/crypto/blake2s"

const (
	Created                              = iota
	InitiateHandshakeMessageSent         = iota
	InitiateHandshakeResponseMessageSent = iota
)

type Peer struct {
	PrivateKey PrivateKey
	PublicKey  PublicKey
}

type Tunnel struct {
	Local     Peer
	Remote    Peer
	Handshake Handshake
}

type Handshake struct {
	ChainKey                [blake2s.Size]byte
	Hash                    [blake2s.Size]byte
	LocalEphemeralSecret    PrivateKey
	LocalEphemeralPublic    PublicKey
	RemoteEphemeralSecret   PrivateKey
	RemoteEphemeralPublic   PublicKey
	Status                  int
	InitiatorIndex          uint32
	PrecomputedStaticStatic SharedSecret
	LastTimestamp           Tai64n
}
