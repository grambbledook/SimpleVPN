package protocol

import "golang.org/x/crypto/blake2s"

type Peer struct {
	PrivateKey PrivateKey
	PublicKey  PublicKey
}

type Handshake struct {
	Chain [blake2s.Size]byte
	Hash  [blake2s.Size]byte
	Epriv PrivateKey
	Epub  PublicKey
}
