package protocol

import (
	"crypto/hmac"
	"crypto/rand"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/curve25519"
	"hash"
)

//(EprivR, EpubR):=DH-Generate()
// Cr := Kdf1(Cr,EpubR)
// msg.ephemeral := EpubR
// Hr := Hash(Hr ∥ msg.ephemeral)
// Cr := Kdf1(Cr,DH(EprivR)
// Cr := Kdf1(Cr,DH(EprivR)
// (Cr,τ,κ) := Kdf3(Cr,Q)
// Hr := Hash(Hr ∥ τ)
// msg.empty := Aead(κ,0,ϵ,Hr)
// Hr := Hash(Hr ∥ msg.empty)

func HMAC1(sum *[blake2s.Size]byte, key, input []byte) {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	mac.Write(input)
	mac.Sum(sum[:0])
}

func KDF1(t0 *[blake2s.Size]byte, key, input []byte) {
	HMAC1(t0, key, input)
	HMAC1(t0, t0[:], []byte{0x1})
}

func NewPrivateKey() (sk NoisePrivateKey) {
	rand.Read(sk[:])
	sk.clamp()

	return sk
}

// Decent explanation of why
// https://neilmadden.blog/2020/05/28/whats-the-curve25519-clamping-all-about
func (sk *NoisePrivateKey) clamp() {
	sk[0] &= 248
	sk[31] = (sk[31] & 127) | 64
}

func (sk *NoisePrivateKey) publicKey() (pk NoisePublicKey) {
	apk := (*[PublicKeySize]byte)(&pk)
	ask := (*[PrivateKeySize]byte)(sk)

	curve25519.ScalarBaseMult(apk, ask)
	return
}
