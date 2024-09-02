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

func HASH(input ...[]byte) (sum [blake2s.Size]byte) {
	h, _ := blake2s.New256(nil)
	for _, data := range input {
		h.Write(data)
	}
	h.Sum(sum[:0])
	return
}

func HKDFExtract(sum *[blake2s.Size]byte, key, input []byte) {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	mac.Write(input)
	mac.Sum(sum[:0])
}

func HKDFExpand(sum *[blake2s.Size]byte, key, info, input []byte) {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	mac.Write(input)
	mac.Write(info)
	mac.Sum(sum[:0])
}

func KDF1(t0 *[blake2s.Size]byte, key, input []byte) {
	// Extract. set t0 = HMAC-Hash(key, input), i.e. compute PRK
	HKDFExtract(t0, key, input)
	HKDFExpand(t0, t0[:], []byte{}, []byte{0x1})
}

// KDF2 HKDF-Extract(salt, IKM) -> PRK
//
//	Inputs:
//	   salt     optional salt value (a non-secret random value);
//	            if not provided, it is set to a string of HashLen zeros.
//	   IKM      input keying material
//
//	Output:
//	   PRK      a pseudorandom key (of HashLen octets)
//
// HKDF-Expand(PRK, info, L) -> OKM
//
// Inputs:
//
//	   PRK      a pseudorandom key of at least HashLen octets
//	            (usually, the output from the extract step)
//	   info     optional context and application specific information
//	            (can be a zero-length string)
//	   L        length of output keying material in octets
//	            (<= 255*HashLen)
//
//	Output:
//	   OKM      output keying material (of L octets)
//
//	The output OKM is calculated as follows:
//
//	N = ceil(L/HashLen)
//	T = T(1) | T(2) | T(3) | ... | T(N)
//	OKM = first L octets of T
//
// where:
//
//	T(0) = empty string (zero length)
//	T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
//	T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
//	T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
func KDF2(t0, t1 *[blake2s.Size]byte, key, input []byte) {
	// Extract. Compute PRK
	var prk [blake2s.Size]byte
	HKDFExtract(&prk, key, input)

	HKDFExpand(t0, prk[:], []byte{}, []byte{0x1})
	HKDFExpand(t1, prk[:], t0[:], []byte{0x2})
}

func DHGenerate() (sk PrivateKey, pk PublicKey) {
	sk = NewPrivateKey()
	pk = sk.PublicKey()
	return
}

func NewPrivateKey() (sk PrivateKey) {
	rand.Read(sk[:])
	sk.clamp()

	return sk
}

// Decent explanation of why
// https://neilmadden.blog/2020/05/28/whats-the-curve25519-clamping-all-about
func (sk *PrivateKey) clamp() {
	sk[0] &= 248
	sk[31] = (sk[31] & 127) | 64
}

func (sk *PrivateKey) PublicKey() (pk PublicKey) {
	apk := (*[PublicKeySize]byte)(&pk)
	ask := (*[PrivateKeySize]byte)(sk)

	curve25519.ScalarBaseMult(apk, ask)
	return
}

func (sk *PrivateKey) SharedSecret(pub PublicKey) (SharedSecret, error) {
	apk := (*[PublicKeySize]byte)(&pub)
	ask := (*[PrivateKeySize]byte)(sk)

	ss, err := curve25519.X25519(ask[:], apk[:])
	return SharedSecret(ss), err
}
