package protocol

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"hash"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/curve25519"
)

// HASH is the WireGuard protocol's hash primitive, unkeyed BLAKE2s-256
// (RFC 7693):
//
//	Hash(input) := Blake2s(input, 32)
//
// The parts are hashed as a single concatenated message, so HASH(&h, a, b)
// computes Hash(a | b) without allocating a joined buffer. It serves two
// separate roles in this package:
//
//   - the running transcript hash H of the Noise handshake, chained as
//     H := Hash(H | x) and fed to the AEAD as associated data (noise.go);
//   - deriving the mac1/mac2 keys from a label and a public key (cookie.go).
//
// Inputs:
//
//	parts    the message fragments, hashed in the order given
//
// Output:
//
//	sum      the 32-byte digest
//
// sum may alias one of the parts, which is how the H := Hash(H | x) chaining
// is written. It is safe because Sum only writes after every part has been
// absorbed. The error from New256 is discarded because it can only report an
// invalid key length, and the key here is always nil.
func HASH(sum *[blake2s.Size]byte, parts ...[]byte) {
	h, _ := blake2s.New256(nil)
	for _, data := range parts {
		h.Write(data)
	}
	h.Sum(sum[:0])
}

// HKDFExtract performs the HKDF extract step (RFC 5869, section 2.2).
//
//	HKDF-Extract(salt, IKM) -> PRK
//
//	Inputs:
//	   salt     optional salt value (a non-secret random value);
//	            if not provided, it is set to a string of HashLen zeros.
//	            NOTE: the salt is the HMAC *key*. In the Noise handshake this
//	            is the running chaining key C, not the secret.
//	   ikm      input keying material, i.e. the actual secret being mixed in
//	            (a DH output, an ephemeral public key, the pre-shared key).
//
//	Output:
//	   prk      a pseudorandom key (of HashLen octets)
func HKDFExtract(prk *[blake2s.Size]byte, salt, ikm []byte) {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, salt)
	mac.Write(ikm)
	mac.Sum(prk[:0])
}

// HKDFExpand computes a single output block T(n) of the HKDF expand step
// (RFC 5869, section 2.3).
//
//	HKDF-Expand(PRK, info, L) -> OKM
//	T(n) = HMAC-Hash(PRK, T(n-1) | info | n)
//
//	Inputs:
//	   prk      a pseudorandom key of at least HashLen octets
//	            (usually, the output from the extract step)
//	   prev     T(n-1), the previous output block; empty when computing T(1)
//	   counter  the single octet n: 0x01 for T(1), 0x02 for T(2), ...
//
//	Output:
//	   t        one output block T(n) of HashLen octets
//
// RFC 5869's optional `info` argument is always empty in WireGuard, so it has
// no parameter here. Callers build OKM one block at a time; see KDF1/2/3.
func HKDFExpand(t *[blake2s.Size]byte, prk, prev, counter []byte) {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, prk)
	mac.Write(prev)
	mac.Write(counter)
	mac.Sum(t[:0])
}

// KDF1 derives one HashLen output block from (salt, ikm).
//
//	PRK = HKDF-Extract(salt, ikm)
//	t0  = T(1) = HMAC-Hash(PRK, 0x01)
//
// salt is the HMAC key (the running chaining key C); ikm is the secret.
func KDF1(t0 *[blake2s.Size]byte, salt, ikm []byte) {
	// Extract into t0, then expand t0 in place. Reusing t0 as both the PRK and
	// the destination is safe: hmac.New absorbs the key into the ipad/opad
	// before mac.Sum writes any output.
	HKDFExtract(t0, salt, ikm)
	HKDFExpand(t0, t0[:], []byte{}, []byte{0x1})
}

// KDF2 derives two HashLen output blocks from (salt, ikm).
//
//	PRK = HKDF-Extract(salt, ikm)
//	t0  = T(1) = HMAC-Hash(PRK, 0x01)
//	t1  = T(2) = HMAC-Hash(PRK, T(1) | 0x02)
//
// salt is the HMAC key (the running chaining key C); ikm is the secret.
func KDF2(t0, t1 *[blake2s.Size]byte, salt, ikm []byte) {
	// Extract. Compute PRK
	var prk [blake2s.Size]byte
	HKDFExtract(&prk, salt, ikm)

	HKDFExpand(t0, prk[:], []byte{}, []byte{0x1})
	HKDFExpand(t1, prk[:], t0[:], []byte{0x2})
}

// KDF3 derives three HashLen output blocks from (salt, ikm).
//
//	PRK = HKDF-Extract(salt, ikm)
//	t0  = T(1) = HMAC-Hash(PRK, 0x01)
//	t1  = T(2) = HMAC-Hash(PRK, T(1) | 0x02)
//	t2  = T(3) = HMAC-Hash(PRK, T(2) | 0x03)
//
// salt is the HMAC key (the running chaining key C); ikm is the secret.
func KDF3(t0, t1, t2 *[blake2s.Size]byte, salt, ikm []byte) {
	// Extract. Compute PRK
	var prk [blake2s.Size]byte
	HKDFExtract(&prk, salt, ikm)

	HKDFExpand(t0, prk[:], []byte{}, []byte{0x1})
	HKDFExpand(t1, prk[:], t0[:], []byte{0x2})
	HKDFExpand(t2, prk[:], t1[:], []byte{0x3})
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

func RandomUint32() (uint32, error) {
	var b [4]byte
	_, err := rand.Read(b[:])
	return binary.LittleEndian.Uint32(b[:]), err
}
