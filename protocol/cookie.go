package protocol

import (
	"crypto/hmac"
	"golang.org/x/crypto/blake2s"
	"time"
)

type Checker struct {
	Mac1Key        [32]byte
	Mac2Key        [32]byte
	LastCookieTime time.Time
}

func (st *Checker) Init(pk PublicKey) {
	HASH(&st.Mac1Key, LabelMac1[:], pk[:])
	HASH(&st.Mac2Key, LabelCookie[:], pk[:])
}

func (ch *Checker) CheckMAC1(msg []byte) bool {
	size := len(msg)
	offsetMac2 := size - CookieSize
	offsetMac1 := offsetMac2 - CookieSize

	var mac1 [blake2s.Size128]byte

	mac, _ := blake2s.New128(ch.Mac1Key[:])
	mac.Write(msg[:offsetMac1])
	mac.Sum(mac1[:0])

	return hmac.Equal(mac1[:], msg[offsetMac1:offsetMac2])
}

type Stamper struct {
	Mac1Key        [32]byte
	Mac2Key        [32]byte
	LastCookieTime time.Time
}

func (st *Stamper) Init(pk PublicKey) {
	HASH(&st.Mac1Key, LabelMac1[:], pk[:])
	HASH(&st.Mac2Key, LabelCookie[:], pk[:])
}

func (st *Stamper) Stamp(msg []byte) {
	size := len(msg)
	offsetMac2 := size - CookieSize
	offsetMac1 := offsetMac2 - CookieSize

	mac1 := msg[offsetMac1:offsetMac2]
	mac2 := msg[offsetMac2:]

	{
		hash, _ := blake2s.New128(st.Mac1Key[:])
		hash.Write(msg[:offsetMac1])
		hash.Sum(mac1[:0])
	}

	if time.Since(st.LastCookieTime) > CookieRefreshTime {
		return
	}

	{
		hash, _ := blake2s.New256(st.Mac2Key[:])
		hash.Write(msg[:offsetMac2])
		hash.Sum(mac2[:0])
	}
}
