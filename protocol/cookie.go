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

func (ch *Checker) Init(pk PublicKey) {
	HASH(&ch.Mac1Key, LabelMac1[:], pk[:])
	HASH(&ch.Mac2Key, LabelCookie[:], pk[:])
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

// CheckMAC2 This implementation is incorrect,
// should be fixed according to 5.4.7 of the whitepaper
func (ch *Checker) CheckMAC2(msg []byte) bool {
	size := len(msg)
	offsetMac2 := size - CookieSize

	var mac2 [blake2s.Size128]byte

	mac, _ := blake2s.New128(ch.Mac2Key[:])
	mac.Write(msg[:offsetMac2])
	mac.Sum(mac2[:0])

	return hmac.Equal(mac2[:], msg[offsetMac2:])
}

type Stamper struct {
	Mac1Key        [blake2s.Size]byte
	Mac2Key        [blake2s.Size]byte
	Cookie         [blake2s.Size128]byte
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

	// 5.4.4 of the whitepaper:
	// if Cookie = nil or f LastCookieTime ≥ 120:
	// 		msg.mac2 := 016
	// else:
	// 		msg.mac2 := Mac(Cookie, msgβ)
	{
		hash, _ := blake2s.New128(st.Cookie[:])
		hash.Write(msg[:offsetMac2])
		hash.Sum(mac2[:0])
	}
}
