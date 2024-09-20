package protocol

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/blake2s"
	"testing"
)

type KDFTest struct {
	key   string
	input string
	t0    string
	t1    string
	t2    string
}

func Test_ECDH(t *testing.T) {
	aliceSK := NewPrivateKey()
	bobsSK := NewPrivateKey()

	t.Log("A's PK", aliceSK)
	t.Log("B's PK", bobsSK)

	alicePK := aliceSK.PublicKey()
	bobsPK := bobsSK.PublicKey()

	t.Log("A's PK", alicePK)
	t.Log("B's PK", bobsPK)

	aliceSS, _ := aliceSK.SharedSecret(bobsPK)
	bobsSS, _ := bobsSK.SharedSecret(alicePK)

	t.Log("A's SS", aliceSS)
	t.Log("B's SS", bobsSS)

	assert.Equal(t, aliceSS, bobsSS, "Shared secrets do not match")
}

// Data for this test case copied from
// the reference implementation https://github.com/WireGuard/wireguard-go
// as I couldn't find an online generator for this.
func Test_KDFs(t *testing.T) {
	tests := []KDFTest{
		{
			key:   "746573742d6b6579",
			input: "746573742d696e707574",
			t0:    "6f0e5ad38daba1bea8a0d213688736f19763239305e0f58aba697f9ffc41c633",
			t1:    "df1194df20802a4fe594cde27e92991c8cae66c366e8106aaa937a55fa371e8a",
			t2:    "fac6e2745a325f5dc5d11a5b165aad08b0ada28e7b4e666b7c077934a4d76c24",
		},
		{
			key:   "776972656775617264",
			input: "776972656775617264",
			t0:    "491d43bbfdaa8750aaf535e334ecbfe5129967cd64635101c566d4caefda96e8",
			t1:    "1e71a379baefd8a79aa4662212fcafe19a23e2b609a3db7d6bcba8f560e3d25f",
			t2:    "31e1ae48bddfbe5de38f295e5452b1909a1b4e38e183926af3780b0c1e1f0160",
		},
		{
			key:   "",
			input: "",
			t0:    "8387b46bf43eccfcf349552a095d8315c4055beb90208fb1be23b894bc2ed5d0",
			t1:    "58a0e5f6faefccf4807bff1f05fa8a9217945762040bcec2f4b4a62bdfe0e86e",
			t2:    "0ce6ea98ec548f8e281e93e32db65621c45eb18dc6f0a7ad94178610a2f7338e",
		},
	}

	for _, data := range tests {
		var t0 [blake2s.Size]byte
		key, _ := hex.DecodeString(data.key)
		input, _ := hex.DecodeString(data.input)
		KDF1(&t0, key, input)
		assert.Equal(t, data.t0, hex.EncodeToString(t0[:]))
	}
	for _, data := range tests {
		var t0, t1 [blake2s.Size]byte
		key, _ := hex.DecodeString(data.key)
		input, _ := hex.DecodeString(data.input)
		KDF2(&t0, &t1, key, input)
		assert.Equal(t, data.t0, hex.EncodeToString(t0[:]))
	}
	for _, data := range tests {
		var t0, t1, t2 [blake2s.Size]byte
		key, _ := hex.DecodeString(data.key)
		input, _ := hex.DecodeString(data.input)
		KDF3(&t0, &t1, &t2, key, input)
		assert.Equal(t, data.t0, hex.EncodeToString(t0[:]))
	}
}
