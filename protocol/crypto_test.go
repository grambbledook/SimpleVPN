package protocol

import (
	"testing"
)

func Test_ECDH(t *testing.T) {
	a_pk := NewPrivateKey()
	b_pk := NewPrivateKey()

	t.Log("A's PK", a_pk)
	t.Log("B's PK", b_pk)

	a_pub := a_pk.PublicKey()
	b_pub := b_pk.PublicKey()

	t.Log("A's PK", a_pub)
	t.Log("B's PK", b_pub)

	k_a, _ := a_pk.SharedSecret(b_pub)
	k_b, _ := b_pk.SharedSecret(a_pub)

	t.Log("A's SS", k_a)
	t.Log("B's SS", k_b)

	if k_a != k_b {
		t.Fatal("Shared secrets do not match")
	}
}
