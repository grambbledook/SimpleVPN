package protocol

import (
	"fmt"
	"testing"
)

func Test_ECDH(t *testing.T) {
	a_pk := NewPrivateKey()
	b_pk := NewPrivateKey()

	fmt.Println("A's PK", a_pk)
	fmt.Println("B's PK", b_pk)

	a_pub := a_pk.publicKey()
	b_pub := b_pk.publicKey()

	fmt.Println("A's PK", a_pub)
	fmt.Println("B's PK", b_pub)

	k_a, _ := a_pk.SharedSecret(b_pub)
	k_b, _ := b_pk.SharedSecret(a_pub)

	fmt.Println("A's SS", k_a)
	fmt.Println("B's SS", k_b)

	if k_a != k_b {
		t.Fatal("Shared secrets do not match")
	}
}
