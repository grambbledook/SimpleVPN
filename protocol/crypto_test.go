package protocol

import (
	"bytes"
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

func Test_Handshake(t *testing.T) {
	initiator_pk := NewPrivateKey()
	responder_pk := NewPrivateKey()

	initiator := Tunnel{
		Local: Peer{
			PrivateKey: initiator_pk,
			PublicKey:  initiator_pk.PublicKey(),
		},
		Remote: Peer{
			PrivateKey: responder_pk,
			PublicKey:  responder_pk.PublicKey(),
		},
		Handshake: Handshake{},
	}

	responder := Tunnel{
		Local: Peer{
			PrivateKey: initiator_pk,
			PublicKey:  initiator_pk.PublicKey(),
		},
		Remote: Peer{
			PrivateKey: responder_pk,
			PublicKey:  responder_pk.PublicKey(),
		},
		Handshake: Handshake{},
	}

	initiator.initialise()
	responder.initialise()

	assertEquals(
		t, "precomputedStaticStatic",
		initiator.Handshake.PrecomputedStaticStatic[:],
		responder.Handshake.PrecomputedStaticStatic[:],
	)

	ih, _ := initiator.InitiateHandshake()
	_ = responder.ProcessInitiateHandshakeMessage(ih)

	assertEquals(
		t, "chainKey after initiation",
		initiator.Handshake.Chain[:],
		responder.Handshake.Chain[:],
	)
	assertEquals(
		t, "hash after initiation",
		initiator.Handshake.Hash[:],
		responder.Handshake.Hash[:],
	)

	ch, _ := responder.CreateInitiateHandshakeResponse()
	_ = initiator.ProcessInitiateHandshakeResponseMessage(ch)
}

func assertEquals(t *testing.T, message string, a, b []byte) {
	if !bytes.Equal(a, b) {
		t.Fatalf("[%s]\n  L: %v\n  R: %v", message, a, b)
	}
}
