package protocol

import (
	"bytes"
	"testing"
)

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
		Remote: Peer{
			PrivateKey: initiator_pk,
			PublicKey:  initiator_pk.PublicKey(),
		},
		Local: Peer{
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
		initiator.Handshake.ChainKey[:],
		responder.Handshake.ChainKey[:],
	)
	assertEquals(
		t, "hash after initiation",
		initiator.Handshake.Hash[:],
		responder.Handshake.Hash[:],
	)

	ch, _ := responder.CreateInitiateHandshakeResponse()
	err := initiator.ProcessInitiateHandshakeResponseMessage(ch)

	if err != nil {
		t.Fatal(err)
	}
	assertEquals(
		t, "chainKey after handshake response",
		initiator.Handshake.ChainKey[:],
		responder.Handshake.ChainKey[:],
	)
	assertEquals(
		t, "hash after handshake response",
		initiator.Handshake.Hash[:],
		responder.Handshake.Hash[:],
	)
}

func assertEquals(t *testing.T, message string, a, b []byte) {
	if !bytes.Equal(a, b) {
		t.Fatalf("[%s]\n  L: %v\n  R: %v", message, a, b)
	}
}
