package protocol

import (
	"bytes"
	"testing"
)

func Test_Handshake(t *testing.T) {
	initiatorSK := NewPrivateKey()
	responderSK := NewPrivateKey()

	initiator := Tunnel{
		Local: Peer{
			PrivateKey: initiatorSK,
			PublicKey:  initiatorSK.PublicKey(),
		},
		Remote: Peer{
			PrivateKey: responderSK,
			PublicKey:  responderSK.PublicKey(),
		},
		Handshake: Handshake{},
	}
	responder := Tunnel{
		Remote: Peer{
			PrivateKey: initiatorSK,
			PublicKey:  initiatorSK.PublicKey(),
		},
		Local: Peer{
			PrivateKey: responderSK,
			PublicKey:  responderSK.PublicKey(),
		},
		Handshake: Handshake{},
	}

	t.Logf("Pre-compute static-static shared secret")
	{
		initiator.Initialise()
		responder.Initialise()

		assertEquals(
			t, "precomputedStaticStatic",
			initiator.Handshake.PrecomputedStaticStatic[:],
			responder.Handshake.PrecomputedStaticStatic[:],
		)
	}

	t.Log("Initiate Handshake stage")
	{

		ih, _ := initiator.InitiateHandshake()
		err := responder.ProcessInitiateHandshakeMessage(ih)

		assertNil(t, "Unable to process handshake initiation", err)
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
	}

	t.Log("Complete Handshake stage")
	{

		ch, _ := responder.CreateInitiateHandshakeResponse()
		err := initiator.ProcessInitiateHandshakeResponseMessage(ch)

		assertNil(t, "Unable to process handshake response", err)
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

	t.Log("Compute transport keys")
	{

		err := initiator.BeginSymmetricSession()
		assertNil(t, "Unable to derive transport keys for initiator", err)

		err = responder.BeginSymmetricSession()
		assertNil(t, "Unable to derive transport keys for responder", err)
	}

	t.Log("Test transport keys for i-r communication")
	{

		var sealed []byte
		testData := []byte("hello world")
		encrypted := initiator.Keypair.SendKey.Seal(sealed, ZeroNonce[:], testData, nil)
		decrypted, err := responder.Keypair.ReceiveKey.Open(sealed[:], ZeroNonce[:], encrypted, nil)

		assertNil(t, "Failed to decrypt data in i-r communication", err)
		assertEquals(t, "decrypted data", testData, decrypted)
	}

	t.Log("Test transport keys for r-i communication")
	{

		var sealed []byte
		testData := []byte("hello world")
		encrypted := responder.Keypair.SendKey.Seal(sealed, ZeroNonce[:], testData, nil)
		decrypted, err := initiator.Keypair.ReceiveKey.Open(sealed[:], ZeroNonce[:], encrypted, nil)

		assertNil(t, "Failed to decrypt data in r-i communication", err)
		assertEquals(t, "decrypted data", testData, decrypted)
	}
}

func assertNil(t *testing.T, message string, err error) {
	if err != nil {
		t.Fatal(message, err)
	}
}

func assertEquals(t *testing.T, message string, a, b []byte) {
	if !bytes.Equal(a, b) {
		t.Fatalf("[%s]\n  L: %v\n  R: %v", message, a, b)
	}
}
