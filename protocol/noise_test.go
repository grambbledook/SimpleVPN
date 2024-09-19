package protocol

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func assertNil(t *testing.T, message string, err error) {
	if err != nil {
		t.Fatal(message, err)
	}
}

func assertEqualb(t *testing.T, message string, a, b []byte) {
	if !bytes.Equal(a, b) {
		t.Fatalf("[%s]\n  L: %v\n  R: %v", message, a, b)
	}
}

func TestTunnel_ProcessInitiateHandshakeMessage(t *testing.T) {
	message := MessageHandshakeInit{}
	decodeString := Must(base64.StdEncoding.DecodeString("AQAAAJBrQxNFTPvCPN7n/XiXPJIZjLIIfaR04Q1mzI8MWBEB2vBpMZ+B5vPkdO0XJ0BAr3DIFfjnYzoooy5iC9p3hmcHeabLfCfCdxYTrWsBluFQu8WiXZgxo/V2WBANV/XIrOxCxQz2H9/sB6dU6yOS3RobwxeNQQrLZmUIvCWvBV3uAAAAAAAAAAAAAAAAAAAAAA=="))
	message.FromBytes(decodeString)

	tunnel := Tunnel{
		Local: Peer{
			PublicKey:  PkFromString("pMo33VR8Lwi0nmi3sAFTFttomPI71LSMkEjFXws94wU="),
			PrivateKey: SkFromString("WEGlnZqW7a3J+AmKoDg+/L95sSIutu9ApEp3AY+l30o="),
		},
		Remote: Peer{
			PublicKey:  PkFromString("doQkpj/AjVrfbTFENyj46kzYWNDdrXulSfxBdnmslCo="),
			PrivateKey: SkFromString("0Iic3DBj7LXp6dl+HKWT7a6/XXzRfqaDiZXArCpLQWE="),
		},
		Handshake: Handshake{},
	}
	tunnel.Initialise()

	err := tunnel.ProcessInitiateHandshakeMessage(message)
	if err != nil {
		t.Fatal("Failed to process initiate handshake message", err)
	}
}

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

		assertEqualb(
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
		assertEqualb(
			t, "chainKey after initiation",
			initiator.Handshake.ChainKey[:],
			responder.Handshake.ChainKey[:],
		)
		assertEqualb(
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
		assertEqualb(
			t, "chainKey after handshake response",
			initiator.Handshake.ChainKey[:],
			responder.Handshake.ChainKey[:],
		)
		assertEqualb(
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
		assertEqualb(t, "decrypted data", testData, decrypted)
	}

	t.Log("Test transport keys for r-i communication")
	{

		var sealed []byte
		testData := []byte("hello world")
		encrypted := responder.Keypair.SendKey.Seal(sealed, ZeroNonce[:], testData, nil)
		decrypted, err := initiator.Keypair.ReceiveKey.Open(sealed[:], ZeroNonce[:], encrypted, nil)

		assertNil(t, "Failed to decrypt data in r-i communication", err)
		assertEqualb(t, "decrypted data", testData, decrypted)
	}
}
