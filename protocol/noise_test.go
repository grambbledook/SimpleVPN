package protocol

import (
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestTunnel_ProcessInitiateHandshakeMessage(t *testing.T) {
	decodeString := Must(base64.StdEncoding.DecodeString("AQAAAJBrQxNFTPvCPN7n/XiXPJIZjLIIfaR04Q1mzI8MWBEB2vBpMZ+B5vPkdO0XJ0BAr3DIFfjnYzoooy5iC9p3hmcHeabLfCfCdxYTrWsBluFQu8WiXZgxo/V2WBANV/XIrOxCxQz2H9/sB6dU6yOS3RobwxeNQQrLZmUIvCWvBV3uAAAAAAAAAAAAAAAAAAAAAA=="))

	message := MessageHandshakeInit{}
	_ = message.FromBytes(decodeString)

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
	assert.Nil(t, err)
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

		assert.Equal(
			t,
			initiator.Handshake.PrecomputedStaticStatic[:],
			responder.Handshake.PrecomputedStaticStatic[:],
		)
	}

	t.Log("Initiate Handshake stage")
	{

		ih, _ := initiator.InitiateHandshake()
		err := responder.ProcessInitiateHandshakeMessage(ih)

		assert.Nil(t, err)
		assert.Equal(
			t,
			initiator.Handshake.ChainKey[:],
			responder.Handshake.ChainKey[:],
		)
		assert.Equal(
			t,
			initiator.Handshake.Hash[:],
			responder.Handshake.Hash[:],
		)
	}

	t.Log("Complete Handshake stage")
	{

		ch, _ := responder.CreateInitiateHandshakeResponse()
		err := initiator.ProcessInitiateHandshakeResponseMessage(ch)

		assert.Nil(t, err)
		assert.Equal(
			t,
			initiator.Handshake.ChainKey[:],
			responder.Handshake.ChainKey[:],
		)
		assert.Equal(
			t,
			initiator.Handshake.Hash[:],
			responder.Handshake.Hash[:],
		)
	}

	t.Log("Compute transport keys")
	{

		err := initiator.BeginSymmetricSession()
		assert.Nil(t, err)

		err = responder.BeginSymmetricSession()
		assert.Nil(t, err)
	}

	t.Log("Test transport keys for i-r communication")
	{

		var sealed []byte
		testData := []byte("hello world")
		encrypted := initiator.Keypair.SendKey.Seal(sealed, ZeroNonce[:], testData, nil)
		decrypted, err := responder.Keypair.ReceiveKey.Open(sealed[:], ZeroNonce[:], encrypted, nil)

		assert.Nil(t, err)
		assert.Equal(t, testData, decrypted)
	}

	t.Log("Test transport keys for r-i communication")
	{

		var sealed []byte
		testData := []byte("hello world")
		encrypted := responder.Keypair.SendKey.Seal(sealed, ZeroNonce[:], testData, nil)
		decrypted, err := initiator.Keypair.ReceiveKey.Open(sealed[:], ZeroNonce[:], encrypted, nil)

		assert.Nil(t, err)
		assert.Equal(t, testData, decrypted)
	}
}
