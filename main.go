package main

import (
	"com.github.grambbledook/simple_vpn/protocol"
	"fmt"
	"gopkg.in/ini.v1"
	"net"
)

func Must[T any](t T, err error) T {
	if err != nil {
		panic(err)
	}
	return t
}

func PublicKey(key string) (pub protocol.PublicKey) {
	copy(pub[:], key)
	return
}

func PrivateKey(key string) (priv protocol.PrivateKey) {
	copy(priv[:], key)
	return
}

func main() {
	cfg := Must(ini.Load("config.conf"))

	devicePublicKey := cfg.Section("Interface").Key("PublicKey")
	devicePrivateKey := cfg.Section("Interface").Key("PrivateKey")
	clientPublicKey := cfg.Section("Peer").Key("PublicKey")

	tunnel := protocol.Tunnel{
		Remote: protocol.Peer{
			PublicKey:  PublicKey(devicePublicKey.String()),
			PrivateKey: PrivateKey(devicePrivateKey.String()),
		},
		Local: protocol.Peer{
			PublicKey:  PublicKey(clientPublicKey.String()),
			PrivateKey: PrivateKey(""),
		},
		Handshake: protocol.Handshake{},
	}

	listenPort := Must(cfg.Section("Interface").Key("ListenPort").Int())
	fmt.Println("Interface params", devicePublicKey, devicePrivateKey, listenPort)

	host := net.UDPAddr{
		IP:   net.IPv4(0, 0, 0, 0),
		Port: listenPort,
	}
	fmt.Println("UDPAddr", host)

	peer := net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 52974,
	}

	bind := Must(net.ListenUDP("udp", &host))
	defer bind.Close()

	fmt.Println("Listening on", bind.LocalAddr())

	buffer := make([]byte, 1024)
	for {
		n, remoteAddr, err := bind.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println("Error reading from UDP", err)
			continue
		}
		fmt.Println("Received", n, "bytes from", remoteAddr)

		if buffer[0] == protocol.InitiateHandshakeMessageType {
			message, err := protocol.FromBytes(buffer)
			if err != nil {
				fmt.Println("  Error occurred on message parsing", err)
				continue
			}

			fmt.Println("  Type", message.Type, "Sender", message.Sender, "ephemeral", message.Ephemeral, "static", message.Static, "ts", message.Timestamp)

			err = tunnel.ProcessInitiateHandshakeMessage(message)
			if err != nil {
				fmt.Println("  Error occurred on ih message processing", err)
				continue
			}

			response, err := tunnel.CreateInitiateHandshakeResponse()
			if err != nil {
				fmt.Println("  Error occurred on ih response creation", err)
				continue
			}

			_, err = bind.WriteToUDP(response.ToBytes(), &peer)
			if err != nil {
				fmt.Println("  Error occurred on ih response sending", err)
				continue
			}

		}

		//Must(bind.WriteToUDP(make([]byte, 120), &peer))
	}
}
