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

		if buffer[0] == protocol.HandshakeInitType {

			var message protocol.MessageHandshakeInit
			if err := message.FromBytes(buffer); err != nil {
				fmt.Println("  Can't parse a message of type [HandshakeInit]", err)
				continue
			}

			fmt.Println("  Type", message.Type, "Sender", message.Sender, "ephemeral", message.Ephemeral, "static", message.Static, "ts", message.Timestamp)

			if err := tunnel.ProcessInitiateHandshakeMessage(message); err != nil {
				fmt.Println("  Error occurred on [HandshakeInit] message processing", err)
				continue
			}

			if response, err := tunnel.CreateInitiateHandshakeResponse(); err != nil {
				fmt.Println("  Error occurred creating Handshake response", err)
			} else if _, err = bind.WriteToUDP(response.ToBytes(), &peer); err != nil {
				fmt.Println("  Error occurred on sending Handshake response", err)
			}
		}
	}
}
