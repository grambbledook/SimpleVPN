package main

import (
	"com.github.grambbledook/simple_vpn/protocol"
	"encoding/base64"
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
	if err := pub.FromBase64(key); err != nil {
		panic(err)
	}
	return
}

func PrivateKey(key string) (priv protocol.PrivateKey) {
	if err := priv.FromBase64(key); err != nil {
		panic(err)
	}
	return
}

func main() {
	cfg := Must(ini.Load("config.conf"))

	devicePublicKey := cfg.Section("Interface").Key("PublicKey")
	devicePrivateKey := cfg.Section("Interface").Key("PrivateKey")
	clientPrivateKey := cfg.Section("Peer").Key("PrivateKey")
	clientPublicKey := cfg.Section("Peer").Key("PublicKey")

	tunnel := protocol.Tunnel{
		Local: protocol.Peer{
			PublicKey:  PublicKey(devicePublicKey.String()),
			PrivateKey: PrivateKey(devicePrivateKey.String()),
		},
		Remote: protocol.Peer{
			PublicKey:  PublicKey(clientPublicKey.String()),
			PrivateKey: PrivateKey(clientPrivateKey.String()),
		},
		Handshake: protocol.Handshake{},
	}
	tunnel.Initialise()

	fmt.Println("host sk 0:", devicePrivateKey.String())
	fmt.Println("host sk 1:", base64.StdEncoding.EncodeToString(tunnel.Local.PrivateKey[:]))

	fmt.Println("host pk 0:", devicePublicKey.String())
	fmt.Println("host pk 1:", base64.StdEncoding.EncodeToString(tunnel.Local.PublicKey[:]))
	ppk := tunnel.Local.PrivateKey.PublicKey()
	fmt.Println("host pk 2:", base64.StdEncoding.EncodeToString(ppk[:]))

	fmt.Println("client sk 0:", clientPrivateKey.String())
	fmt.Println("client sk 1:", base64.StdEncoding.EncodeToString(tunnel.Remote.PrivateKey[:]))

	fmt.Println("client pk 0:", clientPublicKey.String())
	fmt.Println("client pk 1:", base64.StdEncoding.EncodeToString(tunnel.Remote.PublicKey[:]))
	cpk := tunnel.Remote.PrivateKey.PublicKey()
	fmt.Println("client pk 2:", base64.StdEncoding.EncodeToString(cpk[:]))

	listenPort := Must(cfg.Section("Interface").Key("ListenPort").Int())
	fmt.Println("Interface params:\n",
		"  PORT", listenPort, "\n",
		"  SK", base64.StdEncoding.EncodeToString(tunnel.Local.PrivateKey[:]), "\n",
		"  PK", base64.StdEncoding.EncodeToString(tunnel.Local.PublicKey[:]), "\n",
	)
	fmt.Println("Peer params:\n",
		"  SK", base64.StdEncoding.EncodeToString(tunnel.Remote.PrivateKey[:]), "\n",
		"  PK", base64.StdEncoding.EncodeToString(tunnel.Remote.PublicKey[:]), "\n",
	)

	host := net.UDPAddr{
		IP:   net.IPv4(0, 0, 0, 0),
		Port: listenPort,
	}
	fmt.Println("UDPAddr", host)

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
			if err := message.FromBytes(buffer[:n]); err != nil {
				fmt.Println("  Can't parse a message of type [HandshakeInit]", err)
				continue
			}

			fmt.Println("  Type", message.Type, "Sender", message.Sender, "ephemeral", message.Ephemeral, "static", message.Static, "ts", message.Timestamp)

			if err := tunnel.ProcessInitiateHandshakeMessage(message); err != nil {
				fmt.Println("  Error occurred on [HandshakeInit] message processing", err)
				continue
			}
			response, err := tunnel.CreateInitiateHandshakeResponse()
			if err != nil {
				fmt.Println("  Error occurred creating Handshake response", err)
			}
			bytes := response.ToBytes()
			tunnel.Stamper.Stamp(bytes)

			if _, err = bind.WriteToUDP(bytes, remoteAddr); err != nil {
				fmt.Println("  Error occurred on sending Handshake response", err)
			}
		}
	}
}
