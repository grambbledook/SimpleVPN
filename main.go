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

func main() {
	cfg := Must(ini.Load("config.conf"))

	publicKey := cfg.Section("Interface").Key("PublicKey").String()
	privateKey := cfg.Section("Interface").Key("PrivateKey").String()
	listenPort := Must(cfg.Section("Interface").Key("ListenPort").Int())
	fmt.Println("Interface params", publicKey, privateKey, listenPort)

	peerPublicKey := cfg.Section("Peer").Key("PublicKey").String()
	allowedIPs := cfg.Section("Peer").Key("AllowedIPs").Strings(" ")
	fmt.Println("Peer params", peerPublicKey, allowedIPs)

	hist := net.UDPAddr{
		IP:   net.IPv4(0, 0, 0, 0),
		Port: listenPort,
	}
	fmt.Println("UDPAddr", hist)

	peer := net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 52974,
	}

	bind := Must(net.ListenUDP("udp", &hist))
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
		message, err := protocol.FromBytes(buffer)
		if err != nil {
			fmt.Println("  Error", err)
		}
		fmt.Println("  Type", message.Type, "Sender", message.Sender, "ephemeral", message.Ephemeral, "static", message.Static, "ts", message.Timestamp)

		Must(bind.WriteToUDP(make([]byte, 120), &peer))
	}
}
