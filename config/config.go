package config

type Interface struct {
	PublicKey  string
	PrivateKey string
}

type Network struct {
	port int
}

type Peer struct {
	PublicKey  string
	AllowedIps []string
	Endpoint   string
}
