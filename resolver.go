package socks5

import (
	"net"
)

// NameResolver is used to implement custom name resolution
type NameResolver interface {
	Resolve(name string) (*net.IPAddr, error)
}

// DNSResolver uses the system DNS to resolve host names
type DNSResolver struct{}

func (d DNSResolver) Resolve(name string) (*net.IPAddr, error) {
	return net.ResolveIPAddr("ip", name)
}
