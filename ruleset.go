package socks5

import (
	"net"
)

// RuleSet is used to provide custom rules to allow or prohibit actions
type RuleSet interface {
	// AllowConnect is used to filter connect requests
	AllowConnect(dstIP net.IP, dstPort int, srcIP net.IP, srcPort int) bool

	// AllowBind is used to filter bind requests
	AllowBind(dstIP net.IP, dstPort int, srcIP net.IP, srcPort int) bool

	// AllowAssociate is used to filter associate requests
	AllowAssociate(dstIP net.IP, dstPort int, srcIP net.IP, srcPort int) bool
}

// PermitAll returns a RuleSet which allows all types of connections
func PermitAll() RuleSet {
	return &PermitCommand{true, true, true}
}

// PermitNone returns a RuleSet which disallows all types of connections
func PermitNone() RuleSet {
	return &PermitCommand{false, false, false}
}

// PermitCommand is an implementation of the RuleSet which
// enables filtering supported commands
type PermitCommand struct {
	EnableConnect   bool
	EnableBind      bool
	EnableAssociate bool
}

func (p *PermitCommand) AllowConnect(net.IP, int, net.IP, int) bool {
	return p.EnableConnect
}

func (p *PermitCommand) AllowBind(net.IP, int, net.IP, int) bool {
	return p.EnableBind
}

func (p *PermitCommand) AllowAssociate(net.IP, int, net.IP, int) bool {
	return p.EnableAssociate
}
