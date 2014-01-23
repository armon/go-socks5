package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"
)

const (
	connectCommand   = uint8(1)
	bindCommand      = uint8(2)
	associateCommand = uint8(3)
	ipv4Address      = uint8(1)
	fqdnAddress      = uint8(3)
	ipv6Address      = uint8(4)
)

const (
	successReply uint8 = 0
	serverFailure
	ruleFailure
	networkUnreachable
	hostUnreachable
	connectionRefused
	ttlExpired
	commandNotSupported
	addrTypeNotSupported
)

var (
	unrecognizedAddrType = fmt.Errorf("Unrecognized address type")
)

// addrSpec is used to return the target addrSpec
// which may be specified as IPv4, IPv6, or a FQDN
type addrSpec struct {
	fqdn string
	ip   net.IP
	port int
}

type conn interface {
	Write([]byte) (int, error)
	RemoteAddr() net.Addr
}

func (a *addrSpec) String() string {
	if a.fqdn != "" {
		return fmt.Sprintf("%s (%s):%d", a.fqdn, a.ip, a.port)
	}
	return fmt.Sprintf("%s:%d", a.ip, a.port)
}

// handleRequest is used for request processing after authentication
func (s *Server) handleRequest(conn conn, bufConn io.Reader) error {
	// Read the version byte
	header := []byte{0, 0, 0}
	if _, err := io.ReadAtLeast(bufConn, header, 3); err != nil {
		return fmt.Errorf("Failed to get command version: %v", err)
	}

	// Ensure we are compatible
	if header[0] != socks5Version {
		return fmt.Errorf("Unsupported command version: %v", header[0])
	}

	// Read in the destination address
	dest, err := readAddrSpec(bufConn)
	if err != nil {
		if err == unrecognizedAddrType {
			if err := sendReply(conn, addrTypeNotSupported, nil); err != nil {
				return fmt.Errorf("Failed to send reply: %v", err)
			}
		}
		return fmt.Errorf("Failed to read destination address: %v", err)
	}

	// Resolve the address if we have a FQDN
	if dest.fqdn != "" {
		addr, err := s.config.Resolver.Resolve(dest.fqdn)
		if err != nil {
			if err := sendReply(conn, hostUnreachable, nil); err != nil {
				return fmt.Errorf("Failed to send reply: %v", err)
			}
			return fmt.Errorf("Failed to resolve destination '%v': %v", dest.fqdn, err)
		}
		dest.ip = addr
	}

	// Switch on the command
	switch header[1] {
	case connectCommand:
		return s.handleConnect(conn, bufConn, dest)
	case bindCommand:
		return s.handleBind(conn, bufConn, dest)
	case associateCommand:
		return s.handleAssociate(conn, bufConn, dest)
	default:
		if err := sendReply(conn, commandNotSupported, nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Unsupported command: %v", header[1])
	}
}

// handleConnect is used to handle a connect command
func (s *Server) handleConnect(conn conn, bufConn io.Reader, dest *addrSpec) error {
	// Check if this is allowed
	client := conn.RemoteAddr().(*net.TCPAddr)
	if !s.config.Rules.AllowConnect(dest.ip, dest.port, client.IP, client.Port) {
		if err := sendReply(conn, ruleFailure, dest); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Connect to %v blocked by rules", dest)
	}

	// Attempt to connect
	addr := net.TCPAddr{IP: dest.ip, Port: dest.port}
	target, err := net.DialTCP("tcp", nil, &addr)
	if err != nil {
		msg := err.Error()
		resp := hostUnreachable
		if strings.Contains(msg, "refused") {
			resp = connectionRefused
		} else if strings.Contains(msg, "network is unreachable") {
			resp = networkUnreachable
		}
		if err := sendReply(conn, resp, dest); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Connect to %v failed: %v", dest, err)
	}
	defer target.Close()

	// Send success
	if err := sendReply(conn, successReply, dest); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}

	// Start proxying
	errCh := make(chan error, 2)
	go proxy("target", target, bufConn, errCh)
	go proxy("client", conn, target, errCh)

	// Wait
	select {
	case e := <-errCh:
		return e
	}
}

// handleBind is used to handle a connect command
func (s *Server) handleBind(conn conn, bufConn io.Reader, dest *addrSpec) error {
	// Check if this is allowed
	client := conn.RemoteAddr().(*net.TCPAddr)
	if !s.config.Rules.AllowBind(dest.ip, dest.port, client.IP, client.Port) {
		if err := sendReply(conn, ruleFailure, dest); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Bind to %v blocked by rules", dest)
	}

	// TODO: Support bind
	if err := sendReply(conn, commandNotSupported, nil); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}
	return nil
}

// handleAssociate is used to handle a connect command
func (s *Server) handleAssociate(conn conn, bufConn io.Reader, dest *addrSpec) error {
	// Check if this is allowed
	client := conn.RemoteAddr().(*net.TCPAddr)
	if !s.config.Rules.AllowAssociate(dest.ip, dest.port, client.IP, client.Port) {
		if err := sendReply(conn, ruleFailure, dest); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Associate to %v blocked by rules", dest)
	}

	// TODO: Support associate
	if err := sendReply(conn, commandNotSupported, nil); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}
	return nil
}

// readAddrSpec is used to read addrSpec.
// Expects an address type byte, follwed by the address and port
func readAddrSpec(r io.Reader) (*addrSpec, error) {
	d := &addrSpec{}

	// Get the address type
	addrType := []byte{0}
	if _, err := r.Read(addrType); err != nil {
		return nil, err
	}

	// Handle on a per type basis
	switch addrType[0] {
	case ipv4Address:
		addr := make([]byte, 4)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return nil, err
		}
		d.ip = net.IP(addr)

	case ipv6Address:
		addr := make([]byte, 16)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return nil, err
		}
		d.ip = net.IP(addr)

	case fqdnAddress:
		if _, err := r.Read(addrType); err != nil {
			return nil, err
		}
		addrLen := int(addrType[0])
		fqdn := make([]byte, addrLen)
		if _, err := io.ReadAtLeast(r, fqdn, addrLen); err != nil {
			return nil, err
		}
		d.fqdn = string(fqdn)

	default:
		return nil, unrecognizedAddrType
	}

	// Read the port
	port := []byte{0, 0}
	if _, err := io.ReadAtLeast(r, port, 2); err != nil {
		return nil, err
	}
	d.port = int(binary.BigEndian.Uint16(port))

	return d, nil
}

// sendReply is used to send a reply message
func sendReply(w io.Writer, resp uint8, addr *addrSpec) error {
	// Format the address
	var addrType uint8
	var addrBody []byte
	switch {
	case addr == nil:
		addrType = 0
		addrBody = nil

	case addr.fqdn != "":
		addrType = fqdnAddress
		addrBody = append([]byte{byte(len(addr.fqdn))}, addr.fqdn...)

	case addr.ip.To4() != nil:
		addrType = ipv4Address
		addrBody = []byte(addr.ip.To4())

	case addr.ip.To16() != nil:
		addrType = ipv6Address
		addrBody = []byte(addr.ip.To16())

	default:
		return fmt.Errorf("Failed to format address: %v", addr)
	}

	// Format the message
	msg := make([]byte, 6+len(addrBody))
	msg[0] = socks5Version
	msg[1] = resp
	msg[2] = 0 // Reserved
	msg[3] = addrType
	copy(msg[4:], addrBody)
	binary.BigEndian.PutUint16(msg[4+len(addrBody):], uint16(addr.port))

	// Send the message
	_, err := w.Write(msg)
	return err
}

// proxy is used to suffle data from src to destination, and sends errors
// down a dedicated channel
func proxy(name string, dst io.Writer, src io.Reader, errCh chan error) {
	// Copy
	n, err := io.Copy(dst, src)

	// Log, and sleep. This is jank but allows the otherside
	// to finish a pending copy
	log.Printf("[DEBUG] socks: Copied %d bytes to %s", n, name)
	time.Sleep(10 * time.Millisecond)

	// Send any errors
	errCh <- err
}
