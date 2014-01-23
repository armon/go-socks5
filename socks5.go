package socks5

import (
	"bufio"
	"fmt"
	"log"
	"net"
)

const (
	socks5Version = uint8(5)
)

// Config is used to setup and configure a Server
type Config struct {
	// If provided, username/password authentication is enabled
	// otherwise, non-authenticated mode is allowed
	Credentials CredentialStore

	// Resolver can be provided to do custom name resolution.
	// Defaults to DNSResolver if not provided.
	Resolver NameResolver

	// Rules is provided to enable custom logic around permitting
	// various commands. If not provided, PermitAll is used.
	Rules RuleSet

	// BindIP is used for bind or udp associate
	BindIP net.IP
}

// Server is reponsible for accepting connections and handling
// the details of the SOCKS5 protocol
type Server struct {
	config *Config
}

// New creates a new Server and potentially returns an error
func New(conf *Config) (*Server, error) {
	// Ensure we have a DNS resolver
	if conf.Resolver == nil {
		conf.Resolver = DNSResolver{}
	}

	// Ensure we have a rule set
	if conf.Rules == nil {
		conf.Rules = PermitAll()
	}

	server := &Server{
		config: conf,
	}
	return server, nil
}

// ListenAndServe is used to create a listener and serve on it
func (s *Server) ListenAndServe(network, addr string) error {
	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	return s.Serve(l)
}

// Serve is used to serve connections from a listener
func (s *Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go s.ServeConn(conn)
	}
	return nil
}

// ServeConn is used to serve a single connection.
func (s *Server) ServeConn(conn net.Conn) error {
	defer conn.Close()
	bufConn := bufio.NewReader(conn)

	// Read the version byte
	version := []byte{0}
	if _, err := bufConn.Read(version); err != nil {
		log.Printf("[ERR] socks: Failed to get version byte: %v", err)
		return err
	}

	// Ensure we are compatible
	if version[0] != socks5Version {
		err := fmt.Errorf("Unsupported SOCKS version: %v", version)
		log.Printf("[ERR] socks: %v", err)
		return err
	}

	// Authenticate the connection
	if err := s.authenticate(conn, bufConn); err != nil {
		err = fmt.Errorf("Failed to authenticate: %v", err)
		log.Printf("[ERR] socks: %v", err)
		return err
	}

	// Process the client request
	if err := s.handleRequest(conn, bufConn); err != nil {
		err = fmt.Errorf("Failed to handle request: %v", err)
		log.Printf("[ERR] socks: %v", err)
		return err
	}

	return nil
}
