package socks5

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

const (
	socks5Version = uint8(5)
)

type Connector func(net, address string) (net.Conn, error)

// Config is used to setup and configure a Server
type Config struct {
	// AuthMethods can be provided to implement custom authentication
	// By default, "auth-less" mode is enabled.
	// For password-based auth use UserPassAuthenticator.
	AuthMethods []Authenticator

	// If provided, username/password authentication is enabled,
	// by appending a UserPassAuthenticator to AuthMethods. If not provided,
	// and AUthMethods is nil, then "auth-less" mode is enabled.
	Credentials CredentialStore

	// Resolver can be provided to do custom name resolution.
	// Defaults to DNSResolver if not provided.
	Resolver NameResolver

	// Rules is provided to enable custom logic around permitting
	// various commands. If not provided, PermitAll is used.
	Rules RuleSet

	// Rewriter can be used to transparently rewrite addresses.
	// This is invoked before the RuleSet is invoked.
	// Defaults to NoRewrite.
	Rewriter AddressRewriter

	// BindIP is used for bind or udp associate
	BindIP net.IP

	// ConnectFunc may be used as function which establishes connection
	// with remote host while request handling
	ConnectFunc Connector
}

// Server is reponsible for accepting connections and handling
// the details of the SOCKS5 protocol
type Server struct {
	config      *Config
	authMethods map[uint8]Authenticator
	ch          chan bool
}

// New creates a new Server and potentially returns an error
func New(conf *Config) (*Server, error) {
	// Ensure we have at least one authentication method enabled
	if len(conf.AuthMethods) == 0 {
		if conf.Credentials != nil {
			conf.AuthMethods = []Authenticator{&UserPassAuthenticator{conf.Credentials}}
		} else {
			conf.AuthMethods = []Authenticator{&NoAuthAuthenticator{}}
		}
	}

	// Ensure we have a DNS resolver
	if conf.Resolver == nil {
		conf.Resolver = DNSResolver{}
	}

	// Ensure we have a rule set
	if conf.Rules == nil {
		conf.Rules = PermitAll()
	}

	if conf.ConnectFunc == nil {
		conf.ConnectFunc = net.Dial
	}

	server := &Server{
		config: conf,
		ch:     make(chan bool),
	}

	server.authMethods = make(map[uint8]Authenticator)

	for _, a := range conf.AuthMethods {
		server.authMethods[a.GetCode()] = a
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
	if ln, ok := l.(*net.TCPListener); ok {
		return s.asyncServe(ln)
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go s.ServeConn(conn)
	}
	return nil
}

func (s *Server) asyncServe(l *net.TCPListener) error {
	var wg sync.WaitGroup
	var wait bool
	for {
		select {
		case wait = <-s.ch:
		default:
			l.SetDeadline(time.Now().Add(1e9))
			conn, err := l.Accept()
			if err != nil {
				if e, ok := err.(net.Error); ok && e.Timeout() {
					continue
				}
				return err
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				s.ServeConn(conn)
			}()
			continue
		}
		break
	}
	if wait {
		log.Println("Waiting for established connections...")
		wg.Wait()
	}
	l.Close()
	return nil
}

func (s *Server) Stop(wait bool) {
	s.ch <- wait
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
