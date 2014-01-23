package socks5

import (
	"fmt"
	"io"
)

const (
	noAuth          = uint8(0)
	noAcceptable    = uint8(255)
	userPassAuth    = uint8(2)
	userAuthVersion = uint8(1)
	authSuccess     = uint8(0)
	authFailure     = uint8(1)
)

var (
	UserAuthFailed  = fmt.Errorf("User authentication failed")
	NoSupportedAuth = fmt.Errorf("No supported authentication mechanism")
)

// authenticate is used to handle connection authentication
func (s *Server) authenticate(conn io.Writer, bufConn io.Reader) error {
	// Get the methods
	methods, err := readMethods(bufConn)
	if err != nil {
		return fmt.Errorf("Failed to get auth methods: %v", err)
	}

	// Determine what is supported
	supportUserPass := s.config.Credentials != nil

	// Select a usable method
	for _, method := range methods {
		if method == noAuth && !supportUserPass {
			return noAuthMode(conn)
		}
		if method == userPassAuth && supportUserPass {
			return s.userPassAuth(conn, bufConn)
		}
	}

	// No usable method found
	return noAcceptableAuth(conn)
}

// userPassAuth is used to handle username/password based
// authentication
func (s *Server) userPassAuth(conn io.Writer, bufConn io.Reader) error {
	// Tell the client to use user/pass auth
	if _, err := conn.Write([]byte{socks5Version, userPassAuth}); err != nil {
		return err
	}

	// Get the version and username length
	header := []byte{0, 0}
	if _, err := io.ReadAtLeast(bufConn, header, 2); err != nil {
		return err
	}

	// Ensure we are compatible
	if header[0] != userAuthVersion {
		return fmt.Errorf("Unsupported auth version: %v", header[0])
	}

	// Get the user name
	userLen := int(header[1])
	user := make([]byte, userLen)
	if _, err := io.ReadAtLeast(bufConn, user, userLen); err != nil {
		return err
	}

	// Get the password length
	if _, err := bufConn.Read(header[:1]); err != nil {
		return err
	}

	// Get the password
	passLen := int(header[0])
	pass := make([]byte, passLen)
	if _, err := io.ReadAtLeast(bufConn, pass, passLen); err != nil {
		return err
	}

	// Verify the password
	if s.config.Credentials.Valid(string(user), string(pass)) {
		if _, err := conn.Write([]byte{userAuthVersion, authSuccess}); err != nil {
			return err
		}
	} else {
		if _, err := conn.Write([]byte{userAuthVersion, authFailure}); err != nil {
			return err
		}
		return UserAuthFailed
	}

	// Done
	return nil
}

// noAuth is used to handle the "No Authentication" mode
func noAuthMode(conn io.Writer) error {
	_, err := conn.Write([]byte{socks5Version, noAuth})
	return err
}

// noAcceptableAuth is used to handle when we have no eligible
// authentication mechanism
func noAcceptableAuth(conn io.Writer) error {
	conn.Write([]byte{socks5Version, noAcceptable})
	return NoSupportedAuth
}

// readMethods is used to read the number of methods
// and proceeding auth methods
func readMethods(r io.Reader) ([]byte, error) {
	header := []byte{0}
	if _, err := r.Read(header); err != nil {
		return nil, err
	}

	numMethods := int(header[0])
	methods := make([]byte, numMethods)
	_, err := io.ReadAtLeast(r, methods, numMethods)
	return methods, err
}
