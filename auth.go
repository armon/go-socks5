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

type Authenticator interface {
	Authenticate(reader io.Reader, writer io.Writer) error
	GetCode() uint8
}

// NoAuthAuthenticator is used to handle the "No Authentication" mode
type NoAuthAuthenticator struct {}

func (a NoAuthAuthenticator) GetCode() uint8 {
	return noAuth
}

func (a NoAuthAuthenticator) Authenticate(reader io.Reader, writer io.Writer) error {
	_, err := writer.Write([]byte{socks5Version, noAuth})
	return err
}

// UserPassAuthenticator is used to handle username/password based
// authentication
type UserPassAuthenticator struct {
	Credentials CredentialStore
}

func (a UserPassAuthenticator) GetCode() uint8 {
	return userPassAuth
}

func (a UserPassAuthenticator) Authenticate(reader io.Reader, writer io.Writer) error {
	// Tell the client to use user/pass auth
	if _, err := writer.Write([]byte{socks5Version, userPassAuth}); err != nil {
		return err
	}

	// Get the version and username length
	header := []byte{0, 0}
	if _, err := io.ReadAtLeast(reader, header, 2); err != nil {
		return err
	}

	// Ensure we are compatible
	if header[0] != userAuthVersion {
		return fmt.Errorf("Unsupported auth version: %v", header[0])
	}

	// Get the user name
	userLen := int(header[1])
	user := make([]byte, userLen)
	if _, err := io.ReadAtLeast(reader, user, userLen); err != nil {
		return err
	}

	// Get the password length
	if _, err := reader.Read(header[:1]); err != nil {
		return err
	}

	// Get the password
	passLen := int(header[0])
	pass := make([]byte, passLen)
	if _, err := io.ReadAtLeast(reader, pass, passLen); err != nil {
		return err
	}

	// Verify the password
	if a.Credentials.Valid(string(user), string(pass)) {
		if _, err := writer.Write([]byte{userAuthVersion, authSuccess}); err != nil {
			return err
		}
	} else {
		if _, err := writer.Write([]byte{userAuthVersion, authFailure}); err != nil {
			return err
		}
		return UserAuthFailed
	}

	// Done
	return nil

}



// authenticate is used to handle connection authentication
func (s *Server) authenticate(conn io.Writer, bufConn io.Reader) error {
	// Get the methods
	methods, err := readMethods(bufConn)
	if err != nil {
		return fmt.Errorf("Failed to get auth methods: %v", err)
	}

	// Select a usable method
	for _, method := range methods {
		cator, found := s.authMethods[method]
		if found {
			return cator.Authenticate(bufConn, conn)
		}
	}

	// No usable method found
	return noAcceptableAuth(conn)
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
