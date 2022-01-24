package socks5

import (
	"bytes"
	"encoding/binary"
	"io"
	"log"
	"net"
	"os"
	"testing"
	"time"
)

func TestSOCKS5_Connect(t *testing.T) {
	errCh := make(chan error, 1)

	// Create a local listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer l.Close()
	lAddr := l.Addr().(*net.TCPAddr)

	go func() {
		conn, err := l.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()

		buf := make([]byte, 4)
		if _, err := io.ReadAtLeast(conn, buf, 4); err != nil {
			errCh <- err
			return
		}

		if !bytes.Equal(buf, []byte("ping")) {
			errCh <- err
			return
		}
		_, err = conn.Write([]byte("pong"))
		errCh <- err
	}()

	// Create a socks server
	creds := StaticCredentials{
		"foo": "bar",
	}
	cator := UserPassAuthenticator{Credentials: creds}
	conf := &Config{
		AuthMethods: []Authenticator{cator},
		Logger:      log.New(os.Stdout, "", log.LstdFlags),
	}
	serv, err := New(conf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Start listening
	sListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer sListener.Close()

	go func() {
		serv.Serve(sListener)
	}()

	time.Sleep(10 * time.Millisecond)

	// Get a local conn
	conn, err := net.Dial("tcp", sListener.Addr().String())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()
	// Connect, auth and connec to local
	req := bytes.NewBuffer(nil)
	req.Write([]byte{5})
	req.Write([]byte{2, NoAuth, UserPassAuth})
	req.Write([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'r'})
	req.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1})

	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, uint16(lAddr.Port))
	_, err = req.Write(port)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	// Send a ping
	_, err = req.Write([]byte("ping"))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	// Send all the bytes
	_, err = conn.Write(req.Bytes())
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Verify response
	expected := []byte{
		socks5Version, UserPassAuth,
		1, authSuccess,
		5,
		0,
		0,
		1,
		127, 0, 0, 1,
		0, 0,
		'p', 'o', 'n', 'g',
	}
	out := make([]byte, len(expected))

	err = conn.SetDeadline(time.Now().Add(time.Second))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if _, err := io.ReadAtLeast(conn, out, len(out)); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Ignore the port
	out[12] = 0
	out[13] = 0

	if !bytes.Equal(out, expected) {
		t.Fatalf("bad: %v", out)
	}

	// Check server errors
	err = <-errCh
	if err != nil {
		t.Fatalf("err: %v", err)
	}
}
