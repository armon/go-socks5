package socks5

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

type MockConn struct {
	buf bytes.Buffer
}

func (m *MockConn) Write(b []byte) (int, error) {
	return m.buf.Write(b)
}

func (m *MockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: []byte{127, 0, 0, 1}, Port: 65432}
}

func TestRequest_Connect(t *testing.T) {
	errCh := make(chan error, 1)

	// Create a local listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
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
	lAddr := l.Addr().(*net.TCPAddr)

	// Make server
	s := &Server{config: &Config{
		Rules:    PermitAll(),
		Resolver: DNSResolver{},
		Logger:   log.New(os.Stdout, "", log.LstdFlags),
	}}

	// Create the connect request
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1})

	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, uint16(lAddr.Port))
	buf.Write(port)

	// Send a ping
	buf.Write([]byte("ping"))

	// Handle the request
	resp := &MockConn{}
	req, err := NewRequest(buf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if err := s.handleRequest(req, resp); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Verify response
	out := resp.buf.Bytes()
	expected := []byte{
		5,
		0,
		0,
		1,
		127, 0, 0, 1,
		0, 0,
		'p', 'o', 'n', 'g',
	}

	// Ignore the port for both
	out[8] = 0
	out[9] = 0

	if !bytes.Equal(out, expected) {
		t.Fatalf("bad: %v %v", out, expected)
	}
	// Check server errors
	err = <-errCh
	if err != nil {
		t.Fatalf("err: %v", err)
	}
}

func TestRequest_Connect_RuleFail(t *testing.T) {
	errCh := make(chan error, 1)

	// Create a local listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	go func() {
		conn, err := l.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()

		errCh <- fmt.Errorf("unexpected connection received")
	}()
	lAddr := l.Addr().(*net.TCPAddr)

	// Make server
	s := &Server{config: &Config{
		Rules:    PermitNone(),
		Resolver: DNSResolver{},
		Logger:   log.New(os.Stdout, "", log.LstdFlags),
	}}

	// Create the connect request
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1})

	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, uint16(lAddr.Port))
	buf.Write(port)

	// Send a ping
	buf.Write([]byte("ping"))

	// Handle the request
	resp := &MockConn{}
	req, err := NewRequest(buf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if err := s.handleRequest(req, resp); !strings.Contains(err.Error(), "blocked by rules") {
		t.Fatalf("err: %v", err)
	}

	// Verify response
	out := resp.buf.Bytes()
	expected := []byte{
		5,
		2,
		0,
		1,
		0, 0, 0, 0,
		0, 0,
	}

	if !bytes.Equal(out, expected) {
		t.Fatalf("bad: %v %v", out, expected)
	}
	// Check server didn't receive any connection
	select {
	case err = <-errCh:
		t.Fatalf("err: %v", err)
	case <-time.After(time.Millisecond * 500):
	}
}
