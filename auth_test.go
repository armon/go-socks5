package socks5

import (
	"bytes"
	"testing"
)

func TestNoAuth(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{1, noAuth})
	var resp bytes.Buffer

	s, _ := New(&Config{})
	if err := s.authenticate(&resp, req); err != nil {
		t.Fatalf("err: %v", err)
	}

	out := resp.Bytes()
	if !bytes.Equal(out, []byte{socks5Version, noAuth}) {
		t.Fatalf("bad: %v", out)
	}
}

func TestPasswordAuth_Valid(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{2, noAuth, userPassAuth})
	req.Write([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'r'})
	var resp bytes.Buffer

	cred := StaticCredentials{
		"foo": "bar",
	}
	
	cator := UserPassAuthenticator{Credentials: cred}

	s, _ := New(&Config{AuthMethods:[]Authenticator{cator}})

	if err := s.authenticate(&resp, req); err != nil {
		t.Fatalf("err: %v", err)
	}

	out := resp.Bytes()
	if !bytes.Equal(out, []byte{socks5Version, userPassAuth, 1, authSuccess}) {
		t.Fatalf("bad: %v", out)
	}
}

func TestPasswordAuth_Invalid(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{2, noAuth, userPassAuth})
	req.Write([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'z'})
	var resp bytes.Buffer

	cred := StaticCredentials{
		"foo": "bar",
	}
	cator := UserPassAuthenticator{Credentials: cred}
	s, _ := New(&Config{AuthMethods:[]Authenticator{cator}})
	if err := s.authenticate(&resp, req); err != UserAuthFailed {
		t.Fatalf("err: %v", err)
	}

	out := resp.Bytes()
	if !bytes.Equal(out, []byte{socks5Version, userPassAuth, 1, authFailure}) {
		t.Fatalf("bad: %v", out)
	}
}

func TestNoSupportedAuth(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{1, noAuth})
	var resp bytes.Buffer

	cred := StaticCredentials{
		"foo": "bar",
	}
	cator := UserPassAuthenticator{Credentials: cred}

	s, _ := New(&Config{AuthMethods:[]Authenticator{cator}})
	if err := s.authenticate(&resp, req); err != NoSupportedAuth {
		t.Fatalf("err: %v", err)
	}

	out := resp.Bytes()
	if !bytes.Equal(out, []byte{socks5Version, noAcceptable}) {
		t.Fatalf("bad: %v", out)
	}
}
