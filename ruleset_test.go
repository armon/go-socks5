package socks5

import (
	"testing"
)

func TestPermitCommand(t *testing.T) {
	r := &PermitCommand{true, false, false}

	if !r.AllowConnect(nil, 500, nil, 1000) {
		t.Fatalf("expect connect")
	}

	if r.AllowBind(nil, 500, nil, 1000) {
		t.Fatalf("do not expect bind")
	}

	if r.AllowAssociate(nil, 500, nil, 1000) {
		t.Fatalf("do not expect associate")
	}
}
