package internal

import (
	"net"
	"testing"
)

func TestHysteria2Authenticator(t *testing.T) {
	authenticator := hysteria2Authenticator{password: "secret"}

	ok, id := authenticator.Authenticate(nil, "secret", 0)
	if !ok || id != "usque" {
		t.Fatalf("valid password authenticated as ok=%v, id=%q", ok, id)
	}

	ok, id = authenticator.Authenticate(nil, "wrong", 0)
	if ok || id != "" {
		t.Fatalf("invalid password authenticated as ok=%v, id=%q", ok, id)
	}
}

func TestConnectedHysteria2UDPConn(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()

	conn := connectedHysteria2UDPConn{Conn: client}
	go func() {
		_, _ = peer.Write([]byte("reply"))
	}()

	buf := make([]byte, 16)
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom failed: %v", err)
	}
	if got := string(buf[:n]); got != "reply" {
		t.Fatalf("ReadFrom returned %q, want reply", got)
	}
	if addr == "" {
		t.Fatal("ReadFrom returned an empty remote address")
	}

	go func() {
		readBuf := make([]byte, 16)
		_, _ = peer.Read(readBuf)
	}()
	if _, err := conn.WriteTo([]byte("request"), "ignored.example:53"); err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}
}
