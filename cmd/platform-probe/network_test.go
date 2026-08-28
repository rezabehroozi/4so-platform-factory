package main

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

func TestServeTCPAcceptsProbeConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() { done <- serveTCP(listener) }()
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	_ = conn.Close()
	if err != nil || strings.TrimSpace(line) != "4so-platform-probe" {
		t.Fatalf("line=%q err=%v", line, err)
	}
	_ = listener.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("server did not stop after listener close")
	}
}
