package common

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestHostKeyCallbackTOFU(t *testing.T) {
	dir := t.TempDir()
	kh := filepath.Join(dir, "known_hosts")

	cb, err := NewHostKeyCallback(HostKeyConfig{
		KnownHosts:            kh,
		StrictHostKeyChecking: "ask",
	}, nil)
	if err != nil {
		t.Fatalf("NewHostKeyCallback: %v", err)
	}

	key := mustTestPublicKey(t)
	addr := &mockAddr{s: "127.0.0.1:2222"}
	if err := cb("gateway.example.com:2222", addr, key); err != nil {
		t.Fatalf("first connect (TOFU): %v", err)
	}

	data, err := os.ReadFile(kh)
	if err != nil || len(data) == 0 {
		t.Fatalf("known_hosts not written: %v %q", err, data)
	}

	if err := cb("gateway.example.com:2222", addr, key); err != nil {
		t.Fatalf("second connect: %v", err)
	}
}

func TestHostKeyCallbackStrictRejectsUnknown(t *testing.T) {
	dir := t.TempDir()
	kh := filepath.Join(dir, "known_hosts")

	cb, err := NewHostKeyCallback(HostKeyConfig{
		KnownHosts:            kh,
		StrictHostKeyChecking: "yes",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	err = cb("gateway.example.com:2222", &mockAddr{s: "127.0.0.1:2222"}, mustTestPublicKey(t))
	if err == nil {
		t.Fatal("expected rejection for unknown host")
	}
}

type mockAddr struct{ s string }

func (m *mockAddr) Network() string { return "tcp" }
func (m *mockAddr) String() string  { return m.s }

func mustTestPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}
