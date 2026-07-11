package recording

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCryptoRoundTrip(t *testing.T) {
	c, err := NewCrypto("this-is-a-32-byte-secret-key!!!!", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Enabled() {
		t.Fatal("expected enabled")
	}
	plain := []byte("session recording content")
	enc, err := c.Encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	if string(enc) == string(plain) {
		t.Fatal("expected ciphertext")
	}
	out, err := c.Decrypt(enc)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(plain) {
		t.Fatalf("got %q", out)
	}
}

func TestRetention(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "old.txt")
	fresh := filepath.Join(dir, "fresh.txt")
	if err := os.WriteFile(old, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fresh, []byte("y"), 0600); err != nil {
		t.Fatal(err)
	}
	past := time.Now().AddDate(0, 0, -10)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	n, err := EnforceRetention(dir, 5, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("deleted %d want 1", n)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("old file should be gone")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatal("fresh file should remain")
	}
}
