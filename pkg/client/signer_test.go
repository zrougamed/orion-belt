package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func genTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("wrap signer: %v", err)
	}
	return signer
}

// selfSignedCert builds a certificate "signed" by signer itself (a CA in
// name only, for test purposes) with the given validity window.
func selfSignedCert(t *testing.T, subject ssh.Signer, ca ssh.Signer, validAfter, validBefore time.Time) *ssh.Certificate {
	t.Helper()
	cert := &ssh.Certificate{
		Key:             subject.PublicKey(),
		Serial:          1,
		CertType:        ssh.UserCert,
		KeyId:           "alice",
		ValidPrincipals: []string{"alice"},
		ValidAfter:      uint64(validAfter.Unix()),
		ValidBefore:     uint64(validBefore.Unix()),
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatalf("SignCert: %v", err)
	}
	return cert
}

func TestLoadCachedCertSignerFreshCertReused(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "id_ed25519-cert.pub")

	key := genTestSigner(t)
	ca := genTestSigner(t)
	// 12h TTL, just issued — well within the renewal margin's "keep using it" zone.
	cert := selfSignedCert(t, key, ca, time.Now().Add(-time.Minute), time.Now().Add(12*time.Hour))
	if err := os.WriteFile(certPath, ssh.MarshalAuthorizedKey(cert), 0600); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	signer := loadCachedCertSigner(certPath, key)
	if signer == nil {
		t.Fatal("expected a fresh, valid cached cert to be reused")
	}
}

func TestLoadCachedCertSignerNearExpiryNotReused(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "id_ed25519-cert.pub")

	key := genTestSigner(t)
	ca := genTestSigner(t)
	// 12h TTL, issued 11.5h ago — inside the 20% renewal margin (< 2.4h remaining).
	cert := selfSignedCert(t, key, ca, time.Now().Add(-11*time.Hour-30*time.Minute), time.Now().Add(30*time.Minute))
	if err := os.WriteFile(certPath, ssh.MarshalAuthorizedKey(cert), 0600); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	if signer := loadCachedCertSigner(certPath, key); signer != nil {
		t.Fatal("expected a near-expiry cached cert to be treated as due for renewal, not reused")
	}
}

func TestLoadCachedCertSignerKeyMismatchNotReused(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "id_ed25519-cert.pub")

	certKey := genTestSigner(t)
	otherKey := genTestSigner(t) // simulates a rotated local key
	ca := genTestSigner(t)
	cert := selfSignedCert(t, certKey, ca, time.Now().Add(-time.Minute), time.Now().Add(12*time.Hour))
	if err := os.WriteFile(certPath, ssh.MarshalAuthorizedKey(cert), 0600); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	if signer := loadCachedCertSigner(certPath, otherKey); signer != nil {
		t.Fatal("expected a cert issued for a different keypair to be rejected")
	}
}

func TestLoadCachedCertSignerMissingFile(t *testing.T) {
	key := genTestSigner(t)
	if signer := loadCachedCertSigner(filepath.Join(t.TempDir(), "does-not-exist"), key); signer != nil {
		t.Fatal("expected nil when no cached cert file exists")
	}
}
