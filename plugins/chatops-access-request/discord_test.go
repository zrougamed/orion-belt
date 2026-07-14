package chatops

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestVerifyDiscordSignatureValid(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	timestamp := "1699999999"
	body := []byte(`{"type":1}`)
	message := append([]byte(timestamp), body...)
	sig := ed25519.Sign(priv, message)

	err = verifyDiscordSignature(hex.EncodeToString(pub), hex.EncodeToString(sig), timestamp, body)
	if err != nil {
		t.Fatalf("expected valid signature to verify, got: %v", err)
	}
}

func TestVerifyDiscordSignatureTampered(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	timestamp := "1699999999"
	body := []byte(`{"type":1}`)
	message := append([]byte(timestamp), body...)
	sig := ed25519.Sign(priv, message)

	// Tamper with the body after signing.
	tamperedBody := []byte(`{"type":3}`)
	if err := verifyDiscordSignature(hex.EncodeToString(pub), hex.EncodeToString(sig), timestamp, tamperedBody); err == nil {
		t.Fatalf("expected error for tampered body, got nil")
	}

	// Tamper with the signature.
	sigBytes, _ := hex.DecodeString(hex.EncodeToString(sig))
	sigBytes[0] ^= 0xFF
	if err := verifyDiscordSignature(hex.EncodeToString(pub), hex.EncodeToString(sigBytes), timestamp, body); err == nil {
		t.Fatalf("expected error for tampered signature, got nil")
	}

	// Wrong public key.
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if err := verifyDiscordSignature(hex.EncodeToString(otherPub), hex.EncodeToString(sig), timestamp, body); err == nil {
		t.Fatalf("expected error for wrong public key, got nil")
	}
}

func TestVerifyDiscordSignatureMalformed(t *testing.T) {
	if err := verifyDiscordSignature("not-hex", "not-hex-either", "123", []byte("body")); err == nil {
		t.Fatalf("expected error for malformed public key/signature, got nil")
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if err := verifyDiscordSignature(hex.EncodeToString(pub), "deadbeef", "123", []byte("body")); err == nil {
		t.Fatalf("expected error for malformed signature length, got nil")
	}
}
