package chatops

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"
	"time"
)

func makeSlackSignature(secret, timestamp, body string) string {
	base := "v0:" + timestamp + ":" + body
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(base))
	return "v0=" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerifySlackSignatureValid(t *testing.T) {
	secret := "slack-signing-secret"
	body := `payload={"actions":[{"action_id":"approve"}]}`
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := makeSlackSignature(secret, ts, body)

	if err := verifySlackSignature(secret, sig, ts, []byte(body)); err != nil {
		t.Fatalf("expected valid signature to verify, got: %v", err)
	}
}

func TestVerifySlackSignatureTampered(t *testing.T) {
	secret := "slack-signing-secret"
	body := `payload={"actions":[{"action_id":"approve"}]}`
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := makeSlackSignature(secret, ts, body)

	// Tamper with the body after computing the signature.
	tamperedBody := body + "tampered"
	if err := verifySlackSignature(secret, sig, ts, []byte(tamperedBody)); err == nil {
		t.Fatalf("expected error for tampered body, got nil")
	}

	// Tamper with the signature itself.
	tamperedSig := sig[:len(sig)-4] + "0000"
	if err := verifySlackSignature(secret, tamperedSig, ts, []byte(body)); err == nil {
		t.Fatalf("expected error for tampered signature, got nil")
	}

	// Wrong secret.
	if err := verifySlackSignature("wrong-secret", sig, ts, []byte(body)); err == nil {
		t.Fatalf("expected error for wrong secret, got nil")
	}
}

func TestVerifySlackSignatureExpiredTimestamp(t *testing.T) {
	secret := "slack-signing-secret"
	body := `payload={"actions":[{"action_id":"deny"}]}`
	oldTs := strconv.FormatInt(time.Now().Add(-10*time.Minute).Unix(), 10)
	sig := makeSlackSignature(secret, oldTs, body)

	if err := verifySlackSignature(secret, sig, oldTs, []byte(body)); err == nil {
		t.Fatalf("expected error for stale timestamp, got nil")
	}
}

func TestVerifySlackSignatureMissingHeaders(t *testing.T) {
	if err := verifySlackSignature("secret", "", "", []byte("body")); err == nil {
		t.Fatalf("expected error for missing headers, got nil")
	}
}
