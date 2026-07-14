package chatops

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestMagicLinkRoundTrip(t *testing.T) {
	secret := "test-secret"
	link, err := signMagicLink("https://example.com/base", secret, "req-123", "approve")
	if err != nil {
		t.Fatalf("signMagicLink: %v", err)
	}
	if !strings.HasPrefix(link, "https://example.com/base/approve?token=") {
		t.Fatalf("unexpected link shape: %s", link)
	}

	token := strings.TrimPrefix(link, "https://example.com/base/approve?token=")
	claims, err := verifyMagicLink(secret, token)
	if err != nil {
		t.Fatalf("verifyMagicLink: %v", err)
	}
	if claims.RequestID != "req-123" || claims.Action != "approve" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestMagicLinkTampered(t *testing.T) {
	secret := "test-secret"
	link, err := signMagicLink("https://example.com/base", secret, "req-123", "deny")
	if err != nil {
		t.Fatalf("signMagicLink: %v", err)
	}
	token := strings.TrimPrefix(link, "https://example.com/base/deny?token=")

	// Tamper with the payload portion (before the ".").
	dot := strings.LastIndex(token, ".")
	if dot < 0 {
		t.Fatalf("token missing separator: %s", token)
	}
	tampered := token[:dot] + "AAAA" + token[dot:]
	if _, err := verifyMagicLink(secret, tampered); err == nil {
		t.Fatalf("expected error for tampered token, got nil")
	}

	// Tamper with the signature portion.
	tamperedSig := token[:dot+1] + "0000000000000000000000000000000000000000000000000000000000000000"
	if _, err := verifyMagicLink(secret, tamperedSig); err == nil {
		t.Fatalf("expected error for tampered signature, got nil")
	}

	// Wrong secret entirely.
	if _, err := verifyMagicLink("wrong-secret", token); err == nil {
		t.Fatalf("expected error for wrong secret, got nil")
	}
}

func TestMagicLinkExpired(t *testing.T) {
	secret := "test-secret"
	// Build an already-expired token manually (signMagicLink always uses a
	// fresh TTL, so we replicate its construction with a past expiry).
	claims := magicLinkClaims{
		RequestID: "req-999",
		Action:    "approve",
		Exp:       time.Now().Add(-1 * time.Minute).Unix(),
	}
	token := buildTokenForTest(t, secret, claims)

	if _, err := verifyMagicLink(secret, token); err == nil {
		t.Fatalf("expected error for expired token, got nil")
	}
}

func TestMagicLinkMalformed(t *testing.T) {
	secret := "test-secret"
	cases := []string{
		"",
		"no-dot-separator",
		"not-base64.deadbeef",
	}
	for _, c := range cases {
		if _, err := verifyMagicLink(secret, c); err == nil {
			t.Fatalf("expected error for malformed token %q, got nil", c)
		}
	}
}

// buildTokenForTest constructs a token identical in shape to signMagicLink's
// output but with caller-supplied claims, so expiry can be forced into the
// past for TestMagicLinkExpired.
func buildTokenForTest(t *testing.T, secret string, claims magicLinkClaims) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(encoded))
	sig := hex.EncodeToString(mac.Sum(nil))
	return encoded + "." + sig
}
