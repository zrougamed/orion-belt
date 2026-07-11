package auth

import (
	"testing"
	"time"
)

func TestJWTIssueAndValidate(t *testing.T) {
	m := NewJWTManager("test-secret-key", time.Hour)
	token, exp, err := m.Issue("user-1", "alice", true)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if token == "" {
		t.Fatal("empty token")
	}
	if exp.Before(time.Now()) {
		t.Fatal("expiry in the past")
	}

	claims, err := m.Validate(token)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.UserID != "user-1" || claims.Username != "alice" || !claims.IsAdmin {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestJWTRejectsTampered(t *testing.T) {
	m := NewJWTManager("secret", time.Hour)
	token, _, err := m.Issue("u", "bob", false)
	if err != nil {
		t.Fatal(err)
	}
	tampered := token[:len(token)-2] + "xx"
	if _, err := m.Validate(tampered); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestJWTRequiresSecret(t *testing.T) {
	m := NewJWTManager("", time.Hour)
	if m.Enabled() {
		t.Fatal("empty secret should disable JWT")
	}
	if _, _, err := m.Issue("u", "x", false); err == nil {
		t.Fatal("expected error")
	}
}
