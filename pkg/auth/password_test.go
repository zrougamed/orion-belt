package auth

import "testing"

func TestHashVerifyPassword(t *testing.T) {
	h, err := HashPassword("correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(h, "correct-horse-battery") {
		t.Fatal("expected match")
	}
	if VerifyPassword(h, "wrong-password-here") {
		t.Fatal("expected mismatch")
	}
}

func TestValidatePasswordStrength(t *testing.T) {
	if ValidatePasswordStrength("short") == nil {
		t.Fatal("expected error")
	}
	if err := ValidatePasswordStrength("long-enough"); err != nil {
		t.Fatal(err)
	}
}
