package auth

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestTOTPRoundTrip(t *testing.T) {
	key, err := GenerateTOTPSecret("Orion-Belt", "alice")
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !ValidateTOTP(key.Secret(), code) {
		t.Fatal("expected valid totp")
	}
	if ValidateTOTP(key.Secret(), "000000") {
		t.Fatal("expected invalid totp")
	}
}

func TestBackupCodes(t *testing.T) {
	codes, store, err := GenerateBackupCodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 8 {
		t.Fatalf("got %d codes", len(codes))
	}
	newStore, ok := ConsumeBackupCode(store, codes[0])
	if !ok {
		t.Fatal("backup code should match")
	}
	if _, ok := ConsumeBackupCode(newStore, codes[0]); ok {
		t.Fatal("backup code should be single-use")
	}
}
