package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestChallengeStoreSingleUse(t *testing.T) {
	s := newChallengeStore()
	c, err := s.Issue("alice")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !s.Verify("alice", c) {
		t.Fatal("expected first Verify to succeed")
	}
	if s.Verify("alice", c) {
		t.Fatal("expected second Verify of the same challenge to fail (single-use)")
	}
}

func TestChallengeStoreWrongValueRejected(t *testing.T) {
	s := newChallengeStore()
	if _, err := s.Issue("alice"); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if s.Verify("alice", "not-the-real-challenge") {
		t.Fatal("expected Verify with wrong value to fail")
	}
}

func TestChallengeStoreUnknownUserRejected(t *testing.T) {
	s := newChallengeStore()
	if s.Verify("nobody", "anything") {
		t.Fatal("expected Verify for a user with no issued challenge to fail")
	}
}

func TestChallengeStoreReissueInvalidatesPrior(t *testing.T) {
	s := newChallengeStore()
	first, _ := s.Issue("alice")
	second, _ := s.Issue("alice")
	if first == second {
		t.Fatal("expected two Issue calls to produce different challenges")
	}
	if s.Verify("alice", first) {
		t.Fatal("expected the superseded challenge to no longer verify")
	}
	if !s.Verify("alice", second) {
		t.Fatal("expected the latest challenge to verify")
	}
}

func genSigner(t *testing.T) ssh.Signer {
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

func TestVerifyPossessionValidSignature(t *testing.T) {
	s := &APIServer{challenges: newChallengeStore()}
	challenge, _ := s.challenges.Issue("alice")
	signer := genSigner(t)

	sig, err := signer.Sign(rand.Reader, []byte(challenge))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	err = s.verifyPossession("alice", challenge, sig.Format, base64.StdEncoding.EncodeToString(sig.Blob), signer.PublicKey())
	if err != nil {
		t.Fatalf("expected valid signature to verify, got: %v", err)
	}
}

func TestVerifyPossessionWrongKeyRejected(t *testing.T) {
	s := &APIServer{challenges: newChallengeStore()}
	challenge, _ := s.challenges.Issue("alice")
	signer := genSigner(t)
	otherSigner := genSigner(t)

	sig, err := signer.Sign(rand.Reader, []byte(challenge))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Signed by `signer`, but verified against `otherSigner`'s public key —
	// this is the scenario that matters: an attacker who only knows the
	// victim's *public* key (which is not secret) cannot forge this.
	err = s.verifyPossession("alice", challenge, sig.Format, base64.StdEncoding.EncodeToString(sig.Blob), otherSigner.PublicKey())
	if err == nil {
		t.Fatal("expected signature from a different key to be rejected")
	}
}

func TestVerifyPossessionReplayRejected(t *testing.T) {
	s := &APIServer{challenges: newChallengeStore()}
	challenge, _ := s.challenges.Issue("alice")
	signer := genSigner(t)
	sig, _ := signer.Sign(rand.Reader, []byte(challenge))
	sigB64 := base64.StdEncoding.EncodeToString(sig.Blob)

	if err := s.verifyPossession("alice", challenge, sig.Format, sigB64, signer.PublicKey()); err != nil {
		t.Fatalf("first verification should succeed: %v", err)
	}
	if err := s.verifyPossession("alice", challenge, sig.Format, sigB64, signer.PublicKey()); err == nil {
		t.Fatal("expected replay of the same (challenge, signature) pair to be rejected")
	}
}

func TestBootstrapStoreSingleUse(t *testing.T) {
	s := newBootstrapStore()
	code, _, err := s.Issue("user-1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	userID, ok := s.Redeem(code)
	if !ok || userID != "user-1" {
		t.Fatalf("expected first Redeem to succeed with user-1, got ok=%v userID=%q", ok, userID)
	}
	if _, ok := s.Redeem(code); ok {
		t.Fatal("expected second Redeem of the same code to fail (single-use)")
	}
}

func TestBootstrapStoreUnknownCodeRejected(t *testing.T) {
	s := newBootstrapStore()
	if _, ok := s.Redeem("not-a-real-code"); ok {
		t.Fatal("expected Redeem of an unissued code to fail")
	}
}
