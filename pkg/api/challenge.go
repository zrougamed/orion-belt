package api

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ssh"
)

const challengeTTL = 60 * time.Second

// challengeEntry is a single-use, short-lived login nonce.
type challengeEntry struct {
	value     string
	expiresAt time.Time
}

// challengeStore issues and verifies single-use login challenges, proving
// a login request's caller actually holds the private key for the public
// key they present — without this, /login and friends only ever compared
// a bare public-key *string* against the database, which anyone who
// observed or guessed a user's public key (not secret — it's public) could
// replay to mint themselves a session. In-memory, single-process, same
// shape as rateLimiter — a challenge only needs to survive the few seconds
// between issuance and the client's signed follow-up request.
type challengeStore struct {
	mu      sync.Mutex
	entries map[string]challengeEntry // keyed by username
}

func newChallengeStore() *challengeStore {
	return &challengeStore{entries: make(map[string]challengeEntry)}
}

// Issue generates a fresh challenge for username, replacing any prior
// unused one (only the most recent challenge per user is valid).
func (s *challengeStore) Issue(username string) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate challenge: %w", err)
	}
	value := base64.StdEncoding.EncodeToString(buf)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.gc()
	s.entries[username] = challengeEntry{value: value, expiresAt: time.Now().Add(challengeTTL)}
	return value, nil
}

// Verify consumes the challenge for username if it matches and hasn't
// expired. Only a *matching* challenge is removed (single-use, so a
// captured (challenge, signature) pair can't be replayed) — a mismatched
// or unknown value is left alone, otherwise one wrong guess would let an
// attacker invalidate another in-flight login's still-valid challenge.
func (s *challengeStore) Verify(username, value string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[username]
	if !ok || value == "" || entry.value != value {
		return false
	}
	delete(s.entries, username)
	return time.Now().Before(entry.expiresAt)
}

// gc opportunistically drops expired entries. Called with the lock held.
func (s *challengeStore) gc() {
	now := time.Now()
	for k, v := range s.entries {
		if now.After(v.expiresAt) {
			delete(s.entries, k)
		}
	}
}

// issueChallenge is POST /public/auth/challenge — the first step of every
// SSH-pubkey-based login flow (login, loginWithKey, loginJWT).
func (s *APIServer) issueChallenge(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	challenge, err := s.challenges.Issue(req.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue challenge"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"challenge": challenge})
}

// verifyPossession proves the caller holds the private key for presented:
// the challenge must be the one most recently issued to username (single-
// use, 60s TTL) and sigBlobB64/sigFormat must be a valid signature over the
// raw challenge bytes from that same key.
func (s *APIServer) verifyPossession(username, challenge, sigFormat, sigBlobB64 string, presented ssh.PublicKey) error {
	if !s.challenges.Verify(username, challenge) {
		return fmt.Errorf("invalid or expired challenge")
	}
	sigBlob, err := base64.StdEncoding.DecodeString(sigBlobB64)
	if err != nil {
		return fmt.Errorf("invalid signature encoding")
	}
	sig := &ssh.Signature{Format: sigFormat, Blob: sigBlob}
	if err := presented.Verify([]byte(challenge), sig); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}
