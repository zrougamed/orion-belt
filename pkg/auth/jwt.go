package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// JWTClaims are the claims embedded in Orion Belt API JWTs.
type JWTClaims struct {
	UserID   string `json:"uid"`
	Username string `json:"username"`
	IsAdmin  bool   `json:"is_admin"`
	IssuedAt int64  `json:"iat"`
	Expires  int64  `json:"exp"`
}

// JWTManager issues and validates HMAC-SHA256 JWTs.
type JWTManager struct {
	secret []byte
	ttl    time.Duration
}

// NewJWTManager creates a JWT manager. secret must be non-empty for signing.
func NewJWTManager(secret string, ttl time.Duration) *JWTManager {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &JWTManager{
		secret: []byte(secret),
		ttl:    ttl,
	}
}

// Enabled reports whether JWT signing is configured.
func (j *JWTManager) Enabled() bool {
	return j != nil && len(j.secret) > 0
}

// Issue creates a signed JWT for the given user.
func (j *JWTManager) Issue(userID, username string, isAdmin bool) (string, time.Time, error) {
	if !j.Enabled() {
		return "", time.Time{}, fmt.Errorf("JWT secret not configured")
	}

	now := time.Now()
	exp := now.Add(j.ttl)
	claims := JWTClaims{
		UserID:   userID,
		Username: username,
		IsAdmin:  isAdmin,
		IssuedAt: now.Unix(),
		Expires:  exp.Unix(),
	}

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", time.Time{}, err
	}
	payloadEnc := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := header + "." + payloadEnc
	sig := j.sign(signingInput)
	return signingInput + "." + sig, exp, nil
}

// Validate parses and validates a JWT, returning claims.
func (j *JWTManager) Validate(token string) (*JWTClaims, error) {
	if !j.Enabled() {
		return nil, fmt.Errorf("JWT authentication not configured")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	signingInput := parts[0] + "." + parts[1]
	expected := j.sign(signingInput)
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return nil, fmt.Errorf("invalid token signature")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid token payload")
	}

	var claims JWTClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("invalid token claims")
	}

	if time.Now().Unix() > claims.Expires {
		return nil, fmt.Errorf("token expired")
	}

	return &claims, nil
}

func (j *JWTManager) sign(input string) string {
	mac := hmac.New(sha256.New, j.secret)
	mac.Write([]byte(input))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
