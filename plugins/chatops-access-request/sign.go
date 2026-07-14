package chatops

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// magicLinkTTL bounds how long an Approve/Deny link sent to Teams or
// Rocket.Chat remains valid.
const magicLinkTTL = 15 * time.Minute

// magicLinkClaims is the payload embedded in a signed approve/deny link.
type magicLinkClaims struct {
	RequestID string `json:"request_id"`
	Action    string `json:"action"` // "approve" or "deny"
	Exp       int64  `json:"exp"`    // unix seconds
}

// signMagicLink builds a token of the form base64url(json) + "." + hex(hmac)
// per the plugin brief, and returns the full URL to hit approve/deny.
func signMagicLink(publicBaseURL, secret, requestID, action string) (string, error) {
	claims := magicLinkClaims{
		RequestID: requestID,
		Action:    action,
		Exp:       time.Now().Add(magicLinkTTL).Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(encoded))
	sig := hex.EncodeToString(mac.Sum(nil))
	token := encoded + "." + sig

	var path string
	switch action {
	case "approve":
		path = "/approve"
	case "deny":
		path = "/deny"
	default:
		return "", fmt.Errorf("unknown action %q", action)
	}
	return fmt.Sprintf("%s%s?token=%s", publicBaseURL, path, token), nil
}

// verifyMagicLink parses and verifies a token produced by signMagicLink,
// returning the embedded claims on success. It rejects malformed tokens,
// tampered signatures (constant-time compare), and expired claims.
func verifyMagicLink(secret, token string) (*magicLinkClaims, error) {
	dot := -1
	for i := len(token) - 1; i >= 0; i-- {
		if token[i] == '.' {
			dot = i
			break
		}
	}
	if dot < 0 {
		return nil, fmt.Errorf("malformed token")
	}
	encoded := token[:dot]
	sigHex := token[dot+1:]

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(encoded))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	gotSig, err := hex.DecodeString(sigHex)
	if err != nil {
		return nil, fmt.Errorf("malformed signature")
	}
	expectedSigBytes, _ := hex.DecodeString(expectedSig)
	if !hmac.Equal(gotSig, expectedSigBytes) {
		return nil, fmt.Errorf("signature mismatch")
	}

	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("malformed payload")
	}
	var claims magicLinkClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("malformed claims")
	}
	if claims.RequestID == "" || (claims.Action != "approve" && claims.Action != "deny") {
		return nil, fmt.Errorf("invalid claims")
	}
	if time.Now().Unix() > claims.Exp {
		return nil, fmt.Errorf("token expired")
	}
	return &claims, nil
}
