package chatops

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

// Discord interaction types (subset relevant to this plugin).
const (
	discordInteractionTypePing             = 1
	discordInteractionTypeMessageComponent = 3

	discordResponseTypePong          = 1
	discordResponseTypeUpdateMessage = 7
)

// discordMessage builds the outbound message-create payload with an
// Approve/Deny action row. Style 3 = success (green), style 4 = danger (red).
func discordMessage(content, requestID string) map[string]interface{} {
	return map[string]interface{}{
		"content": content,
		"components": []map[string]interface{}{
			{
				"type": 1,
				"components": []map[string]interface{}{
					{
						"type":      2,
						"style":     3,
						"label":     "Approve",
						"custom_id": "approve:" + requestID,
					},
					{
						"type":      2,
						"style":     4,
						"label":     "Deny",
						"custom_id": "deny:" + requestID,
					},
				},
			},
		},
	}
}

// postDiscord sends a message to a Discord channel via the bot API.
func (p *ChatOpsPlugin) postDiscord(ctx context.Context, content, requestID string) error {
	payload := discordMessage(content, requestID)
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal discord payload: %w", err)
	}

	url := fmt.Sprintf("https://discord.com/api/v10/channels/%s/messages", p.cfg.Discord.ChannelID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build discord request: %w", err)
	}
	req.Header.Set("Authorization", "Bot "+p.cfg.Discord.BotToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("discord request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("discord API returned status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// verifyDiscordSignature checks the Ed25519 signature Discord attaches to
// every interaction webhook request, per Discord's documented scheme:
// Verify(pubkey, timestamp+body, signature).
func verifyDiscordSignature(publicKeyHex, signatureHex, timestamp string, body []byte) error {
	pubKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key")
	}
	sigBytes, err := hex.DecodeString(signatureHex)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature")
	}

	message := append([]byte(timestamp), body...)
	if !ed25519.Verify(ed25519.PublicKey(pubKeyBytes), message, sigBytes) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

// discordInteraction is the subset of Discord's interaction payload this
// plugin cares about.
type discordInteraction struct {
	Type int `json:"type"`
	Data struct {
		CustomID string `json:"custom_id"`
	} `json:"data"`
}

// handleDiscordInteraction verifies the Ed25519 signature, handles the PING
// handshake, and for a button click resolves the access request synchronously
// (Discord requires a response within 3 seconds) before responding with an
// UPDATE_MESSAGE interaction response that edits the original message in
// place.
func (p *ChatOpsPlugin) handleDiscordInteraction(w http.ResponseWriter, r *http.Request) {
	rawBody, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	sig := r.Header.Get("X-Signature-Ed25519")
	timestamp := r.Header.Get("X-Signature-Timestamp")
	if err := verifyDiscordSignature(p.cfg.Discord.PublicKey, sig, timestamp, rawBody); err != nil {
		log.Printf("[ChatOpsPlugin] discord signature verification failed: %v", err)
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	var interaction discordInteraction
	if err := json.Unmarshal(rawBody, &interaction); err != nil {
		http.Error(w, "invalid interaction JSON", http.StatusBadRequest)
		return
	}

	switch interaction.Type {
	case discordInteractionTypePing:
		writeJSON(w, http.StatusOK, map[string]interface{}{"type": discordResponseTypePong})
		return

	case discordInteractionTypeMessageComponent:
		p.handleDiscordComponent(w, r, interaction.Data.CustomID)
		return

	default:
		// Unknown interaction type - acknowledge with nothing rather than error.
		w.WriteHeader(http.StatusOK)
	}
}

func (p *ChatOpsPlugin) handleDiscordComponent(w http.ResponseWriter, r *http.Request, customID string) {
	parts := strings.SplitN(customID, ":", 2)
	if len(parts) != 2 {
		http.Error(w, "malformed custom_id", http.StatusBadRequest)
		return
	}
	actionName, requestID := parts[0], parts[1]
	if actionName != "approve" && actionName != "deny" {
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}

	resolveErr := p.api.resolveAction(r.Context(), requestID, actionName)

	var content string
	if resolveErr != nil {
		content = fmt.Sprintf("Failed to %s request %s: %v", actionName, requestID, resolveErr)
		log.Printf("[ChatOpsPlugin] discord %s failed for request %s: %v", actionName, requestID, resolveErr)
	} else {
		verb := "Approved"
		if actionName == "deny" {
			verb = "Denied"
		}
		content = fmt.Sprintf("%s via Discord", verb)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"type": discordResponseTypeUpdateMessage,
		"data": map[string]interface{}{
			"content":    content,
			"components": []interface{}{},
		},
	})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
