package chatops

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// postTeams sends an Adaptive Card to a Microsoft Teams Incoming Webhook
// connector. NOTE (honest capability disclosure): Teams incoming webhooks
// cannot host native interactive buttons that call back into an arbitrary
// HTTP endpoint - that requires registering a full Bot Framework bot, which
// is out of scope here. Instead this sends Action.OpenUrl actions pointing at
// signed magic links (see sign.go) that open in the user's browser and hit
// this plugin's own /approve and /deny routes. This is link-based approval,
// not an in-Teams button click.
func (p *ChatOpsPlugin) postTeams(ctx context.Context, text, requestID string) error {
	approveURL, err := signMagicLink(p.cfg.PublicBaseURL, p.cfg.ApprovalSecret, requestID, "approve")
	if err != nil {
		return fmt.Errorf("sign approve link: %w", err)
	}
	denyURL, err := signMagicLink(p.cfg.PublicBaseURL, p.cfg.ApprovalSecret, requestID, "deny")
	if err != nil {
		return fmt.Errorf("sign deny link: %w", err)
	}

	payload := map[string]interface{}{
		"type": "message",
		"attachments": []map[string]interface{}{
			{
				"contentType": "application/vnd.microsoft.card.adaptive",
				"content": map[string]interface{}{
					"type":    "AdaptiveCard",
					"version": "1.4",
					"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
					"body": []map[string]interface{}{
						{
							"type": "TextBlock",
							"text": text,
							"wrap": true,
						},
					},
					"actions": []map[string]interface{}{
						{"type": "Action.OpenUrl", "title": "Approve", "url": approveURL},
						{"type": "Action.OpenUrl", "title": "Deny", "url": denyURL},
					},
				},
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal teams payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.Teams.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build teams request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("teams request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("teams webhook returned status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}
