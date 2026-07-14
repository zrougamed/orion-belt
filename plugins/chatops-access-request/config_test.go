package chatops

import "testing"

func TestParseConfigRequiresAPIBaseURLAndKey(t *testing.T) {
	_, err := parseConfig(map[string]interface{}{
		"slack": map[string]interface{}{"enabled": true, "bot_token": "x", "signing_secret": "y", "channel": "z"},
	})
	if err == nil {
		t.Fatalf("expected error when api_base_url/api_key missing")
	}
}

func TestParseConfigRequiresAtLeastOnePlatform(t *testing.T) {
	_, err := parseConfig(map[string]interface{}{
		"api_base_url": "http://localhost:8080",
		"api_key":      "obk_test",
	})
	if err == nil {
		t.Fatalf("expected error when no platform is enabled")
	}
}

func TestParseConfigTeamsRequiresApprovalSecret(t *testing.T) {
	_, err := parseConfig(map[string]interface{}{
		"api_base_url": "http://localhost:8080",
		"api_key":      "obk_test",
		"teams":        map[string]interface{}{"enabled": true, "webhook_url": "https://example.com/webhook"},
	})
	if err == nil {
		t.Fatalf("expected error when teams enabled without approval_secret/public_base_url")
	}
}

func TestParseConfigValidSlackOnly(t *testing.T) {
	cfg, err := parseConfig(map[string]interface{}{
		"api_base_url": "http://localhost:8080",
		"api_key":      "obk_test",
		"slack": map[string]interface{}{
			"enabled":        true,
			"bot_token":      "xoxb-test",
			"signing_secret": "sec",
			"channel":        "C123",
		},
	})
	if err != nil {
		t.Fatalf("expected valid config, got error: %v", err)
	}
	if !cfg.Slack.Enabled || cfg.Slack.Channel != "C123" {
		t.Fatalf("unexpected parsed slack config: %+v", cfg.Slack)
	}
}

func TestParseConfigValidTeamsWithMagicLinks(t *testing.T) {
	cfg, err := parseConfig(map[string]interface{}{
		"api_base_url":    "http://localhost:8080",
		"api_key":         "obk_test",
		"approval_secret": "shh",
		"public_base_url": "https://orion.example.com/api/v1/public/plugins/chatops-access-request",
		"teams": map[string]interface{}{
			"enabled":     true,
			"webhook_url": "https://example.com/webhook",
		},
	})
	if err != nil {
		t.Fatalf("expected valid config, got error: %v", err)
	}
	if !cfg.Teams.Enabled {
		t.Fatalf("expected teams enabled")
	}
}
