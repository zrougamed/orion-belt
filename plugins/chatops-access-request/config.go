package chatops

import (
	"encoding/json"
	"fmt"
)

// SlackConfig holds the Slack-specific settings for this plugin.
type SlackConfig struct {
	Enabled       bool   `json:"enabled"`
	BotToken      string `json:"bot_token"`
	SigningSecret string `json:"signing_secret"`
	Channel       string `json:"channel"`
}

// DiscordConfig holds the Discord-specific settings for this plugin.
type DiscordConfig struct {
	Enabled   bool   `json:"enabled"`
	BotToken  string `json:"bot_token"`
	PublicKey string `json:"public_key"`
	ChannelID string `json:"channel_id"`
}

// TeamsConfig holds the Microsoft Teams incoming-webhook settings.
type TeamsConfig struct {
	Enabled    bool   `json:"enabled"`
	WebhookURL string `json:"webhook_url"`
}

// RocketChatConfig holds the Rocket.Chat incoming-webhook settings.
type RocketChatConfig struct {
	Enabled    bool   `json:"enabled"`
	WebhookURL string `json:"webhook_url"`
}

// Config is the fully-parsed configuration for the chatops-access-request
// plugin, decoded from the raw map[string]interface{} passed to Initialize.
type Config struct {
	APIBaseURL     string
	APIKey         string
	ApprovalSecret string
	PublicBaseURL  string
	Slack          SlackConfig
	Discord        DiscordConfig
	Teams          TeamsConfig
	RocketChat     RocketChatConfig
}

// decodeSubConfig re-marshals a nested map[string]interface{} block (as
// arrives from JSON config) into a typed struct. Missing blocks are left as
// the zero value.
func decodeSubConfig(raw map[string]interface{}, key string, out interface{}) error {
	sub, ok := raw[key]
	if !ok || sub == nil {
		return nil
	}
	m, ok := sub.(map[string]interface{})
	if !ok {
		return fmt.Errorf("%s must be an object", key)
	}
	b, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshal %s config: %w", key, err)
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("unmarshal %s config: %w", key, err)
	}
	return nil
}

// parseConfig validates and decodes the raw plugin config map, per the
// contract described in the plugin brief:
//   - api_base_url and api_key are always required
//   - each platform block is optional and independently toggled by its own
//     "enabled" field
//   - at least one platform must be enabled or Initialize fails
//   - approval_secret and public_base_url are only required when teams or
//     rocketchat is enabled (they rely on signed magic links)
func parseConfig(raw map[string]interface{}) (*Config, error) {
	cfg := &Config{}

	apiBaseURL, ok := raw["api_base_url"].(string)
	if !ok || apiBaseURL == "" {
		return nil, fmt.Errorf("api_base_url is required")
	}
	cfg.APIBaseURL = apiBaseURL

	apiKey, ok := raw["api_key"].(string)
	if !ok || apiKey == "" {
		return nil, fmt.Errorf("api_key is required")
	}
	cfg.APIKey = apiKey

	if v, ok := raw["approval_secret"].(string); ok {
		cfg.ApprovalSecret = v
	}
	if v, ok := raw["public_base_url"].(string); ok {
		cfg.PublicBaseURL = v
	}

	if err := decodeSubConfig(raw, "slack", &cfg.Slack); err != nil {
		return nil, err
	}
	if err := decodeSubConfig(raw, "discord", &cfg.Discord); err != nil {
		return nil, err
	}
	if err := decodeSubConfig(raw, "teams", &cfg.Teams); err != nil {
		return nil, err
	}
	if err := decodeSubConfig(raw, "rocketchat", &cfg.RocketChat); err != nil {
		return nil, err
	}

	if !cfg.Slack.Enabled && !cfg.Discord.Enabled && !cfg.Teams.Enabled && !cfg.RocketChat.Enabled {
		return nil, fmt.Errorf("at least one of slack, discord, teams, rocketchat must be enabled")
	}

	if cfg.Slack.Enabled {
		if cfg.Slack.BotToken == "" {
			return nil, fmt.Errorf("slack.bot_token is required when slack is enabled")
		}
		if cfg.Slack.SigningSecret == "" {
			return nil, fmt.Errorf("slack.signing_secret is required when slack is enabled")
		}
		if cfg.Slack.Channel == "" {
			return nil, fmt.Errorf("slack.channel is required when slack is enabled")
		}
	}

	if cfg.Discord.Enabled {
		if cfg.Discord.BotToken == "" {
			return nil, fmt.Errorf("discord.bot_token is required when discord is enabled")
		}
		if cfg.Discord.PublicKey == "" {
			return nil, fmt.Errorf("discord.public_key is required when discord is enabled")
		}
		if cfg.Discord.ChannelID == "" {
			return nil, fmt.Errorf("discord.channel_id is required when discord is enabled")
		}
	}

	if cfg.Teams.Enabled && cfg.Teams.WebhookURL == "" {
		return nil, fmt.Errorf("teams.webhook_url is required when teams is enabled")
	}

	if cfg.RocketChat.Enabled && cfg.RocketChat.WebhookURL == "" {
		return nil, fmt.Errorf("rocketchat.webhook_url is required when rocketchat is enabled")
	}

	if cfg.Teams.Enabled || cfg.RocketChat.Enabled {
		if cfg.ApprovalSecret == "" {
			return nil, fmt.Errorf("approval_secret is required when teams or rocketchat is enabled")
		}
		if cfg.PublicBaseURL == "" {
			return nil, fmt.Errorf("public_base_url is required when teams or rocketchat is enabled")
		}
	}

	return cfg, nil
}
