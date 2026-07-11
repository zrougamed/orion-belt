package api

import (
	"strings"
	"testing"
)

func TestBuildAgentInstallScriptDebian(t *testing.T) {
	script := buildAgentInstallScript(
		"debian",
		"web-01",
		"gw.example.com",
		2222,
		"https://packages.example.com",
		"1.2.3",
		"-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----",
		map[string]string{"os": "debian", "env": "lab"},
	)
	checks := []string{
		"#!/usr/bin/env bash",
		`host: "gw.example.com"`,
		`name: "web-01"`,
		"orion-belt-agent_${VERSION}_amd64.deb",
		"ORION_AGENT_KEY",
		"-----BEGIN PRIVATE KEY-----",
		"systemctl enable --now orion-belt-agent",
		`PKG_BASE="https://packages.example.com"`,
	}
	for _, c := range checks {
		if !strings.Contains(script, c) {
			t.Fatalf("script missing %q\n%s", c, script)
		}
	}
}

func TestBuildAgentInstallScriptAlpine(t *testing.T) {
	script := buildAgentInstallScript("alpine", "a1", "10.0.0.1", 2222, "http://pkg", "0.4.0", "KEYDATA", nil)
	if !strings.Contains(script, "apk add --allow-untrusted") {
		t.Fatal("expected apk install path")
	}
	if !strings.Contains(script, "orion-belt-agent_${VERSION}_x86_64.apk") {
		t.Fatal("expected apk package name")
	}
}
