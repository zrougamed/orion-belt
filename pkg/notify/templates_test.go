package notify

import (
	"strings"
	"testing"
)

func TestRenderApproved(t *testing.T) {
	title, body := Render("access_request.approved", map[string]string{
		"machine": "lab-1",
		"ttl":     "30m",
	})
	if title == "" || body == "" {
		t.Fatalf("empty render: %q %q", title, body)
	}
	if !strings.Contains(body, "lab-1") {
		t.Fatalf("expected machine in body: %q", body)
	}
}

func TestRenderRejected(t *testing.T) {
	title, body := Render("access_request.rejected", map[string]string{"machine": "x"})
	if title != "Access request rejected" || !strings.Contains(body, "x") {
		t.Fatalf("bad render: %q %q", title, body)
	}
}
