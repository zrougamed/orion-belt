package chatops

import (
	"fmt"
	"log"
	"net/http"
)

// htmlPage renders a minimal, self-contained HTML page (no external assets)
// suitable for viewing inside a chat app's in-app browser on a phone.
func htmlPage(w http.ResponseWriter, status int, title, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!doctype html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
       display: flex; align-items: center; justify-content: center; min-height: 100vh;
       margin: 0; background: #f5f5f5; color: #1a1a1a; }
.card { background: #fff; border-radius: 12px; padding: 32px 24px; max-width: 420px;
        text-align: center; box-shadow: 0 2px 12px rgba(0,0,0,0.08); }
h1 { font-size: 18px; margin: 0 0 8px; }
p { font-size: 14px; color: #555; margin: 0; }
</style>
</head>
<body>
<div class="card">
<h1>%s</h1>
<p>%s</p>
</div>
</body>
</html>`, title, title, message)
}

// handleMagicLink handles both /approve and /deny: parse+verify the signed
// token, reject expired/malformed/tampered tokens, then call the core
// approve/reject API and render a minimal result page.
func (p *ChatOpsPlugin) handleMagicLink(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			htmlPage(w, http.StatusBadRequest, "Invalid link", "Missing token.")
			return
		}

		claims, err := verifyMagicLink(p.cfg.ApprovalSecret, token)
		if err != nil {
			log.Printf("[ChatOpsPlugin] magic link verification failed: %v", err)
			htmlPage(w, http.StatusBadRequest, "Invalid or expired link", err.Error())
			return
		}
		if claims.Action != action {
			htmlPage(w, http.StatusBadRequest, "Invalid link", "This link does not match the requested action.")
			return
		}

		if err := p.api.resolveAction(r.Context(), claims.RequestID, action); err != nil {
			log.Printf("[ChatOpsPlugin] %s failed for request %s: %v", action, claims.RequestID, err)
			htmlPage(w, http.StatusOK, "Action failed", fmt.Sprintf("Failed to %s request: %v", action, err))
			return
		}

		verb := "approved"
		if action == "deny" {
			verb = "denied"
		}
		htmlPage(w, http.StatusOK, "Success", fmt.Sprintf("Access request %s.", verb))
	}
}
