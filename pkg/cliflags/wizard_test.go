package cliflags

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCheckAPI_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/version" {
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"version":"dev"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	if err := checkAPI(srv.URL, time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestCheckAPI_Down(t *testing.T) {
	err := checkAPI("http://127.0.0.1:1", 200*time.Millisecond)
	if err == nil {
		t.Fatal("expected error for closed port")
	}
}

func TestExpandPath(t *testing.T) {
	if expandPath("") != "" {
		t.Fatal("empty")
	}
	p := expandPath("~/nope-that-is-relative")
	if p == "" || p[0] == '~' {
		t.Fatalf("expected home expansion, got %q", p)
	}
}
