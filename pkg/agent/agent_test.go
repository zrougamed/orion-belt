package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoginShellFromPasswd(t *testing.T) {
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	writeFile(t, passwd, ""+
		"root:x:0:0:root:/root:/bin/bash\n"+
		"nologin-user:x:1001:1001::/home/nologin-user:/sbin/nologin\n"+
		"blank-shell:x:1002:1002::/home/blank-shell:\n",
	)

	cases := []struct {
		name string
		want string
	}{
		{"root", "/bin/bash"},
		{"nologin-user", "/sbin/nologin"},
		{"blank-shell", "/bin/sh"},  // empty shell field falls back
		{"missing-user", "/bin/sh"}, // not present in db
	}

	for _, c := range cases {
		if got := loginShellFromPasswd(passwd, c.name); got != c.want {
			t.Errorf("loginShellFromPasswd(%q) = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestLoginShellFromPasswdMissingFile(t *testing.T) {
	if got := loginShellFromPasswd("/does/not/exist", "root"); got != "/bin/sh" {
		t.Errorf("expected /bin/sh fallback, got %q", got)
	}
}

func TestCredentialForIdentitySameAsCurrentEuid(t *testing.T) {
	id := &unixIdentity{Username: "self", UID: uint32(os.Geteuid())}
	cred, err := credentialForIdentity(id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred != nil {
		t.Errorf("expected nil credential (no-op) when target uid matches current euid, got %+v", cred)
	}
}

func TestCredentialForIdentityDifferentUidNonRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; this case only exercises the non-root guard")
	}
	id := &unixIdentity{Username: "someone-else", UID: uint32(os.Geteuid()) + 1}
	cred, err := credentialForIdentity(id)
	if err == nil {
		t.Fatalf("expected error when agent isn't root and target uid differs, got credential %+v", cred)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
