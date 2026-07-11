package common

import "testing"

func TestParseGatewaySSHUser(t *testing.T) {
	cases := []struct {
		in                    string
		auth, remote, machine string
	}{
		{"alice", "alice", "", ""},
		{"alice+web-01", "alice", "root", "web-01"},
		{"alice+bob%web-01", "alice", "bob", "web-01"},
		{"alice+bob@web-01", "alice", "bob", "web-01"},
	}
	for _, tc := range cases {
		a, r, m := ParseGatewaySSHUser(tc.in)
		if a != tc.auth || r != tc.remote || m != tc.machine {
			t.Fatalf("%q => (%q,%q,%q) want (%q,%q,%q)", tc.in, a, r, m, tc.auth, tc.remote, tc.machine)
		}
	}
}
