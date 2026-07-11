package common

import "strings"

// ParseGatewaySSHUser parses OpenSSH agentless usernames.
//
// Formats:
//
//	alice                 → auth=alice, no auto-target
//	alice+web-01          → auth=alice, remote=root, machine=web-01
//	alice+bob%web-01      → auth=alice, remote=bob, machine=web-01
//	alice+bob@web-01      → auth=alice, remote=bob, machine=web-01  (@ after +)
func ParseGatewaySSHUser(sshUser string) (authUser, remoteUser, machine string) {
	authUser = sshUser
	if i := strings.IndexByte(sshUser, '+'); i > 0 {
		authUser = sshUser[:i]
		target := sshUser[i+1:]
		if target == "" {
			return authUser, "", ""
		}
		// Prefer % then @ for remote%machine
		if j := strings.IndexAny(target, "%@"); j > 0 {
			remoteUser = target[:j]
			machine = target[j+1:]
			return authUser, remoteUser, machine
		}
		return authUser, "root", target
	}
	return authUser, "", ""
}

// FormatTarget builds remoteUser@machine for proxying.
func FormatTarget(remoteUser, machine string) string {
	if remoteUser == "" {
		remoteUser = "root"
	}
	return remoteUser + "@" + machine
}
