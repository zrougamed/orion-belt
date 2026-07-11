# OpenSSH agentless clients

Orion Belt accepts vanilla OpenSSH clients — no `osh` binary required.

## Interactive shell

```bash
# As root on machine web-01 (authenticate as gateway user alice)
ssh alice+web-01@orion-gateway.example.com

# As bob on web-01
ssh 'alice+bob%web-01@orion-gateway.example.com'
# or
ssh 'alice+bob@web-01@orion-gateway.example.com'
```

Username format: `gatewayUser+machine` or `gatewayUser+remoteUser%machine`.

## Exec / one-shot commands

```bash
ssh alice@orion-gateway.example.com 'bob@web-01'
ssh alice@orion-gateway.example.com 'bob@web-01 uptime'
```

## FIDO / YubiKey SSH keys

Store your security-key public key (e.g. `sk-ssh-ed25519@openssh.com AAAA...`) as the user's primary key or via **Security → SSH keys** in the web UI / `POST /api/v1/ssh-keys`.

```bash
ssh-keygen -t ed25519-sk -f ~/.ssh/id_ed25519_sk
# paste id_ed25519_sk.pub into Orion
ssh -i ~/.ssh/id_ed25519_sk alice+web-01@orion-gateway
```

Touch the YubiKey when prompted by OpenSSH.

## Example `~/.ssh/config`

```sshconfig
Host orion
  HostName orion-gateway.example.com
  Port 2222
  User alice
  IdentityFile ~/.ssh/id_ed25519_sk

Host web-01
  HostName web-01
  ProxyCommand none
  # Route through Orion using the +machine username form:
Host web-01.orion
  HostName orion-gateway.example.com
  Port 2222
  User alice+web-01
  IdentityFile ~/.ssh/id_ed25519_sk
  RequestTTY force
```

Then: `ssh web-01.orion`

## Notes

- Agents still run on target hosts (reverse tunnel). “Agentless” refers to **clients**, not removing machine agents.
- ProxyJump / `direct-tcpip` is not used; Orion opens a session on the agent instead.
- SCP: prefer `ocp`, or `ssh alice@gw 'alice@web-01 scp -t /path'` style exec (same as `ocp`).

## Lab verification

To exercise these flows on a local QEMU gateway, follow [E2E_TEST_PLAN.md](E2E_TEST_PLAN.md) cases **TC-QEMU-007** … **TC-QEMU-010** (`make lab-qemu-start`).
