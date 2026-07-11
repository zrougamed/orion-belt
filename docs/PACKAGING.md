# Packaging & installation

Orion Belt ships native packages for major Linux distributions via **GoReleaser + nFPM**.

## Packages

| Package | Contents | Formats |
|---------|----------|---------|
| `orion-belt` | gateway server + systemd unit + `/etc/orion-belt/server.yaml` | deb, rpm, apk |
| `orion-belt-agent` | reverse SSH agent + systemd unit | deb, rpm, apk |
| `orion-belt-tools` | `osh`, `ocp`, `oadmin` | deb, rpm, apk |

## Build locally

```bash
# Requires Go 1.26.5+ (see go.mod). Optional: nfpm or goreleaser.
make packages
# → dist/*.deb  dist/*.rpm  dist/*.apk  + raw binaries
```

Or:

```bash
./scripts/package.sh
```

## Install

### Debian / Ubuntu

```bash
sudo apt install ./orion-belt_*_amd64.deb
sudo apt install ./orion-belt-agent_*_amd64.deb
sudo apt install ./orion-belt-tools_*_amd64.deb
```

### RHEL / Rocky / Fedora / openSUSE

```bash
sudo rpm -Uvh orion-belt-*.rpm orion-belt-agent-*.rpm orion-belt-tools-*.rpm
# openSUSE:
sudo zypper install ./orion-belt-*.rpm
```

### Alpine

```bash
sudo apk add --allow-untrusted ./orion-belt-*.apk
```

## Enable services

```bash
# Edit DB connection / JWT secret first
sudoedit /etc/orion-belt/server.yaml
sudo systemctl enable --now orion-belt-server

# On each target host
sudoedit /etc/orion-belt/agent.yaml
sudo systemctl enable --now orion-belt-agent
```

## Release (GitHub)

Push a tag `v*`. The Release workflow runs the CVE gate, then GoReleaser publishes archives + packages to GitHub Releases.

```bash
git tag v0.5.0
git push origin v0.5.0
```

## APT/YUM repos (optional follow-up)

For production, mirror `dist/` into:

- an APT repo (`reprepro` / `aptly`)
- an RPM repo (`createrepo_c`)
- an Alpine repo (`abuild`)

Point hosts at those repos so `apt install orion-belt` / `dnf install orion-belt` work without downloading packages by hand.
