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

## APT / YUM / APK repositories

Build packages, then publish static repo trees:

```bash
make packages
./scripts/publish-repos.sh
# → repos/apt  repos/rpm  repos/apk
```

Serve `repos/` over HTTPS (nginx, CDN, GitHub Pages, S3). Client snippets:

| Format | Snippet |
|--------|---------|
| APT | `packaging/repos/apt.sources.example` |
| RPM/DNF/Zypper | `packaging/repos/rpm.repo.example` |
| Alpine | `packaging/repos/apk.repositories.example` |

Signing (recommended for production):

```bash
ORION_GPG_KEY=YOURKEYID ./scripts/publish-repos.sh
ORION_APK_PRIVKEY=~/.abuild/orion-belt.rsa ./scripts/publish-repos.sh
```

Wire the script into release CI after GoReleaser to refresh the hosted repo.

### Arch Linux

Binary packages via `packaging/arch/PKGBUILD` (reads GitHub release tarballs):

```bash
cd packaging/arch
# bump pkgver to match a released tag (without leading v)
makepkg -si
```

That installs `orion-belt`, `orion-belt-agent`, and `orion-belt-tools`. Publishing to the AUR is a follow-up once a stable version is tagged.

## First-run setup

See [SETUP.md](SETUP.md). After install:

```bash
sudoedit /etc/orion-belt/server.yaml
sudo systemctl enable --now orion-belt-server
orion-belt-server setup
```
