# QEMU multi-distro lab

See [../README.md](../README.md) for the full lab overview and current image pins.

```bash
ORION_REFRESH_IMAGES=1 ./download-images.sh   # force newest images
./up.sh
./test-e2e.sh
./down.sh
```

| Variable | Default | Meaning |
|----------|---------|---------|
| `ORION_PKG_PORT` | `8765` | Host HTTP port serving `dist/` |
| `ORION_VERSION` | `0.0.0-dev` | Package version string in cloud-init URLs |
| `ORION_LAB_SSH_KEY` | `run/lab_id_ed25519` | SSH key injected via cloud-init |
| `ORION_API` | `http://127.0.0.1:8080` | API base for `test-e2e.sh` |
| `ORION_REFRESH_IMAGES` | `0` | Set `1` to re-download cloud images |
