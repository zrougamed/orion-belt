# ADR 0001 — Session recording compression (OBGZ1)

## Status

Accepted — 2026-07-14 (**v0.9.0**)

## Context

Cast v2 recordings are newline-delimited JSON and grow quickly on busy gateways. Operators also asked for live watch and playback without changing the public cast format clients consume over the API.

## Decision

Compress recordings **at flush** with gzip when `recording.compression` is `gzip` (default). On-disk files are prefixed with the magic banner `OBGZ1\n` followed by gzip bytes. Playback and content APIs call `MaybeDecompress` so clients still receive plain cast text. Set `compression: none` to keep legacy plaintext casts.

Live session watch fans raw PTY bytes via an in-process hub and does **not** depend on the on-disk format.

## Consequences

- Older plaintext `.cast` files remain readable.
- Encryption (when configured) wraps the compressed blob.
- Tools that open the file path directly must understand OBGZ1 or use the HTTP content endpoint.
- Future formats can introduce a new magic without breaking decompress pass-through of unknown payloads (plain cast).
