# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build
make build                  # outputs to dist/trac3-<version>-linux-x86_64

# Run (builds first)
make run ARGS="renew --help"

# Vet
make vet

# Test
make test                   # unit tests
make test-integration        # integration tests (pebble ACME + gofakes3)
make test-all               # both

# Run directly
go run . renew [flags]
go run . sync [flags]

# Docker
make docker-build
```

## Architecture

TAS3 (traefik-acme-s3) is a CLI tool with two commands: `renew` and `sync`. Both share a global `Config` (debug flag + closet config) parsed via `kong`.

### Packages

**`pkg/certcloset`** — S3-backed certificate store.
- `CertCloset`: holds an S3 client and an in-memory `CertificateList` (index).
- The index (`cert_index.json`) is stored in S3 and loaded at startup. It maps domain → expiration date.
- Certificates are stored per-domain as JSON objects in S3, with the private key AES-encrypted (see `crypt.go`) when `PushPrivateKey=true`.
- `LocalCertCloset` (`localCloset.go`) mirrors the same interface for local filesystem storage used during `sync`.

**`pkg/buckcert`** — ACME client wrapping `go-acme/lego`.
- Uses HTTP-01 challenge, serving challenge files via S3 (`ChallengeBucket`).
- ACME user key + registration persisted to `UserKeyPath` (JSON) so registration survives restarts.

**`pkg/traefikclient`** — Traefik API client.
- Queries Traefik's router API, parses `Host(...)` rules via regex to extract domains.
- Optional: if `--traefik.url` is empty, skipped entirely.

### `app` package — orchestration

- `Renew`: deduplicates domains (Traefik API + `--domains` env), filters `--ignored-domains`, skips domains in failure backoff, requests certs via `buckcert`, stores via `certcloset`. Renews 2 months before expiry.
- `Sync`: diffs remote S3 index vs local index, downloads missing/changed certs, writes them to disk, then generates a Traefik dynamic config file (TOML or YAML) listing all cert/key paths.
- `backoff.go`: failure state persisted to `<StateDir>/renew_failures.json`. Domains that fail renewal are skipped for `FailureBackoffMinutes` (default 60) to avoid ACME rate-limit spam.

### Data flow

```
renew:
  Traefik API → domain list
  + --domains env
  - --ignored-domains
  → buckcert (lego HTTP-01 via S3) → certificate
  → certcloset.StoreCertificate (S3, encrypted key)
  → certcloset.SaveIndex (cert_index.json on S3)

sync:
  certcloset (S3 index) diff localCloset (local index)
  → download changed certs from S3 to local disk
  → write traefik dynamic config (tls.certificates[])
```

## Key env vars / flags (kong tags drive both)

| Env var | Flag prefix | Purpose |
|---|---|---|
| `CLOSET_BUCKET` | `--closet.bucket` | S3 bucket for certs + index |
| `CLOSET_PASSWORD` | `--closet.password` | AES encryption key for private keys |
| `LETSENCRYPT_EMAIL` | `--letsencrypt.email` | ACME account email |
| `LETSENCRYPT_CA_URL` | `--letsencrypt.ca-url` | Default: LE staging |
| `LETSENCRYPT_BUCKET` | `--letsencrypt.challenge-bucket` | S3 bucket for HTTP-01 challenges |
| `DOMAINS` | `--domains` | Extra domains beyond Traefik API |
| `IGNORED_DOMAINS` | `--ignored-domains` | Domains to skip |
| `TAS3_STATE_DIR` | `--state-dir` | Dir for failure backoff state file |
