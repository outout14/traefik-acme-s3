# TAS3 — Traefik ACME S3

TAS3 obtains TLS certificates via Let's Encrypt (ACME HTTP-01) and stores them encrypted in S3. A companion `sync` command downloads them to disk and generates the Traefik dynamic TLS config.

## Commands

### `renew`

Discovers domains from Traefik's router API and/or `DOMAINS`, requests certificates via ACME HTTP-01 (challenge files served from S3), stores them encrypted in S3, and persists the index.

### `sync`

Diffs the S3 index against the local copy, downloads changed certificates, and writes a Traefik dynamic config file (`tls.certificates[]`).

## Environment variables

### Global

| Variable | Flag | Default | Description |
|---|---|---|---|
| `DEBUG` | `--debug` | `false` | Enable debug logging |
| `LOKI_URL` | `--loki-url` | `` | Loki push URL (disabled if empty) |
| `LOKI_APP` | `--loki-app` | `tas3` | Value for the `app` Loki label |
| `CLOSET_PASSWORD` | `--closet.password` | — | AES-256 encryption key for private keys |
| `CLOSET_BUCKET` | `--closet.bucket` | — | S3 bucket for certs and index |
| `CLOSET_PUSH_PRIVATE_KEY` | `--closet.push-private-key` | `true` | Store private key encrypted in S3 |

### S3 credentials

TAS3 uses the AWS SDK default config chain — no custom S3 flags. Set these standard env vars:

| Variable | Description |
|---|---|
| `AWS_ACCESS_KEY_ID` | S3 access key |
| `AWS_SECRET_ACCESS_KEY` | S3 secret key |
| `AWS_REGION` | S3 region |
| `AWS_ENDPOINT_URL` | S3-compatible endpoint (e.g. MinIO: `http://minio:9000`) |

### `renew`

| Variable | Flag | Default | Description |
|---|---|---|---|
| `LETSENCRYPT_EMAIL` | `--letsencrypt.email` | — | ACME account email |
| `LETSENCRYPT_CA_URL` | `--letsencrypt.ca-url` | LE staging | ACME directory URL |
| `LETSENCRYPT_KEY_TYPE` | `--letsencrypt.key-type` | `P256` | Key type: P256, P384, RSA2048, RSA4096, RSA8192 |
| `LETSENCRYPT_BUCKET` | `--letsencrypt.challenge-bucket` | — | S3 bucket for HTTP-01 challenge files |
| `LETSENCRYPT_USER_KEY_PATH` | `--letsencrypt.user-key-path` | `./le_user.json` | **Must point to a persistent path** — stores ACME account key and registration |
| `DOMAINS` | `--domains` | — | Extra domains beyond Traefik API |
| `IGNORED_DOMAINS` | `--ignored-domains` | — | Domains to skip |
| `TAS3_STATE_DIR` | `--state-dir` | — | **Recommended: set to a persistent path** — stores failure backoff state |
| `TAS3_FAILURE_BACKOFF_MINUTES` | `--failure-backoff-minutes` | `60` | Minutes to skip a domain after renewal failure |
| `TAS3_REQUEST_DELAY_SECONDS` | `--request-delay-seconds` | `3` | Delay between certificate requests |
| `TRAEFIK_API_URL` | `--traefik.url` | — | Traefik API base URL (optional) |
| `TRAEFIK_API_USERNAME` | `--traefik.username` | — | Traefik API basic auth username |
| `TRAEFIK_API_PASSWORD` | `--traefik.password` | — | Traefik API basic auth password |
| `TRAEFIK_API_TIMEOUT` | `--traefik.timeout` | `5` | Traefik API request timeout (seconds) |
| `TRAEFIK_API_INSECURE` | `--traefik.insecure` | `false` | Skip TLS verification for Traefik API |

### `sync`

| Variable | Flag | Description |
|---|---|---|
| `TRAEFIK_LOCAL_STORE` | `--traefik.local-store` | Local directory to write certificates |
| `TRAEFIK_OUTPUT_FILE` | `--traefik.config-file` | Path for the generated Traefik dynamic config |
| `TRAEFIK_OUTPUT_FORMAT` | `--traefik.format` | `toml` or `yaml` |
| `TRAEFIK_CERTIFICATE_DIR` | `--traefik.certificate-dir` | Certificate path prefix written into the config file |

## Persistent volumes

Two paths **must** be on a persistent volume in container deployments:

- **`LETSENCRYPT_USER_KEY_PATH`** — the ACME account key and registration. If lost, TAS3 re-registers a new account on every start, which will hit Let's Encrypt rate limits.
- **`TAS3_STATE_DIR`** — failure backoff state. If lost, previously-failed domains are retried immediately, risking ACME rate-limit bans.

## S3 HTTP-01 challenge

The challenge bucket (`LETSENCRYPT_BUCKET`) must be served publicly at `/.well-known/acme-challenge/` for your domains. Configure your S3 provider (or a reverse proxy) to serve `GET /.well-known/acme-challenge/<token>` from that bucket.

## Using production Let's Encrypt

Set `LETSENCRYPT_CA_URL=https://acme-v02.api.letsencrypt.org/directory`.

The default CA URL points to the staging environment.

## Docker

```bash
docker pull ghcr.io/outout14/traefik-acme-s3:main

docker run --rm \
  -e AWS_ACCESS_KEY_ID=minioadmin \
  -e AWS_SECRET_ACCESS_KEY=minioadmin \
  -e AWS_REGION=us-east-1 \
  -e AWS_ENDPOINT_URL=http://minio:9000 \
  -e CLOSET_BUCKET=my-certs \
  -e CLOSET_PASSWORD=changeme \
  -e LETSENCRYPT_EMAIL=admin@example.com \
  -e LETSENCRYPT_CA_URL=https://acme-v02.api.letsencrypt.org/directory \
  -e LETSENCRYPT_BUCKET=my-acme-challenges \
  -e LETSENCRYPT_USER_KEY_PATH=/state/le_user.json \
  -e TAS3_STATE_DIR=/state \
  -e DOMAINS=example.com,www.example.com \
  -v /persistent/tas3:/state \
  ghcr.io/outout14/traefik-acme-s3:main renew
```

## Development

```bash
make build           # build binary to dist/
make run ARGS="renew --help"
make vet             # go vet ./...
make test            # unit tests
make test-integration # integration tests
make test-all        # both
make clean           # remove dist/ and test cache
```
