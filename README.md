# TAS3 — Traefik ACME S3

TAS3 obtains TLS certificates via Let's Encrypt (ACME HTTP-01) and stores them encrypted in S3. A companion `sync` command downloads them to disk and generates dynamic TLS config for Traefik and/or HAProxy.

## Commands

### `renew`

Discovers domains from Traefik's router API, the traefik config-server API, and/or `DOMAINS`, requests certificates via ACME HTTP-01 (challenge files served from S3), stores them encrypted in S3, and persists the index.

### `sync`

Diffs the S3 index against the local copy, downloads changed certificates, and writes output config for any enabled backends:

- **Traefik** — dynamic config file (`tls.certificates[]`, TOML or YAML). Optional; enabled by setting `TRAEFIK_OUTPUT_FILE`.
- **HAProxy** — per-domain PEM bundles (cert + key concatenated) and optional `crt-list` file. Optional; enabled by setting `HAPROXY_CRT_DIR`.

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
| `TAS3_FAILURE_BACKOFF_MINUTES` | `--failure-backoff-minutes` | `60` | Minutes to skip a domain after renewal failure |
| `TAS3_REQUEST_DELAY_SECONDS` | `--request-delay-seconds` | `3` | Delay between certificate requests |
| `TRAEFIK_API_URL` | `--traefik.url` | — | Traefik API base URL (optional) |
| `TRAEFIK_API_USERNAME` | `--traefik.username` | — | Traefik API basic auth username |
| `TRAEFIK_API_PASSWORD` | `--traefik.password` | — | Traefik API basic auth password |
| `TRAEFIK_API_TIMEOUT` | `--traefik.timeout` | `5` | Traefik API request timeout (seconds) |
| `TRAEFIK_API_INSECURE` | `--traefik.insecure` | `false` | Skip TLS verification for Traefik API |
| `CONFIG_SERVER_URL` | `--config-server.url` | — | traefik config-server base URL (optional, e.g. `http://config-server:8000`) |
| `CONFIG_SERVER_NODE` | `--config-server.node` | — | Filter config-server backends to this node name. Empty = all backends |
| `CONFIG_SERVER_TIMEOUT` | `--config-server.timeout` | `5` | Config-server request timeout (seconds) |

### `sync`

#### Local cert store (required)

| Variable | Flag | Description |
|---|---|---|
| `TRAEFIK_LOCAL_STORE` | `--traefik.local-store` | Local directory where certificates are cached (`<domain>/cert.pem` + `key.pem`) |

#### Traefik output (optional)

Enabled when `TRAEFIK_OUTPUT_FILE` is set.

| Variable | Flag | Default | Description |
|---|---|---|---|
| `TRAEFIK_OUTPUT_FILE` | `--traefik.config-file` | — | Path for the generated Traefik dynamic config |
| `TRAEFIK_OUTPUT_FORMAT` | `--traefik.format` | `toml` | `toml` or `yaml` |
| `TRAEFIK_CERTIFICATE_DIR` | `--traefik.certificate-dir` | — | Certificate path prefix written into the config file |

#### HAProxy output (optional)

Enabled when `HAPROXY_CRT_DIR` is set. Writes one `<domain>.pem` bundle (cert + key concatenated, mode 0600) per domain.

| Variable | Flag | Default | Description |
|---|---|---|---|
| `HAPROXY_CRT_DIR` | `--haproxy.cert-dir` | — | Directory to write HAProxy PEM bundles |
| `HAPROXY_CRT_LIST_FILE` | `--haproxy.crt-list-file` | — | Path for the generated `crt-list` file. Empty = no crt-list written |
| `HAPROXY_CRT_DIR_REF` | `--haproxy.cert-dir-ref` | `HAPROXY_CRT_DIR` | Cert dir as HAProxy sees it in crt-list paths (useful when the path differs inside the HAProxy container) |

HAProxy config example:
```
bind *:443 ssl crt-list /etc/haproxy/crt-list.txt
```

### Daemon mode (both commands)

Set `TAS3_INTERVAL` to run continuously instead of once-and-exit.

| Variable | Flag | Default | Description |
|---|---|---|---|
| `TAS3_INTERVAL` | `--interval` | `0` | Daemon loop interval (e.g. `1h`, `5m`). `0` = run once and exit |
| `TAS3_HTTP_ADDR` | `--http-addr` | `` | Bind address for HTTP trigger + health server (e.g. `:8080`). Bind to loopback or use a reverse proxy — no TLS provided |
| `TAS3_HTTP_TOKEN` | `--http-token` | `` | Bearer token for `POST /trigger` auth. Takes priority over `TAS3_HTTP_TOKEN_FILE` |
| `TAS3_HTTP_TOKEN_FILE` | `--http-token-file` | `` | Path to file containing the HTTP token (Docker secret fallback) |
| `TAS3_TRIGGER_RATE_LIMIT` | `--trigger-rate-limit` | `10` | Max `POST /trigger` requests per minute (`0` = unlimited) |
| `TAS3_METRICS_ADDR` | `--metrics-addr` | `` | Separate bind address for `/metrics` (e.g. `:9090`). Empty = served on `TAS3_HTTP_ADDR` when set |

HTTP endpoints (when `TAS3_HTTP_ADDR` is set):

- `POST /trigger` — fire an immediate run (auth required when token is configured)
- `GET /health` — JSON status with `last_renew` / `last_sync` timestamps
- `GET /metrics` — Prometheus metrics (also available on `TAS3_METRICS_ADDR`)

### DNS UPDATE / DANE-TLSA (optional)

When enabled, TAS3 publishes TLSA and CAA records via RFC 2136 DNS UPDATE after each renewal. A 3-phase rollover prevents DANE verification gaps: new TLSA is pre-published, the certificate is switched after the TLSA TTL expires, then the old TLSA is removed.

| Variable | Default | Description |
|---|---|---|
| `DNS_UPDATE_ENABLED` | `false` | Enable DNS UPDATE |
| `DNS_UPDATE_KEYS_FILE` | — | Path to JSON file mapping domain → TSIG key config |
| `DNS_UPDATE_TTL` | `300` | TTL for TLSA and CAA records |
| `DNS_UPDATE_TLSA_PORT` | `443` | Port in TLSA record name (`_PORT._PROTO.domain`) |
| `DNS_UPDATE_TLSA_PROTO` | `tcp` | Protocol in TLSA record name |
| `DNS_UPDATE_CAA_ISSUER` | — | CAA issuer value. Empty = derived from ACME CA URL |
| `DNS_UPDATE_CAA_IODEF` | — | CAA iodef value (e.g. `mailto:ops@example.com`) |
| `DNS_UPDATE_ROLLOVER_ENABLED` | `true` | 3-phase TLSA rollover. `false` = atomic swap (gap risk) |
| `DNS_UPDATE_TLSA_TTL_SECONDS` | `3600` | Seconds to wait after pre-publishing new TLSA before switching cert |
| `DNS_UPDATE_SYNC_LAG_SECONDS` | `300` | Seconds to wait after cert switch before removing old TLSA |

## Persistent volumes

One path **must** be on a persistent volume in container deployments:

- **`LETSENCRYPT_USER_KEY_PATH`** — the ACME account key and registration. If lost, TAS3 re-registers a new account on every start, which will hit Let's Encrypt rate limits.

All other state (failure backoff, TLSA rollover progress, distributed lock) is stored in S3 alongside the certificates.

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
  -e DOMAINS=example.com,www.example.com \
  -v /persistent/tas3:/state \
  ghcr.io/outout14/traefik-acme-s3:main renew
```

### Daemon mode example

```bash
docker run -d \
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
  -e DOMAINS=example.com,www.example.com \
  -e TAS3_INTERVAL=12h \
  -e TAS3_HTTP_ADDR=127.0.0.1:8080 \
  -p 127.0.0.1:8080:8080 \
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
