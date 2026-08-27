# fortirecover

Small, read-only FortiGate REST API helper intended for legitimate recovery,
documentation, and hardware migration work.

## What it reads

- IPsec Phase 1 configuration and `psksecret`
- RADIUS server configuration and shared secrets
- TACACS+ server configuration and shared keys

FortiOS can return selected reversible secrets in plaintext when the CMDB API
request includes `plain-text-password=1`. The tool only asks for plaintext when
you explicitly use `--reveal` or `export --plaintext`.

## Authentication

Use a dedicated FortiGate REST API administrator and an API token.

FortiOS 7.4.5+ / 7.6.1+ expects API tokens in the HTTP `Authorization: Bearer`
header by default. This tool does that; it never adds the token to the URL.

Recommended:

```bash
export FORTIGATE_HOST='https://fgt.example.net'
export FORTIGATE_API_TOKEN='paste-token-here'
```

Or omit `FORTIGATE_API_TOKEN` and the tool will prompt without echoing the token.

## TLS

Certificate verification is enabled by default.

Corporate/private CA:

```bash
./fortirecover.py ipsec --ca-file ./corp-ca.pem
```

For a self-signed management certificate, `--insecure` is available:

```bash
./fortirecover.py ipsec --insecure
```

Prefer a trusted CA or `--ca-file` for real recovery work.

## Usage

Inventory IPsec tunnels, hiding PSKs:

```bash
./fortirecover.py ipsec --ca-file ./corp-ca.pem
```

Reveal matching PSKs (full PSKs are never truncated):

```bash
./fortirecover.py ipsec --match Azure --reveal --ca-file ./corp-ca.pem
```

For exact copy/paste or shell processing, emit only secret fields as TSV:

```bash
./fortirecover.py ipsec --match Azure --reveal --secrets-only   --ca-file ./corp-ca.pem
```

Example shape:

```text
ipsec  Azure-S2S  psksecret  exact-full-secret-here
```

Inventory all supported secret-bearing objects:

```bash
./fortirecover.py all --ca-file ./corp-ca.pem
```

Plaintext migration/recovery bundle:

```bash
./fortirecover.py export \
  --output ./fortigate-recovery.json \
  --plaintext \
  --ca-file ./corp-ca.pem
```

The export is created with Unix mode `0600`. Treat it as credential material:
do not commit it to Git or attach it to ordinary tickets.

Specific VDOM:

```bash
./fortirecover.py ipsec --vdom branch01 --reveal --ca-file ./corp-ca.pem
```

Fortinet notes that in multi-VDOM mode API visibility can also depend on which
VDOM owns the interface through which the FortiGate is accessed.

## API permissions

Plaintext secret recovery is highly privileged. If the API returns encrypted
values, blanks, 403, or 401, check the REST API administrator profile/scope,
trusted hosts, VDOM scope, and FortiOS version.

For a one-off recovery operation, a short-lived API token is preferable. FortiOS
7.6.x supports generating API keys with an expiry time.

## Security properties

- Read-only HTTP GETs only.
- API token is sent in a header, not a query string.
- Token can come from an environment variable, token file, or hidden prompt.
- Secrets are masked by default.
- Plaintext must be explicitly requested.
- Plaintext export uses mode `0600`.
- Existing export files are not overwritten without `--force`.
