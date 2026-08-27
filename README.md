# FortiRecover 0.5

FortiRecover is a small, read-only FortiGate REST API helper for inventorying and recovering credentials during documentation, incident recovery, and hardware migration.

It uses only the Python standard library and performs HTTP `GET` requests only.

## Commands

```text
list          inventory configured objects; never request plaintext secrets
audit         check whether secret fields are actually recoverable; never print values
show          print only secrets that were really returned in plaintext
export FILE   write a recovery JSON after requesting plaintext-capable API output
```

`export` is a recovery operation. There is intentionally no "masked JSON export" mode.

## Supported resources

| Resource | API path | Secret fields | Recovery status |
| --- | --- | --- | --- |
| `ipsec` | `vpn.ipsec/phase1-interface` | `psksecret` | Fortinet-documented |
| `radius` | `user/radius` | shared `secret` fields | Fortinet-documented |
| `tacacs` | `user/tacacs+` | shared `key` fields | Fortinet-documented |
| `ldap` | `user/ldap` | bind `password` | best-effort; verify with `audit` |
| `local` | `user/local` | `passwd`, `ppk-secret` | best-effort; verify with `audit` |
| `snmp-community` | `system/snmp/community` | v1/v2c community `name` | best-effort; verify with `audit` |
| `snmp-user` | `system/snmp/user` | `auth-pwd`, `priv-pwd` | best-effort; verify with `audit` |

Fortinet explicitly documents plaintext API recovery using `plain-text-password=1` for IPsec PSKs and, as of 2026, RADIUS and TACACS+ shared secrets. The other resource types contain password/secret fields in FortiOS, but their plaintext API recovery is not equally well documented. FortiRecover therefore labels them **best-effort** instead of pretending that every FortiOS build will decrypt them.

---

# Requirements

- Python 3.10+
- FortiGate/FortiOS with REST API access
- a REST API administrator/token with sufficient permissions
- HTTPS strongly recommended
- `git` is recommended because FortiRecover uses it for the strongest export safety check; a filesystem fallback remains available

No third-party Python modules are required.

---

# Creating a FortiGate REST API token

For recovery work, use a **temporary dedicated REST API administrator** rather than a permanent automation account whenever possible.

Recommended lifecycle:

```text
create temporary REST API admin
        ↓
restrict Trusted Host to your management IP/subnet
        ↓
give only the permissions needed
        ↓
generate a short-lived API token
        ↓
run list / audit / show / export
        ↓
verify the migration/recovery
        ↓
revoke the token or delete the API admin
```

Fortinet recommends least privilege and Trusted Hosts for REST API administrators. Plaintext credential recovery is highly privileged; Fortinet's documented IPsec PSK procedure assumes a `super_admin` session.

## GUI method

You need an administrator with sufficient privileges to create REST API administrators.

In the FortiGate GUI:

```text
System
  -> Administrators
  -> Create New
  -> REST API Admin
```

Recommended values:

```text
Username:
    fortirecover

Administrator Profile:
    minimum profile that works for the required recovery operation

Trusted Hosts:
    your management workstation or management subnet

CORS Allow Origin:
    leave unset unless you specifically need browser CORS access

PKI Group:
    optional
```

For one management workstation, prefer a `/32` Trusted Host where practical:

```text
10.20.12.34/32
```

When FortiGate generates the API token, **copy it immediately**. The token is shown only once.

Do not put the token into:

- Git
- tickets
- screenshots
- chat messages
- shell command arguments
- ordinary notes or shared documents

### `super_admin` caveat

Fortinet documents that the GUI does not allow assigning the built-in `super_admin` profile directly to a REST API user in the same way as ordinary profiles.

If plaintext-secret recovery requires `super_admin`, adjust the temporary API user through the CLI:

```text
config system api-user
    edit "fortirecover"
        set accprofile "super_admin"
    next
end
```

For a temporary recovery account, combine high privilege with a narrow Trusted Host and a short token lifetime.

## CLI method

Example for one trusted workstation:

```text
config system api-user
    edit "fortirecover"
        set comments "Temporary credential recovery"
        set accprofile "super_admin"
        set vdom "root"

        config trusthost
            edit 1
                set type ipv4-trusthost
                set ipv4-trusthost 10.20.12.34 255.255.255.255
            next
        end
    next
end
```

Replace `10.20.12.34` with the source IP that the FortiGate **actually sees**.

This matters if the request comes through:

- NAT
- a management VPN
- a jump host
- another VDOM
- asymmetric or policy-routed management paths

## Generate a short-lived token

FortiOS 7.6.x supports an expiration value in minutes:

```text
execute api-user generate-key fortirecover 60
```

That creates a token valid for approximately 60 minutes.

Fortinet documents the supported expiry range as:

```text
1 .. 10080 minutes
```

`10080` minutes is seven days.

Without the expiry argument:

```text
execute api-user generate-key fortirecover
```

the generated key does not receive that configured expiration. A short-lived token is preferable for recovery work.

Again: **the generated API token is displayed only once**. If it is lost, generate a new token rather than trying to recover the old one.

---

# Supplying the token

FortiRecover sends the token using the HTTP header:

```text
Authorization: Bearer <token>
```

The token is never added to the URL query string.

## fish shell

For the current shell session:

```fish
set -x FORTIGATE_HOST https://10.10.10.100
set -x FORTIGATE_API_TOKEN 'paste-token-here'
```

Then:

```fish
python fortirecover.py list --insecure
```

## Avoid putting the token in shell history

The cleaner one-off method is to omit `FORTIGATE_API_TOKEN` entirely:

```fish
python fortirecover.py \
    --host https://10.10.10.100 \
    list \
    --insecure
```

FortiRecover prompts with hidden input:

```text
FortiGate API token (FORTIGATE_API_TOKEN is unset):
```

The token is not echoed and is not part of the command line.

A token file is also supported:

```fish
python fortirecover.py \
    --host https://10.10.10.100 \
    --token-file ~/.config/fortirecover/token \
    list
```

Protect that file appropriately.

---

# TLS

Certificate verification is enabled by default.

With an internal CA:

```fish
python fortirecover.py \
    --host https://fgt.example.net \
    --ca-file ./company-ca.pem \
    list
```

For a self-signed management certificate:

```fish
python fortirecover.py \
    --host https://10.10.10.100 \
    list \
    --insecure
```

`--insecure` prints a warning because TLS identity verification is disabled.

---

# 1. Inventory without secrets

Start here:

```fish
python fortirecover.py \
    --host https://10.10.10.100 \
    list \
    --insecure
```

`list` does **not** send `plain-text-password=1`.

Limit the request to selected resource types:

```fish
python fortirecover.py \
    --host https://10.10.10.100 \
    list \
    --only ipsec,ldap,radius \
    --insecure
```

For SNMP v1/v2c, the community `name` is itself the secret, so `list` deliberately does not print it.

---

# 2. Audit recoverability without printing secret values

`audit` is intended to answer:

> Which secrets can this FortiGate/API account actually return in plaintext?

Example:

```fish
python fortirecover.py \
    --host https://10.10.10.100 \
    audit \
    --insecure
```

`audit` **does** request `plain-text-password=1`, because it must inspect the returned values, but it never prints those values.

Example output shape:

```text
RESOURCE        SUPPORT      OBJECTS  FIELDS  PLAIN  ENC  MASK  HASH  EMPTY  RESULT
--------------  -----------  -------  ------  -----  ---  ----  ----  -----  -----------
ipsec           documented   12       12      12     0    0     0     0      OK
radius          documented   2        2       2      0    0     0     0      OK
ldap            best-effort  2        2       1      1    0     0     0      PARTIAL
local           best-effort  15       10      0      8    0     2     0      UNRECOVERED
snmp-community  best-effort  1        1       1      0    0     0     0      OK
```

Secret states:

- `plaintext` — usable recovered value
- `encrypted` — FortiOS returned `ENC ...`
- `masked` — value resembles `FortinetPasswordMask` or an asterisk mask
- `hashed` — value looks one-way hashed and is not treated as recovered plaintext
- `empty` — field exists but has no value

Audit results:

- `OK` — plaintext values were returned and there are no unresolved secret fields
- `PARTIAL` — some plaintext values were recovered, others were not
- `UNRECOVERED` — secret fields exist but only encrypted/masked/hashed forms were returned
- `EMPTY` — only empty secret fields were seen
- `NO FIELDS` — objects exist but the expected secret field was not present in the API response
- `NO OBJECTS` — no objects of that resource type were returned

Use `audit` before a migration if you are not sure what the specific FortiOS build exposes.

---

# 3. Show recovered plaintext secrets

Example for IPsec:

```fish
python fortirecover.py \
    --host https://10.10.10.100 \
    show \
    --only ipsec \
    --insecure
```

Filter to one object:

```fish
python fortirecover.py \
    --host https://10.10.10.100 \
    show \
    --only ipsec \
    --match Azure \
    --insecure
```

Output is TSV-style:

```text
ipsec  Azure-S2S  psksecret  exact-plaintext-secret
```

Important behavior in v0.5:

- `show` prints **only values classified as plaintext**
- it does not dump an `ENC ...` blob and pretend that it was recovered
- unresolved fields generate a warning suggesting `audit`

This reduces the chance of copying a FortiOS ciphertext blob into a third-party device as though it were the real password.

---

# 4. Export a recovery JSON

Use a directory outside every Git repository/worktree:

```fish
python fortirecover.py \
    --host https://10.10.10.100 \
    export /tmp/fortigate-recovery.json \
    --insecure
```

FortiRecover requests plaintext-capable API output and stores the returned objects.

The JSON includes:

```text
resources    returned CMDB objects
audit        per-resource secret recoverability summary
errors       resource types that could not be queried
```

The metadata says `plaintext_requested: true`. This is more accurate than claiming that every FortiOS password field was necessarily decrypted.

The file is created with Unix permissions:

```text
0600
```

If some resource endpoints fail, FortiRecover still writes the successfully recovered data and records failures in the top-level `errors` object. The command returns non-zero for a partial export.

If every requested resource fails, no export file is created.

## Git safety guard

FortiRecover refuses to export plaintext recovery data anywhere inside a Git repository, worktree, submodule, or bare repository.

Primary detection uses:

```text
git rev-parse
```

with a manual `.git`/bare-repository fallback.

The protection applies to nested directories too:

```text
~/src/project/.git
~/src/project/private/deep/recovery.json   <- BLOCKED
```

There is deliberately no `--allow-git` override.

---

# VDOM notes

The API user can be scoped to a VDOM:

```text
set vdom "root"
```

FortiRecover also supports:

```fish
--vdom VDOM_NAME
```

Example:

```fish
python fortirecover.py \
    --host https://10.10.10.100 \
    audit \
    --vdom branch01 \
    --only ipsec \
    --insecure
```

Fortinet specifically notes that, in multi-VDOM configurations, plaintext IPsec visibility can depend on the VDOM associated with the interface through which the FortiGate is accessed. If expected objects are missing, verify both API-user scope and the management path/interface.

---

# Common errors

FortiRecover provides targeted errors for:

- HTTP 401 — bad/expired token or API authentication problem
- HTTP 403 — admin profile, Trusted Host, VDOM, or permission issue
- HTTP 404 — CMDB endpoint unavailable on this build/scope
- TLS certificate verification failure
- DNS failure
- connection refused
- timeout
- malformed/non-JSON API response
- export destination inside Git
- existing export file without `--force`
- permission denied
- read-only filesystem
- disk full

If `list` works but `audit/show/export` does not recover plaintext, the most likely difference is privilege or FortiOS behavior for that secret type.

---

# Trusted Hosts troubleshooting

If a token appears valid but API calls return 401/403, verify:

1. The API user's Trusted Hosts include the source IP FortiGate actually sees.
2. The API user is assigned to the correct VDOM.
3. The token has not expired.
4. The access profile permits the requested CMDB path.
5. The profile is sufficiently privileged for plaintext-secret recovery.
6. You are reaching the expected FortiGate management interface/VDOM.
7. NAT or a jump host has not changed the apparent source address.

---

# After recovery

Treat the export like a credential vault.

Recommended cleanup:

```text
1. Verify the recovered credentials on the replacement device.
2. Remove the plaintext JSON from normal working directories.
3. Retain it only under an intentional credential-backup policy.
4. Delete/disable the temporary FortiRecover API administrator.
5. If the account is retained, generate a new token so the recovery token is revoked.
6. Rotate sensitive shared secrets where practical.
```

Delete a temporary API user with:

```text
config system api-user
    delete "fortirecover"
end
```

---

# Tests

Run the standard-library test suite:

```bash
python -m unittest discover -s tests -v
```

Tests cover secret-state classification, prevention of `ENC ...` leakage through `show`, parser/resource selection, SNMP community identity handling, and Git export blocking.

---

# Fortinet references

- REST API administrator:
  https://docs.fortinet.com/document/fortigate/7.6.2/administration-guide/399023/rest-api-administrator

- Using APIs / Bearer tokens / Trusted Hosts:
  https://docs.fortinet.com/document/fortigate/latest/administration-guide/940602/using-apis

- `config system api-user` CLI reference:
  https://docs.fortinet.com/document/fortigate/7.6.0/cli-reference/625450553/config-system-api-user

- Recovering IPsec PSKs with `plain-text-password=1`:
  https://community.fortinet.com/fortigate-3/technical-tip-use-the-fortigate-api-to-recover-an-ipsec-pre-shared-key-in-plain-text-format-177878

- Recovering RADIUS/TACACS+ shared secrets:
  https://community.fortinet.com/fortigate-3/technical-tip-using-the-fortigate-api-to-retrieve-the-radius-or-tacacs-secret-key-227412

- LDAP password field (`config user ldap`):
  https://docs.fortinet.com/document/fortigate/7.6.2/cli-reference/590785459/config-user-ldap

- Local-user password and PPK fields (`config user local`):
  https://docs.fortinet.com/document/fortigate/7.6.0/cli-reference/109120963/config-user-local

- SNMPv3 auth/privacy password fields (`config system snmp user`):
  https://docs.fortinet.com/document/fortigate/7.6.6/cli-reference/292257317/config-system-snmp-user

- Fortinet password-mask representation (`FortinetPasswordMask`):
  https://docs.fortinet.com/document/fortigate/7.2.0/new-features/598820

---

# Security note

FortiRecover is intentionally read-only, but plaintext credential recovery is still a highly sensitive administrative operation. Use a dedicated short-lived API token, narrow Trusted Hosts, trusted management networks, and secure handling of exported files.
