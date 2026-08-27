# fortirecover 0.4

Read-only helper for inventorying and recovering selected FortiGate secrets
through the FortiOS REST API.

The interface intentionally has only three normal modes:

```text
list          inventory only; do not request plaintext secrets
show          print plaintext secrets to the terminal
export FILE   save a plaintext recovery bundle as JSON
```

There is intentionally no "masked JSON export" mode. If you ask for an export,
the purpose is recovery, so the JSON contains the recoverable plaintext secrets.

---

# Creating a FortiGate REST API token

## Recommended recovery workflow

For recovery work, do **not** reuse a permanent automation account if you can
avoid it.

A safer workflow is:

1. Create a dedicated REST API administrator such as `fortirecover`.
2. Restrict it to the workstation or management subnet you are using with
   **Trusted Hosts**.
3. Give it only the permissions needed for the task.
4. Generate a short-lived API token.
5. Run `fortirecover`.
6. Remove the API administrator, regenerate its token, or otherwise revoke the
   credential when recovery is complete.
7. Protect or destroy any plaintext JSON export when it is no longer needed.

Fortinet explicitly recommends least privilege and Trusted Hosts for REST API
administrators. FortiOS 7.6.x can generate API tokens with an expiration time.

Important: Fortinet's documented method for retrieving an IPsec PSK in plaintext
uses a `super_admin` session. A read-only profile may be sufficient for ordinary
inventory, but do **not** assume it will be allowed to expose decrypted secrets.
If `list` works but `show`/`export` does not return plaintext, check the access
profile first.

## Method A — GUI

You need an administrator with `super_admin` privileges to create a REST API
administrator.

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
    use the minimum profile that works for the required operation

Trusted Hosts:
    your management workstation or management subnet

CORS Allow Origin:
    leave unset unless you specifically need browser CORS access

PKI Group:
    optional; useful if you already use client-certificate authentication
```

For a single management workstation, use a host route rather than a broad
network whenever practical.

Example:

```text
10.20.12.34/32
```

When the REST API administrator is created in the GUI, FortiGate generates an
API token.

**Copy it immediately. The generated token is shown only once.**

Do not paste it into tickets, shell history, Git, notes synchronized to
untrusted systems, or command-line arguments.

### Important GUI limitation

Fortinet documents that a REST API user created through the GUI cannot be
assigned the built-in `super_admin` profile from the GUI.

If plaintext-secret recovery specifically requires `super_admin`, change the API
user's profile from the CLI:

```text
config system api-user
    edit "fortirecover"
        set accprofile "super_admin"
    next
end
```

For a temporary recovery account, combine that privilege with a narrow Trusted
Host and a short-lived token.

---

## Method B — CLI

This method is convenient because the account, Trusted Host, VDOM scope, profile,
and token lifetime are explicit.

Example for a single trusted workstation:

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

Replace:

```text
10.20.12.34
```

with the **source IP that FortiGate actually sees for your API requests**.

If you are coming through NAT, a management VPN, a jump host, another VDOM, or a
different routing path, the apparent source address may not be the address you
initially expect.

### Generate the token

FortiOS 7.6.x supports an optional expiration time in minutes:

```text
execute api-user generate-key fortirecover 60
```

This example creates a token valid for approximately **60 minutes**.

Fortinet documents the expiry range as:

```text
1 .. 10080 minutes
```

`10080` minutes is seven days.

If you omit the expiry:

```text
execute api-user generate-key fortirecover
```

the generated key does not have that configured expiration. For a recovery task,
a short-lived token is strongly preferable.

Again:

**The generated API token is displayed only once. Save it at creation time.**

If a token is lost, generate a new one rather than trying to recover the old
token.

---

# Using the token with fortirecover

## fish shell

For the current shell session:

```fish
set -x FORTIGATE_HOST https://10.10.10.100
set -x FORTIGATE_API_TOKEN 'paste-token-here'
```

Then:

```fish
python fortirecover-v0.4.py list --insecure
```

The script sends the token using:

```text
Authorization: Bearer <token>
```

It does **not** put the token into the URL.

This matters on modern FortiOS versions because URL query-string API tokens are
disabled by default on newer releases and are also easier to leak through logs,
history, proxies, and monitoring systems.

## Avoid shell history entirely

If `FORTIGATE_API_TOKEN` is not set, simply run:

```fish
python fortirecover-v0.4.py \
    --host https://10.10.10.100 \
    list \
    --insecure
```

The program prompts:

```text
FortiGate API token (FORTIGATE_API_TOKEN is unset):
```

Input is hidden with `getpass`, so the token is not echoed and is not stored as
part of the command line.

This is the preferable mode for a one-off recovery.

---

# Verify access before exposing secrets

Start with:

```fish
python fortirecover-v0.4.py \
    --host https://10.10.10.100 \
    list \
    --only ipsec \
    --insecure
```

This performs an inventory request **without**
`plain-text-password=1`.

If that works, test one known tunnel before dumping everything:

```fish
python fortirecover-v0.4.py \
    --host https://10.10.10.100 \
    show \
    --only ipsec \
    --match Azure \
    --insecure
```

The `show` command deliberately warns that plaintext secrets are about to be
written to terminal scrollback.

Expected output shape:

```text
ipsec  Azure-S2S  psksecret  exact-plaintext-secret
```

---

# Export for migration/recovery

Use a directory outside Git:

```fish
python fortirecover-v0.4.py \
    --host https://10.10.10.100 \
    export /tmp/fortigate-recovery.json \
    --insecure
```

`export` always means:

```text
full supported API objects
+
recoverable plaintext credentials
```

The output file is created with permissions:

```text
0600
```

The tool refuses to export anywhere inside a Git repository or worktree. It
walks upward from the destination directory looking for `.git`, so this is also
blocked:

```text
~/src/my-project/private/recovery.json
```

when:

```text
~/src/my-project/.git
```

exists.

There is deliberately no Git-safety override.

---

# Supported secret-bearing objects

Current version supports:

```text
IPsec Phase 1
    psksecret

RADIUS
    secret
    secondary-secret
    tertiary-secret
    rsso-secret

TACACS+
    key
    secondary-key
    tertiary-key
```

Fortinet documents `plain-text-password=1` for IPsec PSK recovery and also for
RADIUS/TACACS+ shared secrets.

Not every password on a FortiGate is recoverable. For example, credentials that
are stored only as a one-way hash cannot be reconstructed as plaintext.

---

# VDOM notes

The API user can be scoped with:

```text
set vdom "root"
```

or other appropriate VDOMs.

The program also supports:

```fish
--vdom VDOM_NAME
```

Example:

```fish
python fortirecover-v0.4.py \
    --host https://10.10.10.100 \
    show \
    --vdom branch01 \
    --only ipsec \
    --insecure
```

Fortinet specifically warns that, in multi-VDOM configurations, access to
plaintext IPsec configuration can depend on the VDOM associated with the
interface through which you reach the FortiGate. If an object seems to be
missing, verify both the API user's VDOM scope and the management interface/path
used for the request.

---

# Trusted Hosts troubleshooting

If the tool gets HTTP 401/403 even though the token looks correct, check:

1. The API user's Trusted Hosts include the source IP FortiGate sees.
2. The administrator/profile used to create/manage the API account is not
   restricted in a way that unexpectedly blocks the same management source.
3. The API user is assigned to the correct VDOM.
4. The token has not expired.
5. The access profile permits reading the requested CMDB path.
6. For plaintext recovery, the profile is sufficiently privileged to expose the
   decrypted field.
7. You are connecting through the expected FortiGate interface/VDOM.

Fortinet notes that when Trusted Hosts are configured, the API client's address
must be allowed appropriately for the relevant administrator/API-user context.

---

# After recovery

A plaintext export should be treated like a credential vault.

Recommended cleanup after the migration/recovery is finished:

```text
1. Verify that the recovered credentials work on the replacement equipment.
2. Remove the plaintext JSON from ordinary working directories.
3. Securely retain it only if there is a deliberate credential-backup policy.
4. Delete or disable the temporary `fortirecover` API administrator.
5. If the API account is retained, regenerate its token so the recovery token
   can no longer be used.
6. Rotate particularly sensitive shared secrets when practical.
```

For a temporary API user, removal is straightforward:

```text
config system api-user
    delete "fortirecover"
end
```

---

# Fortinet references

Official Fortinet documentation used for these instructions:

- REST API administrator:
  https://docs.fortinet.com/document/fortigate/7.6.2/administration-guide/399023/rest-api-administrator

- Using APIs / token expiry / Trusted Hosts:
  https://docs.fortinet.com/document/fortigate/latest/administration-guide/940602/using-apis

- `config system api-user` CLI reference:
  https://docs.fortinet.com/document/fortigate/7.6.0/cli-reference/625450553/config-system-api-user

- Recovering IPsec PSK using `plain-text-password=1`:
  https://community.fortinet.com/fortigate-3/technical-tip-use-the-fortigate-api-to-recover-an-ipsec-pre-shared-key-in-plain-text-format-177878

- Recovering RADIUS/TACACS+ shared secrets:
  https://community.fortinet.com/fortigate-3/technical-tip-using-the-fortigate-api-to-retrieve-the-radius-or-tacacs-secret-key-227412

- API token generation and expiry:
  https://community.fortinet.com/fortigate-3/technical-tip-how-to-create-a-rest-api-admin-user-and-assign-it-to-an-admin-profile-130221
