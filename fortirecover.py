#!/usr/bin/env python3
from __future__ import annotations

import argparse
import errno
import getpass
import json
import os
import socket
import subprocess
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "0.5.2"

RESOURCES: dict[str, dict[str, Any]] = {
    "ipsec": {
        "path": "/api/v2/cmdb/vpn.ipsec/phase1-interface",
        "label": "IPsec Phase 1",
        "support": "documented",
        "secrets": {"psksecret"},
        "identity": ("name",),
        "match": ("name", "remote-gw"),
        "columns": (("name", "NAME"), ("remote-gw", "REMOTE"),
                    ("interface", "INTERFACE"), ("ike-version", "IKE")),
    },
    "radius": {
        "path": "/api/v2/cmdb/user/radius",
        "label": "RADIUS",
        "support": "documented",
        "secrets": {"secret", "secondary-secret", "tertiary-secret", "rsso-secret"},
        "identity": ("name",),
        "match": ("name", "server", "secondary-server", "tertiary-server"),
        "columns": (("name", "NAME"), ("server", "PRIMARY"),
                    ("secondary-server", "SECONDARY"), ("tertiary-server", "TERTIARY")),
    },
    "tacacs": {
        "path": "/api/v2/cmdb/user/tacacs+",
        "label": "TACACS+",
        "support": "documented",
        "secrets": {"key", "secondary-key", "tertiary-key"},
        "identity": ("name",),
        "match": ("name", "server", "secondary-server", "tertiary-server"),
        "columns": (("name", "NAME"), ("server", "PRIMARY"),
                    ("secondary-server", "SECONDARY"), ("tertiary-server", "TERTIARY")),
    },
    "ldap": {
        "path": "/api/v2/cmdb/user/ldap",
        "label": "LDAP",
        "support": "best-effort",
        "secrets": {"password"},
        "identity": ("name",),
        "match": ("name", "server", "secondary-server", "tertiary-server", "username"),
        "columns": (("name", "NAME"), ("server", "PRIMARY"),
                    ("username", "BIND USER"), ("secure", "SECURE"), ("type", "TYPE")),
    },
    "local": {
        "path": "/api/v2/cmdb/user/local",
        "label": "Local users",
        "support": "best-effort",
        "secrets": {"passwd", "ppk-secret"},
        "identity": ("name",),
        "match": ("name", "ldap-server", "radius-server", "tacacs+-server"),
        "columns": (("name", "NAME"), ("status", "STATUS"), ("two-factor", "2FA"),
                    ("ldap-server", "LDAP"), ("radius-server", "RADIUS")),
    },
    "snmp-community": {
        # `config system snmp community` maps to CMDB namespace system.snmp.
        "path": "/api/v2/cmdb/system.snmp/community",
        "label": "SNMP v1/v2c communities",
        "support": "best-effort",
        # `name` is the community string itself. Never use it as display identity.
        "secrets": {"name"},
        "identity": ("id",),
        "match": ("id",),
        "columns": (("id", "ID"), ("status", "STATUS"),
                    ("query-v1-status", "V1 QUERY"), ("query-v2c-status", "V2C QUERY"),
                    ("trap-v2c-status", "V2C TRAP")),
    },
    "snmp-user": {
        # `config system snmp user` maps to CMDB namespace system.snmp.
        "path": "/api/v2/cmdb/system.snmp/user",
        "label": "SNMPv3 users",
        "support": "best-effort",
        "secrets": {"auth-pwd", "priv-pwd"},
        "identity": ("name",),
        "match": ("name",),
        "columns": (("name", "NAME"), ("security-level", "SECURITY"),
                    ("auth-proto", "AUTH"), ("priv-proto", "PRIV"), ("status", "STATUS")),
    },
}

STATES = ("plaintext", "encrypted", "masked", "hashed", "empty")
HASH_PREFIXES = ("$1$", "$2a$", "$2b$", "$2y$", "$5$", "$6$")
HASH_TAG_PREFIXES = ("{SHA}", "{SSHA}", "{MD5}")
RED, YELLOW, GREEN, RESET = "\033[31;1m", "\033[33;1m", "\033[32;1m", "\033[0m"


def _paint(text: str, color: str) -> str:
    if sys.stderr.isatty() and "NO_COLOR" not in os.environ:
        return f"{color}{text}{RESET}"
    return text


def danger(msg: str) -> None:
    print(_paint(f"DANGER: {msg}", RED), file=sys.stderr)


def warn(msg: str) -> None:
    print(_paint(f"WARNING: {msg}", YELLOW), file=sys.stderr)


def good(msg: str) -> None:
    print(_paint(msg, GREEN))


class AppError(RuntimeError):
    pass


class FortiGate:
    def __init__(self, host: str, token: str, *, insecure: bool = False,
                 ca_file: str | None = None, timeout: float = 15,
                 vdom: str | None = None) -> None:
        if not host.startswith(("https://", "http://")):
            host = "https://" + host
        self.base = host.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.vdom = vdom

        parsed = urllib.parse.urlparse(self.base)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise AppError(f"Invalid FortiGate address: {host!r}")

        if parsed.scheme == "http":
            danger("Plain HTTP is being used. Token and secrets can be intercepted.")
            self.ctx = None
        elif insecure:
            warn("TLS certificate verification is DISABLED (--insecure).")
            self.ctx = ssl._create_unverified_context()
        else:
            try:
                self.ctx = ssl.create_default_context(cafile=ca_file)
            except (OSError, ssl.SSLError) as exc:
                raise AppError(f"Cannot load CA file: {exc}") from exc

    def get(self, path: str, *, plaintext: bool) -> dict[str, Any]:
        params: dict[str, str] = {}
        if self.vdom:
            params["vdom"] = self.vdom
        if plaintext:
            params["plain-text-password"] = "1"

        url = self.base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)

        request = urllib.request.Request(url, headers={
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
            "User-Agent": f"fortirecover/{VERSION}",
        })

        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.ctx) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace").strip()
            tail = f" FortiGate said: {body[:300]}" if body else ""
            messages = {
                400: f"HTTP 400 Bad Request while reading {path}. Check CMDB path and FortiOS support.",
                401: "HTTP 401 Unauthorized. Check API token, expiry, and REST API access.",
                403: "HTTP 403 Forbidden. Check API admin profile, VDOM, Trusted Hosts, and permissions.",
                404: f"HTTP 404 for {path}. Endpoint may be unavailable on this FortiOS build/scope.",
            }
            raise AppError(messages.get(exc.code, f"HTTP {exc.code} while reading {path}.") + tail) from exc
        except urllib.error.URLError as exc:
            reason = exc.reason
            if isinstance(reason, ssl.SSLCertVerificationError):
                msg = "TLS certificate verification failed. Use a trusted certificate, --ca-file, or --insecure."
            elif isinstance(reason, socket.gaierror):
                msg = f"DNS/name resolution failed: {reason}"
            elif isinstance(reason, ConnectionRefusedError):
                msg = f"Connection refused by {self.base}. Check address/port/admin HTTPS."
            elif isinstance(reason, socket.timeout):
                msg = f"Connection timed out after {self.timeout:g} seconds."
            else:
                msg = f"Cannot reach FortiGate: {reason}"
            raise AppError(msg) from exc
        except TimeoutError as exc:
            raise AppError(f"Connection timed out after {self.timeout:g} seconds.") from exc

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            preview = raw[:250].decode("utf-8", "replace")
            raise AppError(f"FortiGate returned non-JSON data: {preview!r}") from exc

        if not isinstance(data, dict):
            raise AppError(f"Unexpected API response type: {type(data).__name__}")
        if data.get("status") == "error":
            raise AppError(f"FortiGate API error: {data.get('error', data.get('message', data))}")
        return data


def _results(payload: dict[str, Any]) -> list[dict[str, Any]]:
    value = payload.get("results", [])
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return [value] if isinstance(value, dict) else []


def selected_resources(value: str | None) -> list[str]:
    if not value:
        return list(RESOURCES)
    selected: list[str] = []
    for part in value.split(","):
        name = part.strip().lower()
        if not name:
            continue
        if name not in RESOURCES:
            raise AppError(f"Unknown resource {name!r}. Valid: {', '.join(RESOURCES)}")
        if name not in selected:
            selected.append(name)
    if not selected:
        raise AppError("No valid resources selected.")
    return selected


def fetch(fg: FortiGate, resource: str, *, plaintext: bool,
          match: str | None) -> list[dict[str, Any]]:
    items = _results(fg.get(RESOURCES[resource]["path"], plaintext=plaintext))
    if not match:
        return items
    needle = match.casefold()
    fields = RESOURCES[resource]["match"]
    return [item for item in items
            if any(needle in str(item.get(field, "")).casefold() for field in fields)]


def _fmt(value: Any, limit: int = 48) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    text = str(value).replace("\n", "\\n")
    return text if len(text) <= limit else text[:limit - 1] + "…"


def show_inventory(items: list[dict[str, Any]], resource: str) -> None:
    columns = RESOURCES[resource]["columns"]
    headers = [header for _, header in columns]
    rows = [[_fmt(item.get(key, "")) for key, _ in columns] for item in items]
    widths = [max([len(headers[i]), *[len(row[i]) for row in rows]]) for i in range(len(headers))]
    print(f"\n[{RESOURCES[resource]['label']}]  entries: {len(rows)}")
    print("  ".join(headers[i].ljust(widths[i]) for i in range(len(headers))))
    print("  ".join("-" * widths[i] for i in range(len(headers))))
    for row in rows:
        print("  ".join(row[i].ljust(widths[i]) for i in range(len(headers))))


def find_secrets(value: Any, names: set[str], prefix: str = "") -> list[tuple[str, Any]]:
    found: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else key
            if key in names:
                found.append((path, child))
            else:
                found.extend(find_secrets(child, names, path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(find_secrets(child, names, f"{prefix}[{index}]" if prefix else f"[{index}]"))
    return found


def classify_secret(value: Any, *, recognize_hash: bool = False) -> str:
    """Classify a secret value without guessing hashes unless explicitly allowed.

    Hash-looking prefixes are valid plaintext for shared secrets.  Callers must
    opt in only for fields whose schema can actually contain one-way hashes.
    """
    if value in (None, "", []):
        return "empty"
    if not isinstance(value, str):
        return "plaintext"
    text = value.strip()
    if not text:
        return "empty"
    if text.startswith("ENC "):
        return "encrypted"
    if text == "FortinetPasswordMask" or (len(text) >= 4 and set(text) == {"*"}):
        return "masked"
    if recognize_hash and (
        text.upper().startswith(HASH_TAG_PREFIXES) or text.startswith(HASH_PREFIXES)
    ):
        return "hashed"
    return "plaintext"


def _secret_field_name(path: str) -> str:
    return path.rsplit(".", 1)[-1]


def classify_resource_secret(value: Any, resource: str, path: str) -> str:
    """Classify using field semantics from RESOURCES instead of value shape alone."""
    hash_fields = RESOURCES[resource].get("hash_fields", set())
    return classify_secret(value, recognize_hash=_secret_field_name(path) in hash_fields)


def object_identity(item: dict[str, Any], resource: str) -> str:
    secrets = RESOURCES[resource]["secrets"]
    for field in RESOURCES[resource]["identity"]:
        if field not in secrets and item.get(field) not in (None, ""):
            return str(item[field])
    return "<object>"


def audit_summary(items: list[dict[str, Any]], resource: str) -> dict[str, Any]:
    counts: Counter[str] = Counter()
    for item in items:
        for path, value in find_secrets(item, RESOURCES[resource]["secrets"]):
            counts[classify_resource_secret(value, resource, path)] += 1
    total = sum(counts.values())
    unresolved = counts["encrypted"] + counts["masked"] + counts["hashed"]
    if not items:
        result = "NO OBJECTS"
    elif not total:
        result = "NO FIELDS"
    elif counts["plaintext"] and unresolved:
        result = "PARTIAL"
    elif counts["plaintext"]:
        result = "OK"
    elif unresolved:
        result = "UNRECOVERED"
    else:
        result = "EMPTY"
    return {
        "support": RESOURCES[resource]["support"],
        "objects": len(items),
        "secret_fields_seen": total,
        "states": {state: counts[state] for state in STATES},
        "result": result,
    }


def show_audit(rows: list[tuple[str, dict[str, Any]]]) -> None:
    headers = ("RESOURCE", "SUPPORT", "OBJECTS", "FIELDS", "PLAIN", "ENC", "MASK", "HASH", "EMPTY", "RESULT")
    table = []
    for resource, summary in rows:
        states = summary["states"]
        table.append([resource, summary["support"], str(summary["objects"]),
                      str(summary["secret_fields_seen"]), str(states["plaintext"]),
                      str(states["encrypted"]), str(states["masked"]), str(states["hashed"]),
                      str(states["empty"]), summary["result"]])
    widths = [max([len(headers[i]), *[len(row[i]) for row in table]]) for i in range(len(headers))]
    print("  ".join(headers[i].ljust(widths[i]) for i in range(len(headers))))
    print("  ".join("-" * widths[i] for i in range(len(headers))))
    for row in table:
        print("  ".join(row[i].ljust(widths[i]) for i in range(len(headers))))


def show_secrets(items: list[dict[str, Any]], resource: str) -> None:
    plain = False
    unresolved: Counter[str] = Counter()
    for item in items:
        identity = object_identity(item, resource)
        for path, value in find_secrets(item, RESOURCES[resource]["secrets"]):
            state = classify_resource_secret(value, resource, path)
            if state == "plaintext":
                plain = True
                print(f"{resource}\t{identity}\t{path}\t{value}")
            elif state != "empty":
                unresolved[state] += 1
    if not plain:
        print(f"{resource}\t<no recoverable plaintext secrets>")
    if unresolved:
        detail = ", ".join(f"{state}={count}" for state, count in sorted(unresolved.items()))
        warn(f"{RESOURCES[resource]['label']}: secret fields not recovered ({detail}). Run 'audit'.")


def find_git_context(directory: Path) -> str | None:
    directory = directory.resolve()
    try:
        env = {key: value for key, value in os.environ.items()
               if key not in {"GIT_DIR", "GIT_WORK_TREE"}}
        probe = subprocess.run(
            ["git", "-C", str(directory), "rev-parse", "--is-inside-work-tree",
             "--is-inside-git-dir", "--is-bare-repository", "--show-toplevel"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            timeout=3, check=False, env=env,
        )
        if probe.returncode == 0:
            lines = [line.strip() for line in probe.stdout.splitlines() if line.strip()]
            return f"Git repository detected by git rev-parse: {lines[-1] if lines else directory}"
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        pass
    current = directory
    while True:
        marker = current / ".git"
        if marker.exists() or marker.is_symlink():
            return f"Git marker detected: {marker}"
        if current.parent == current:
            break
        current = current.parent
    if (directory / "HEAD").is_file() and (directory / "objects").is_dir() and (directory / "refs").is_dir():
        return f"Bare Git repository detected: {directory}"
    return None


def validate_export_path(path: Path, force: bool) -> Path:
    path = path.expanduser()
    parent = path.parent.resolve()
    git_context = find_git_context(parent)
    if git_context:
        danger("REFUSING TO EXPORT PLAINTEXT SECRETS INSIDE A GIT REPOSITORY.")
        danger(git_context)
        danger("Choose a directory outside every Git worktree/repository.")
        raise AppError("Unsafe export destination.")
    if not parent.exists():
        raise AppError(f"Destination directory does not exist: {parent}")
    if not parent.is_dir():
        raise AppError(f"Destination parent is not a directory: {parent}")
    if path.exists() and path.is_dir():
        raise AppError(f"Destination is a directory, not a JSON file: {path}")
    if path.exists() and not force:
        raise AppError(f"File already exists: {path}. Use --force only if overwrite is intentional.")
    return path


def write_json(path: Path, data: Any, force: bool) -> None:
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if force else os.O_EXCL)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise AppError(f"File already exists: {path}") from exc
    except PermissionError as exc:
        raise AppError(f"Permission denied while creating {path}") from exc
    except OSError as exc:
        if exc.errno == errno.ENOSPC:
            raise AppError(f"No space left on device while creating {path}") from exc
        if exc.errno == errno.EROFS:
            raise AppError(f"Filesystem is read-only: {path.parent}") from exc
        raise AppError(f"Cannot create {path}: {exc}") from exc
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(path, 0o600)
    except Exception:
        path.unlink(missing_ok=True)
        raise


def token_from_args(args: argparse.Namespace) -> str:
    if getattr(args, "token_file", None):
        try:
            token = Path(args.token_file).expanduser().read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise AppError(f"Cannot read token file: {exc}") from exc
        if not token:
            raise AppError("Token file is empty.")
        return token
    token = os.environ.get(getattr(args, "token_env", "FORTIGATE_API_TOKEN"), "").strip()
    if token:
        return token
    token = getpass.getpass(f"FortiGate API token ({getattr(args, 'token_env', 'FORTIGATE_API_TOKEN')} is unset): ").strip()
    if not token:
        raise AppError("No API token supplied.")
    return token


def add_connection_options(parser: argparse.ArgumentParser, suppress: bool = False) -> None:
    default = argparse.SUPPRESS if suppress else None
    parser.add_argument("--host", default=argparse.SUPPRESS if suppress else os.environ.get("FORTIGATE_HOST"),
                        help="FortiGate URL/IP[:port], or FORTIGATE_HOST")
    parser.add_argument("--vdom", default=default, help="VDOM name")
    parser.add_argument("--token-env", default=argparse.SUPPRESS if suppress else "FORTIGATE_API_TOKEN",
                        help="environment variable containing API token")
    parser.add_argument("--token-file", default=default, help="read API token from file")
    parser.add_argument("--ca-file", default=default, help="CA bundle for TLS verification")
    parser.add_argument("--insecure", action="store_true", default=default,
                        help="disable TLS certificate verification")
    parser.add_argument("--timeout", type=float, default=argparse.SUPPRESS if suppress else 15.0,
                        help="HTTP timeout seconds")


def add_filters(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--only", help="comma-separated resources: " + ",".join(RESOURCES) + " (default: all)")
    parser.add_argument("--match", help="filter by non-secret name/server/identity fields")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="fortirecover", description="Read-only FortiGate recovery helper.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Commands:
  list          inventory; never request plaintext secrets
  audit         classify recoverability without printing values
  show          print only actually recovered plaintext secrets
  export FILE   save recovery JSON and audit summary

Documented plaintext recovery: ipsec, radius, tacacs.
Other resources are best-effort; verify them with audit.
""",
    )
    root.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    add_connection_options(root)
    sub = root.add_subparsers(dest="command", required=True)
    for command, help_text in (
        ("list", "inventory without requesting plaintext secrets"),
        ("audit", "check recoverability without printing secret values"),
        ("show", "show actually recovered plaintext secrets"),
    ):
        child = sub.add_parser(command, help=help_text)
        add_connection_options(child, True)
        add_filters(child)
    export = sub.add_parser("export", help="export recovery JSON")
    add_connection_options(export, True)
    export.add_argument("file", help="destination JSON file")
    add_filters(export)
    export.add_argument("--force", action="store_true", help="overwrite existing file")
    return root


def main() -> int:
    args = parser().parse_args()
    if not getattr(args, "host", None):
        danger("--host is required unless FORTIGATE_HOST is set.")
        return 2
    try:
        fg = FortiGate(
            args.host, token_from_args(args), insecure=getattr(args, "insecure", False),
            ca_file=getattr(args, "ca_file", None), timeout=getattr(args, "timeout", 15.0),
            vdom=getattr(args, "vdom", None),
        )
        resources = selected_resources(getattr(args, "only", None))
        match = getattr(args, "match", None)

        if args.command == "list":
            failed = False
            for resource in resources:
                try:
                    show_inventory(fetch(fg, resource, plaintext=False, match=match), resource)
                except AppError as exc:
                    failed = True
                    danger(f"{RESOURCES[resource]['label']}: {exc}")
            if failed:
                warn("Some resources failed; successful inventory is shown above.")
            return int(failed)

        if args.command == "audit":
            warn("AUDIT requests plain-text-password=1 but never prints secret values.")
            rows, failed = [], False
            for resource in resources:
                try:
                    rows.append((resource, audit_summary(fetch(fg, resource, plaintext=True, match=match), resource)))
                except AppError as exc:
                    failed = True
                    danger(f"{RESOURCES[resource]['label']}: {exc}")
            if rows:
                show_audit(rows)
            if failed:
                warn("Some resources failed; successful audit results are shown above.")
            return int(failed)

        if args.command == "show":
            danger("PLAINTEXT SECRETS WILL BE PRINTED TO THIS TERMINAL.")
            warn("Terminal scrollback, screen sharing, and logs may expose them.")
            failed = False
            for resource in resources:
                try:
                    show_secrets(fetch(fg, resource, plaintext=True, match=match), resource)
                except AppError as exc:
                    failed = True
                    danger(f"{RESOURCES[resource]['label']}: {exc}")
            if failed:
                warn("Some resources failed; successful secrets are shown above.")
            return int(failed)

        print(f"fortirecover {VERSION}", file=sys.stderr)
        out = validate_export_path(Path(args.file), args.force)
        danger("EXPORT MAY CONTAIN PLAINTEXT CREDENTIALS.")
        warn("The JSON file will be created with permissions 0600.")
        bundle: dict[str, Any] = {
            "tool": "fortirecover", "tool_version": VERSION, "format_version": 2,
            "created_utc": datetime.now(timezone.utc).isoformat(), "fortigate": fg.base,
            "vdom": fg.vdom, "plaintext_requested": True,
            "resources": {}, "audit": {}, "errors": {},
        }
        successes = unresolved = 0
        for resource in resources:
            try:
                items = fetch(fg, resource, plaintext=True, match=match)
                summary = audit_summary(items, resource)
                bundle["resources"][resource] = items
                bundle["audit"][resource] = summary
                unresolved += sum(summary["states"][state] for state in ("encrypted", "masked", "hashed"))
                successes += 1
            except AppError as exc:
                bundle["errors"][resource] = str(exc)
                danger(f"{RESOURCES[resource]['label']}: {exc}")
        if not successes:
            raise AppError("Every requested resource failed; no file was written.")
        write_json(out, bundle, args.force)
        good(f"Wrote recovery bundle: {out}")
        print("Plaintext requested: yes")
        print("Permissions: 0600")
        if unresolved:
            warn(f"{unresolved} secret field(s) remained encrypted, masked, or hashed; see 'audit' in JSON.")
        if bundle["errors"]:
            warn("PARTIAL EXPORT: see the top-level 'errors' object in the JSON.")
            return 1
        return 0
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except AppError as exc:
        danger(str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
