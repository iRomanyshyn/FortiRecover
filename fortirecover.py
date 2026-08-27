#!/usr/bin/env python3
"""
fortirecover.py — small read-only FortiGate secret recovery helper.

Designed for FortiOS 7.6.x REST API.
- Uses Authorization: Bearer <token>
- Never puts the API token in the URL
- TLS verification is ON by default
- Secrets are masked unless --reveal or --plaintext is explicitly used
- Plaintext exports are created with mode 0600
"""

from __future__ import annotations

import argparse
import copy
import getpass
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


RESOURCES = {
    "ipsec": {
        "path": "/api/v2/cmdb/vpn.ipsec/phase1-interface",
        "label": "IPsec Phase 1",
        "secret_fields": {"psksecret"},
        "columns": [
            ("name", "NAME"),
            ("remote-gw", "REMOTE"),
            ("interface", "INTERFACE"),
            ("ike-version", "IKE"),
            ("psksecret", "PSK"),
        ],
    },
    "radius": {
        "path": "/api/v2/cmdb/user/radius",
        "label": "RADIUS",
        "secret_fields": {
            "secret",
            "secondary-secret",
            "tertiary-secret",
            "rsso-secret",
        },
        "columns": [
            ("name", "NAME"),
            ("server", "PRIMARY"),
            ("secondary-server", "SECONDARY"),
            ("tertiary-server", "TERTIARY"),
            ("secret", "SECRET"),
        ],
    },
    "tacacs": {
        "path": "/api/v2/cmdb/user/tacacs+",
        "label": "TACACS+",
        "secret_fields": {"key", "secondary-key", "tertiary-key"},
        "columns": [
            ("name", "NAME"),
            ("server", "PRIMARY"),
            ("secondary-server", "SECONDARY"),
            ("tertiary-server", "TERTIARY"),
            ("key", "KEY"),
        ],
    },
}

ALL_SECRET_FIELDS = set().union(*(r["secret_fields"] for r in RESOURCES.values()))


class FortiAPIError(RuntimeError):
    pass


class FortiGate:
    def __init__(
        self,
        host: str,
        token: str,
        *,
        verify_tls: bool = True,
        ca_file: str | None = None,
        timeout: float = 15.0,
        vdom: str | None = None,
    ) -> None:
        if not host.startswith(("https://", "http://")):
            host = "https://" + host
        self.base = host.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.vdom = vdom

        if self.base.startswith("http://"):
            print(
                "WARNING: using plain HTTP. API token and recovered secrets can be exposed.",
                file=sys.stderr,
            )
            self.ssl_context = None
        elif verify_tls:
            self.ssl_context = ssl.create_default_context(cafile=ca_file)
        else:
            self.ssl_context = ssl._create_unverified_context()

    def get(self, path: str, *, plaintext_passwords: bool = False) -> dict[str, Any]:
        params: dict[str, str] = {}
        if self.vdom:
            params["vdom"] = self.vdom
        if plaintext_passwords:
            params["plain-text-password"] = "1"

        url = self.base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)

        req = urllib.request.Request(
            url,
            method="GET",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/json",
                "User-Agent": "fortirecover/0.1",
            },
        )

        try:
            with urllib.request.urlopen(
                req, timeout=self.timeout, context=self.ssl_context
            ) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")
            raise FortiAPIError(
                f"HTTP {exc.code} from FortiGate for {path}: {body[:500]}"
            ) from exc
        except urllib.error.URLError as exc:
            raise FortiAPIError(f"Cannot reach FortiGate: {exc.reason}") from exc

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            preview = raw[:300].decode("utf-8", "replace")
            raise FortiAPIError(f"FortiGate returned non-JSON data: {preview}") from exc

        if isinstance(payload, dict):
            status = payload.get("status")
            http_status = payload.get("http_status")
            if status == "error" or (isinstance(http_status, int) and http_status >= 400):
                raise FortiAPIError(
                    f"FortiGate API error for {path}: "
                    f"{payload.get('error', payload.get('message', payload))}"
                )
            return payload

        raise FortiAPIError(f"Unexpected API response type: {type(payload).__name__}")


def get_results(payload: dict[str, Any]) -> list[dict[str, Any]]:
    results = payload.get("results", [])
    if isinstance(results, list):
        return [x for x in results if isinstance(x, dict)]
    if isinstance(results, dict):
        return [results]
    return []


def secret_mask(value: Any) -> str:
    if value in (None, "", []):
        return ""
    text = str(value)
    if text.startswith("ENC "):
        return "<encrypted>"
    return "<hidden>"


def redact_tree(value: Any, secret_fields: set[str]) -> Any:
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if k in secret_fields:
                out[k] = secret_mask(v)
            else:
                out[k] = redact_tree(v, secret_fields)
        return out
    if isinstance(value, list):
        return [redact_tree(v, secret_fields) for v in value]
    return value


def filter_entries(entries: list[dict[str, Any]], needle: str | None) -> list[dict[str, Any]]:
    if not needle:
        return entries
    n = needle.casefold()
    return [
        e
        for e in entries
        if n in str(e.get("name", "")).casefold()
        or n in str(e.get("server", "")).casefold()
        or n in str(e.get("remote-gw", "")).casefold()
    ]


def format_cell(value: Any, width_limit: int | None = 48) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    text = str(value).replace("\n", "\\n")
    if width_limit is not None and len(text) > width_limit:
        return text[: width_limit - 1] + "…"
    return text


def walk_secrets(
    value: Any,
    secret_fields: set[str],
    prefix: str = "",
) -> list[tuple[str, Any]]:
    found: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else key
            if key in secret_fields:
                found.append((path, child))
            else:
                found.extend(walk_secrets(child, secret_fields, path))
    elif isinstance(value, list):
        for i, child in enumerate(value):
            path = f"{prefix}[{i}]" if prefix else f"[{i}]"
            found.extend(walk_secrets(child, secret_fields, path))
    return found


def print_secrets_only(
    entries: list[dict[str, Any]],
    resource: str,
    reveal: bool,
) -> None:
    spec = RESOURCES[resource]
    for entry in entries:
        name = str(entry.get("name", ""))
        for path, value in walk_secrets(entry, spec["secret_fields"]):
            shown = value if reveal else secret_mask(value)
            # TSV makes this easy to copy, grep, cut, or redirect.
            print(f"{resource}\\t{name}\\t{path}\\t{shown}")


def print_table(entries: list[dict[str, Any]], resource: str, reveal: bool) -> None:
    spec = RESOURCES[resource]
    cols = spec["columns"]
    secret_fields = spec["secret_fields"]

    rows: list[list[str]] = []
    for entry in entries:
        row = []
        for key, _header in cols:
            val = entry.get(key, "")
            if key in secret_fields and not reveal:
                val = secret_mask(val)
            # Never truncate a plaintext secret: recovery output must be exact.
            limit = None if (key in secret_fields and reveal) else 48
            row.append(format_cell(val, limit))
        rows.append(row)

    headers = [header for _key, header in cols]
    widths = [
        max(len(headers[i]), *(len(row[i]) for row in rows)) if rows else len(headers[i])
        for i in range(len(headers))
    ]

    print(f"\n[{spec['label']}]  entries: {len(rows)}")
    print("  ".join(headers[i].ljust(widths[i]) for i in range(len(headers))))
    print("  ".join("-" * widths[i] for i in range(len(headers))))
    for row in rows:
        print("  ".join(row[i].ljust(widths[i]) for i in range(len(headers))))


def atomic_json_write(path: Path, data: Any, *, force: bool = False) -> None:
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)

    flags = os.O_WRONLY | os.O_CREAT
    if force:
        flags |= os.O_TRUNC
    else:
        flags |= os.O_EXCL

    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        raise FortiAPIError(
            f"{path} already exists. Use --force if you really want to overwrite it."
        )

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(path, 0o600)
    except Exception:
        try:
            path.unlink(missing_ok=True)
        finally:
            raise


def resolve_token(args: argparse.Namespace) -> str:
    if args.token_file:
        p = Path(args.token_file).expanduser()
        try:
            token = p.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise FortiAPIError(f"Cannot read token file {p}: {exc}") from exc
        if token:
            return token

    token = os.environ.get(args.token_env, "").strip()
    if token:
        return token

    token = getpass.getpass(f"FortiGate API token ({args.token_env} is unset): ").strip()
    if not token:
        raise FortiAPIError("No API token supplied.")
    return token


def fetch_resource(
    fg: FortiGate,
    resource: str,
    *,
    plaintext: bool,
    match: str | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    spec = RESOURCES[resource]
    payload = fg.get(spec["path"], plaintext_passwords=plaintext)
    entries = filter_entries(get_results(payload), match)
    return payload, entries


def run_list(args: argparse.Namespace, fg: FortiGate) -> int:
    resources = list(RESOURCES) if args.action == "all" else [args.action]

    if args.reveal:
        print(
            "WARNING: plaintext secrets will be printed to this terminal.",
            file=sys.stderr,
        )

    for resource in resources:
        _payload, entries = fetch_resource(
            fg, resource, plaintext=args.reveal, match=args.match
        )
        if args.secrets_only:
            print_secrets_only(entries, resource, reveal=args.reveal)
        else:
            print_table(entries, resource, reveal=args.reveal)

    return 0


def run_export(args: argparse.Namespace, fg: FortiGate) -> int:
    if not args.output:
        raise FortiAPIError("export requires --output FILE")

    exported: dict[str, Any] = {
        "tool": "fortirecover",
        "format_version": 1,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "fortigate": fg.base,
        "vdom": fg.vdom,
        "plaintext_secrets": bool(args.plaintext),
        "resources": {},
    }

    for resource, spec in RESOURCES.items():
        _payload, entries = fetch_resource(
            fg, resource, plaintext=args.plaintext, match=args.match
        )
        if not args.plaintext:
            entries = redact_tree(copy.deepcopy(entries), spec["secret_fields"])
        exported["resources"][resource] = entries

    out = Path(args.output)
    atomic_json_write(out, exported, force=args.force)

    mode = "PLAINTEXT secrets" if args.plaintext else "masked secrets"
    print(f"Wrote {out.expanduser()} with {mode}; permissions set to 0600.")
    if args.plaintext:
        print(
            "Treat this file as a credential vault: do not commit it to Git, "
            "sync it to untrusted storage, or attach it to tickets.",
            file=sys.stderr,
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fortirecover",
        description=(
            "Read-only FortiGate REST API helper for recovering/documenting "
            "IPsec PSKs and AAA shared secrets."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=r"""
Examples:
  export FORTIGATE_HOST=https://fgt.example.net
  export FORTIGATE_API_TOKEN='...'

  # Inventory only; secrets stay masked:
  fortirecover --ca-file ./corp-ca.pem ipsec
  fortirecover --ca-file ./corp-ca.pem all

  # Show one/few matching IPsec PSKs:
  fortirecover --ca-file ./corp-ca.pem ipsec --match Azure --reveal

  # Exact secret-only TSV, useful for copy/pipes:
  fortirecover --ca-file ./corp-ca.pem ipsec --match Azure       --reveal --secrets-only

  # Self-signed lab/admin certificate:
  fortirecover --insecure ipsec --reveal

  # Migration recovery bundle; plaintext, chmod 0600:
  fortirecover --ca-file ./corp-ca.pem export \
      --output ./fortigate-recovery.json --plaintext

  # Specific VDOM:
  fortirecover --vdom branch01 --insecure ipsec --reveal

Token precedence:
  1. --token-file
  2. environment variable named by --token-env (default FORTIGATE_API_TOKEN)
  3. hidden interactive prompt
""",
    )

    p.add_argument(
        "action",
        choices=["ipsec", "radius", "tacacs", "all", "export"],
        help="what to retrieve",
    )
    p.add_argument(
        "--host",
        default=os.environ.get("FORTIGATE_HOST"),
        help="FortiGate URL/IP[:port], or FORTIGATE_HOST",
    )
    p.add_argument(
        "--vdom",
        help="VDOM name; omitted means the API user's/default scope",
    )
    p.add_argument(
        "--token-env",
        default="FORTIGATE_API_TOKEN",
        help="environment variable holding the API token",
    )
    p.add_argument(
        "--token-file",
        help="read API token from a local file instead of environment/prompt",
    )
    p.add_argument(
        "--ca-file",
        help="CA/certificate bundle for FortiGate HTTPS verification",
    )
    p.add_argument(
        "--insecure",
        action="store_true",
        help="disable TLS certificate verification (not recommended)",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="HTTP timeout in seconds (default: 15)",
    )
    p.add_argument(
        "--match",
        help="case-insensitive substring filter on name/server/remote gateway",
    )
    p.add_argument(
        "--reveal",
        action="store_true",
        help="print plaintext secrets for list actions",
    )
    p.add_argument(
        "--secrets-only",
        action="store_true",
        help="print only secret fields as TSV: resource, name, field, value",
    )
    p.add_argument(
        "--output",
        "-o",
        help="output JSON file for export",
    )
    p.add_argument(
        "--plaintext",
        action="store_true",
        help="include plaintext secrets in export",
    )
    p.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing export file",
    )
    return p


def main() -> int:
    args = build_parser().parse_args()

    if not args.host:
        print(
            "error: --host is required unless FORTIGATE_HOST is set",
            file=sys.stderr,
        )
        return 2

    if args.action != "export" and args.plaintext:
        print("error: --plaintext is only valid with export; use --reveal", file=sys.stderr)
        return 2
    if args.action == "export" and args.reveal:
        print("error: --reveal is for list actions; use --plaintext", file=sys.stderr)
        return 2

    try:
        token = resolve_token(args)
        fg = FortiGate(
            args.host,
            token,
            verify_tls=not args.insecure,
            ca_file=args.ca_file,
            timeout=args.timeout,
            vdom=args.vdom,
        )
        if args.action == "export":
            return run_export(args, fg)
        return run_list(args, fg)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except (FortiAPIError, ssl.SSLError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
