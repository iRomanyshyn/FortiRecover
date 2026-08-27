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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "0.4.0"

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
        ],
    },
    "radius": {
        "path": "/api/v2/cmdb/user/radius",
        "label": "RADIUS",
        "secret_fields": {
            "secret", "secondary-secret", "tertiary-secret", "rsso-secret"
        },
        "columns": [
            ("name", "NAME"),
            ("server", "PRIMARY"),
            ("secondary-server", "SECONDARY"),
            ("tertiary-server", "TERTIARY"),
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
        ],
    },
}

RED = "\033[31;1m"
YELLOW = "\033[33;1m"
GREEN = "\033[32;1m"
RESET = "\033[0m"


def use_color() -> bool:
    return sys.stderr.isatty() and "NO_COLOR" not in os.environ


def paint(text: str, color: str) -> str:
    return f"{color}{text}{RESET}" if use_color() else text


def danger(msg: str) -> None:
    print(paint(f"DANGER: {msg}", RED), file=sys.stderr)


def warn(msg: str) -> None:
    print(paint(f"WARNING: {msg}", YELLOW), file=sys.stderr)


def good(msg: str) -> None:
    print(paint(msg, GREEN))


class AppError(RuntimeError):
    pass


class FortiGate:
    def __init__(
        self,
        host: str,
        token: str,
        *,
        insecure: bool = False,
        ca_file: str | None = None,
        timeout: float = 15,
        vdom: str | None = None,
    ):
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
            except (OSError, ssl.SSLError) as e:
                raise AppError(f"Cannot load CA file: {e}") from e

    def get(self, path: str, *, plaintext: bool) -> dict[str, Any]:
        params = {}
        if self.vdom:
            params["vdom"] = self.vdom
        if plaintext:
            params["plain-text-password"] = "1"

        url = self.base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)

        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/json",
                "User-Agent": f"fortirecover/{VERSION}",
            },
        )

        try:
            with urllib.request.urlopen(
                req, timeout=self.timeout, context=self.ctx
            ) as r:
                raw = r.read()
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace").strip()
            tail = f" FortiGate said: {body[:300]}" if body else ""
            if e.code == 401:
                raise AppError(
                    "HTTP 401 Unauthorized. Check API token, expiry, and REST API access."
                    + tail
                ) from e
            if e.code == 403:
                raise AppError(
                    "HTTP 403 Forbidden. Check API admin profile, VDOM scope, "
                    "trusted hosts, and permissions." + tail
                ) from e
            if e.code == 404:
                raise AppError(
                    f"HTTP 404 for {path}. Endpoint may be unavailable on this "
                    f"FortiOS version/scope.{tail}"
                ) from e
            raise AppError(f"HTTP {e.code} while reading {path}.{tail}") from e
        except urllib.error.URLError as e:
            reason = e.reason
            if isinstance(reason, ssl.SSLCertVerificationError):
                raise AppError(
                    "TLS certificate verification failed. Use a trusted certificate, "
                    "--ca-file, or --insecure."
                ) from e
            if isinstance(reason, socket.gaierror):
                raise AppError(f"DNS/name resolution failed: {reason}") from e
            if isinstance(reason, ConnectionRefusedError):
                raise AppError(
                    f"Connection refused by {self.base}. Check address/port/admin HTTPS."
                ) from e
            if isinstance(reason, socket.timeout):
                raise AppError(
                    f"Connection timed out after {self.timeout:g} seconds."
                ) from e
            raise AppError(f"Cannot reach FortiGate: {reason}") from e
        except TimeoutError as e:
            raise AppError(
                f"Connection timed out after {self.timeout:g} seconds."
            ) from e

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            preview = raw[:250].decode("utf-8", "replace")
            raise AppError(f"FortiGate returned non-JSON data: {preview!r}") from e

        if not isinstance(data, dict):
            raise AppError(f"Unexpected API response type: {type(data).__name__}")

        if data.get("status") == "error":
            raise AppError(
                f"FortiGate API error: {data.get('error', data.get('message', data))}"
            )
        return data


def results(payload: dict[str, Any]) -> list[dict[str, Any]]:
    r = payload.get("results", [])
    if isinstance(r, list):
        return [x for x in r if isinstance(x, dict)]
    if isinstance(r, dict):
        return [r]
    return []


def selected_resources(value: str | None) -> list[str]:
    if not value:
        return list(RESOURCES)

    out = []
    for part in value.split(","):
        name = part.strip().lower()
        if not name:
            continue
        if name not in RESOURCES:
            raise AppError(
                f"Unknown resource {name!r}. Valid: {', '.join(RESOURCES)}"
            )
        if name not in out:
            out.append(name)

    if not out:
        raise AppError("No valid resources selected.")
    return out


def filtered(items: list[dict[str, Any]], needle: str | None) -> list[dict[str, Any]]:
    if not needle:
        return items
    n = needle.casefold()
    fields = ("name", "server", "secondary-server", "tertiary-server", "remote-gw")
    return [
        x for x in items
        if any(n in str(x.get(f, "")).casefold() for f in fields)
    ]


def fetch(
    fg: FortiGate,
    resource: str,
    *,
    plaintext: bool,
    match: str | None,
) -> list[dict[str, Any]]:
    data = fg.get(RESOURCES[resource]["path"], plaintext=plaintext)
    return filtered(results(data), match)


def fmt(value: Any, limit: int = 48) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    text = str(value).replace("\n", "\\n")
    return text if len(text) <= limit else text[:limit - 1] + "…"


def show_inventory(items: list[dict[str, Any]], resource: str) -> None:
    spec = RESOURCES[resource]
    cols = spec["columns"]
    headers = [h for _, h in cols]
    rows = [[fmt(x.get(k, "")) for k, _ in cols] for x in items]
    widths = [
        max([len(headers[i]), *[len(row[i]) for row in rows]])
        for i in range(len(headers))
    ]
    print(f"\n[{spec['label']}]  entries: {len(rows)}")
    print("  ".join(headers[i].ljust(widths[i]) for i in range(len(headers))))
    print("  ".join("-" * widths[i] for i in range(len(headers))))
    for row in rows:
        print("  ".join(row[i].ljust(widths[i]) for i in range(len(headers))))


def find_secrets(
    obj: Any,
    names: set[str],
    prefix: str = "",
) -> list[tuple[str, Any]]:
    found = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else k
            if k in names:
                found.append((path, v))
            else:
                found.extend(find_secrets(v, names, path))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            path = f"{prefix}[{i}]" if prefix else f"[{i}]"
            found.extend(find_secrets(v, names, path))
    return found


def show_secrets(items: list[dict[str, Any]], resource: str) -> None:
    fields = RESOURCES[resource]["secret_fields"]
    any_found = False
    for item in items:
        name = str(item.get("name", ""))
        for path, value in find_secrets(item, fields):
            if value in ("", None, []):
                continue
            any_found = True
            print(f"{resource}\t{name}\t{path}\t{value}")
    if not any_found:
        print(f"{resource}\t<no plaintext secrets returned>")


def find_git_context(directory: Path) -> str | None:
    """
    Return a human-readable Git context if `directory` is inside a worktree,
    inside a bare Git repository, or underneath a directory containing a
    .git marker.

    Primary detection uses Git itself because it correctly handles linked
    worktrees, submodules, separate gitdirs, and bare repositories. A manual
    parent walk is retained as a fallback when Git is unavailable.
    """
    directory = directory.resolve()

    # Strong check: ask Git whether this path belongs to any repository.
    try:
        probe = subprocess.run(
            [
                "git", "-C", str(directory), "rev-parse",
                "--is-inside-work-tree",
                "--is-inside-git-dir",
                "--is-bare-repository",
                "--show-toplevel",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=3,
            check=False,
            env={k: v for k, v in os.environ.items() if k not in {"GIT_DIR", "GIT_WORK_TREE"}},
        )
        if probe.returncode == 0:
            lines = [line.strip() for line in probe.stdout.splitlines() if line.strip()]
            # Any successful rev-parse here means Git resolved repository context.
            top = lines[-1] if lines else str(directory)
            return f"Git repository detected by git rev-parse: {top}"
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        pass

    # Fallback check for normal repositories/worktrees if git(1) is unavailable.
    current = directory
    while True:
        marker = current / ".git"
        if marker.exists() or marker.is_symlink():
            return f"Git marker detected: {marker}"
        if current.parent == current:
            break
        current = current.parent

    # Bare repository fallback: HEAD + objects + refs at the directory itself.
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
        raise AppError(
            f"File already exists: {path}. Use --force only if overwrite is intentional."
        )

    return path


def write_json(path: Path, data: Any, force: bool) -> None:
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if force else os.O_EXCL)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError as e:
        raise AppError(f"File already exists: {path}") from e
    except PermissionError as e:
        raise AppError(f"Permission denied while creating {path}") from e
    except OSError as e:
        if e.errno == errno.ENOSPC:
            raise AppError(f"No space left on device while creating {path}") from e
        if e.errno == errno.EROFS:
            raise AppError(f"Filesystem is read-only: {path.parent}") from e
        raise AppError(f"Cannot create {path}: {e}") from e

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


def token_from_args(args: argparse.Namespace) -> str:
    if args.token_file:
        try:
            t = Path(args.token_file).expanduser().read_text(encoding="utf-8").strip()
        except OSError as e:
            raise AppError(f"Cannot read token file: {e}") from e
        if not t:
            raise AppError("Token file is empty.")
        return t

    t = os.environ.get(args.token_env, "").strip()
    if t:
        return t

    t = getpass.getpass(f"FortiGate API token ({args.token_env} is unset): ").strip()
    if not t:
        raise AppError("No API token supplied.")
    return t


def add_connection_options(p: argparse.ArgumentParser, suppressed: bool = False) -> None:
    d = argparse.SUPPRESS if suppressed else None

    p.add_argument(
        "--host",
        default=argparse.SUPPRESS if suppressed else os.environ.get("FORTIGATE_HOST"),
        help="FortiGate URL/IP[:port], or FORTIGATE_HOST",
    )
    p.add_argument("--vdom", default=d, help="VDOM name")
    p.add_argument(
        "--token-env",
        default=argparse.SUPPRESS if suppressed else "FORTIGATE_API_TOKEN",
        help="environment variable containing API token",
    )
    p.add_argument("--token-file", default=d, help="read API token from file")
    p.add_argument("--ca-file", default=d, help="CA bundle for TLS verification")
    p.add_argument(
        "--insecure",
        action="store_true",
        default=d,
        help="disable TLS certificate verification",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=argparse.SUPPRESS if suppressed else 15.0,
        help="HTTP timeout seconds",
    )


def add_filters(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--only",
        help="comma-separated resources: ipsec,radius,tacacs (default: all)",
    )
    p.add_argument("--match", help="filter by name/server/remote gateway")


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fortirecover",
        description="Read-only FortiGate recovery helper.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
The three normal operations are:

  fortirecover list
      Inventory only. Does NOT request plaintext passwords.

  fortirecover show
      Print plaintext secrets to the terminal.

  fortirecover export FILE
      Export full objects WITH PLAINTEXT SECRETS to JSON.

There is intentionally no masked export mode.
""",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    add_connection_options(p)

    sub = p.add_subparsers(dest="command", required=True)

    lp = sub.add_parser("list", help="inventory without plaintext secrets")
    add_connection_options(lp, True)
    add_filters(lp)

    sp = sub.add_parser("show", help="show plaintext secrets")
    add_connection_options(sp, True)
    add_filters(sp)

    ep = sub.add_parser("export", help="export plaintext recovery JSON")
    add_connection_options(ep, True)
    ep.add_argument("file", help="destination JSON file")
    add_filters(ep)
    ep.add_argument("--force", action="store_true", help="overwrite existing file")

    return p


def main() -> int:
    args = parser().parse_args()

    if not getattr(args, "host", None):
        danger("--host is required unless FORTIGATE_HOST is set.")
        return 2

    try:
        token = token_from_args(args)
        fg = FortiGate(
            args.host,
            token,
            insecure=getattr(args, "insecure", False),
            ca_file=getattr(args, "ca_file", None),
            timeout=getattr(args, "timeout", 15.0),
            vdom=getattr(args, "vdom", None),
        )
        resources = selected_resources(getattr(args, "only", None))
        match = getattr(args, "match", None)

        if args.command == "list":
            failed = False
            for resource in resources:
                try:
                    show_inventory(
                        fetch(fg, resource, plaintext=False, match=match),
                        resource,
                    )
                except AppError as e:
                    failed = True
                    danger(f"{RESOURCES[resource]['label']}: {e}")
            if failed:
                warn("Some resources failed; successful inventory is shown above.")
                return 1
            return 0

        if args.command == "show":
            danger("PLAINTEXT SECRETS WILL BE PRINTED TO THIS TERMINAL.")
            warn("Terminal scrollback, screen sharing, and logs may expose them.")
            failed = False
            for resource in resources:
                try:
                    show_secrets(
                        fetch(fg, resource, plaintext=True, match=match),
                        resource,
                    )
                except AppError as e:
                    failed = True
                    danger(f"{RESOURCES[resource]['label']}: {e}")
            if failed:
                warn("Some resources failed; successful secrets are shown above.")
                return 1
            return 0

        if args.command == "export":
            print(f"fortirecover {VERSION}", file=sys.stderr)
            out = validate_export_path(Path(args.file), args.force)
            danger("EXPORT WILL CONTAIN PLAINTEXT CREDENTIALS.")
            warn("The JSON file will be created with permissions 0600.")

            bundle = {
                "tool": "fortirecover",
                "tool_version": VERSION,
                "format_version": 1,
                "created_utc": datetime.now(timezone.utc).isoformat(),
                "fortigate": fg.base,
                "vdom": fg.vdom,
                "plaintext_secrets": True,
                "resources": {},
                "errors": {},
            }

            successes = 0
            for resource in resources:
                try:
                    bundle["resources"][resource] = fetch(
                        fg, resource, plaintext=True, match=match
                    )
                    successes += 1
                except AppError as e:
                    bundle["errors"][resource] = str(e)
                    danger(f"{RESOURCES[resource]['label']}: {e}")

            if successes == 0:
                raise AppError("Every requested resource failed; no file was written.")

            write_json(out, bundle, args.force)

            good(f"Wrote PLAINTEXT recovery bundle: {out}")
            print("Secrets: PLAINTEXT")
            print("Permissions: 0600")

            if bundle["errors"]:
                warn("PARTIAL EXPORT: see the top-level 'errors' object in the JSON.")
                return 1
            return 0

        raise AppError("Unknown command.")

    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except AppError as e:
        danger(str(e))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
