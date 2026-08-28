import contextlib
import importlib.util
import io
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "fortirecover.py"
spec = importlib.util.spec_from_file_location("fortirecover", MODULE_PATH)
fr = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(fr)


class SecretClassificationTests(unittest.TestCase):
    def test_secret_states_without_hash_guessing(self):
        cases = {
            None: "empty",
            "": "empty",
            "ENC abcdef": "encrypted",
            "FortinetPasswordMask": "masked",
            "********": "masked",
            "$6$salt$hash": "plaintext",
            "{SSHA}abcdef": "plaintext",
            "correct horse battery staple": "plaintext",
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(fr.classify_secret(value), expected)

    def test_hash_recognition_is_explicit_opt_in(self):
        for value in ("$1$salt$hash", "$6$salt$hash", "{SHA}abcdef", "{SSHA}abcdef"):
            with self.subTest(value=value):
                self.assertEqual(fr.classify_secret(value), "plaintext")
                self.assertEqual(
                    fr.classify_secret(value, recognize_hash=True),
                    "hashed",
                )

    def test_audit_summary_mixed(self):
        items = [
            {"name": "a", "psksecret": "secret-a"},
            {"name": "b", "psksecret": "ENC encrypted"},
            {"name": "c", "psksecret": ""},
        ]
        summary = fr.audit_summary(items, "ipsec")
        self.assertEqual(summary["states"]["plaintext"], 1)
        self.assertEqual(summary["states"]["encrypted"], 1)
        self.assertEqual(summary["states"]["empty"], 1)
        self.assertEqual(summary["result"], "PARTIAL")

    def test_hash_like_ipsec_secret_is_plaintext(self):
        value = "$6$looks-like-a-hash-but-is-a-psk"
        items = [{"name": "vpn", "psksecret": value}]

        summary = fr.audit_summary(items, "ipsec")
        self.assertEqual(summary["states"]["plaintext"], 1)
        self.assertEqual(summary["states"]["hashed"], 0)
        self.assertEqual(summary["result"], "OK")

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            fr.show_secrets(items, "ipsec")
        self.assertIn(value, stdout.getvalue())

    def test_hash_like_radius_and_snmp_secrets_are_plaintext(self):
        radius = [{"name": "rad", "secret": "{SHA}literal-radius-secret"}]
        snmp = [{"id": 1, "name": "$1$literal-community"}]

        radius_summary = fr.audit_summary(radius, "radius")
        snmp_summary = fr.audit_summary(snmp, "snmp-community")

        self.assertEqual(radius_summary["states"]["plaintext"], 1)
        self.assertEqual(radius_summary["states"]["hashed"], 0)
        self.assertEqual(snmp_summary["states"]["plaintext"], 1)
        self.assertEqual(snmp_summary["states"]["hashed"], 0)

    def test_resource_hash_fields_metadata_controls_hash_detection(self):
        resource = "local"
        old = fr.RESOURCES[resource].get("hash_fields")
        fr.RESOURCES[resource]["hash_fields"] = {"passwd"}
        try:
            items = [{
                "name": "alice",
                "passwd": "$6$salt$actual-hash",
                "ppk-secret": "$6$literal-shared-secret",
            }]
            summary = fr.audit_summary(items, resource)
            self.assertEqual(summary["states"]["hashed"], 1)
            self.assertEqual(summary["states"]["plaintext"], 1)
        finally:
            if old is None:
                fr.RESOURCES[resource].pop("hash_fields", None)
            else:
                fr.RESOURCES[resource]["hash_fields"] = old

    def test_show_does_not_print_encrypted_blob(self):
        items = [{"name": "vpn", "psksecret": "ENC do-not-print-me"}]
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            fr.show_secrets(items, "ipsec")
        self.assertNotIn("do-not-print-me", stdout.getvalue())
        self.assertIn("no recoverable plaintext", stdout.getvalue())
        self.assertIn("encrypted=1", stderr.getvalue())

    def test_parser_accepts_audit_and_new_resources(self):
        args = fr.parser().parse_args([
            "--host", "https://fgt.example", "audit",
            "--only", "ldap,local,snmp-community,snmp-user",
        ])
        self.assertEqual(args.command, "audit")
        self.assertEqual(
            fr.selected_resources(args.only),
            ["ldap", "local", "snmp-community", "snmp-user"],
        )

    def test_snmp_community_identity_never_uses_secret_name(self):
        item = {"id": 1, "name": "super-secret-community"}
        self.assertEqual(fr.object_identity(item, "snmp-community"), "1")

    def test_snmp_cmdb_paths_use_system_dot_snmp_namespace(self):
        self.assertEqual(
            fr.RESOURCES["snmp-community"]["path"],
            "/api/v2/cmdb/system.snmp/community",
        )
        self.assertEqual(
            fr.RESOURCES["snmp-user"]["path"],
            "/api/v2/cmdb/system.snmp/user",
        )


class GitSafetyTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("git"), "git executable not available")
    def test_nested_git_directory_is_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            nested = root / "deep" / "directory"
            nested.mkdir(parents=True)
            subprocess.run(
                ["git", "init", "-q", str(root)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            context = fr.find_git_context(nested)
            self.assertIsNotNone(context)
            with self.assertRaises(fr.AppError):
                fr.validate_export_path(nested / "recovery.json", False)

    def test_non_git_directory_is_allowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "recovery.json"
            self.assertEqual(fr.validate_export_path(path, False), path)


if __name__ == "__main__":
    unittest.main()
