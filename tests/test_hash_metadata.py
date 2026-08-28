import contextlib
import importlib.util
import io
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "fortirecover.py"
spec = importlib.util.spec_from_file_location("fortirecover_hash_metadata", MODULE_PATH)
fr = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(fr)


class ProductionHashMetadataTests(unittest.TestCase):
    def test_local_passwd_is_hash_bearing_in_production_metadata(self):
        self.assertEqual(fr.RESOURCES["local"].get("hash_fields"), {"passwd"})

    def test_local_passwd_hash_is_not_reported_as_plaintext(self):
        items = [{"name": "alice", "passwd": "$6$salt$actual-hash"}]
        summary = fr.audit_summary(items, "local")

        self.assertEqual(summary["states"]["hashed"], 1)
        self.assertEqual(summary["states"]["plaintext"], 0)
        self.assertEqual(summary["result"], "UNRECOVERED")

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            fr.show_secrets(items, "local")
        self.assertNotIn("$6$salt$actual-hash", stdout.getvalue())
        self.assertIn("no recoverable plaintext", stdout.getvalue())

    def test_local_ppk_secret_keeps_hash_looking_plaintext(self):
        value = "$6$literal-ppk-secret"
        items = [{"name": "alice", "ppk-secret": value}]
        summary = fr.audit_summary(items, "local")

        self.assertEqual(summary["states"]["plaintext"], 1)
        self.assertEqual(summary["states"]["hashed"], 0)

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            fr.show_secrets(items, "local")
        self.assertIn(value, stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
