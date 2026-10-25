import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
import sys

TMP = tempfile.TemporaryDirectory()
os.environ["DATA_DIR"] = TMP.name
os.environ["COOKIE_SECURE"] = "0"
os.environ["ABYSS_TEST_MODE"] = "1"
spec = importlib.util.spec_from_file_location("panel_main", Path(__file__).parents[1] / "app" / "main.py")
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)

class CoreTests(unittest.TestCase):
    def setUp(self):
        mod.init_db()

    def test_password_hash_and_verify(self):
        hashed = mod.password_hash("a-strong-test-password-123")
        self.assertTrue(mod.verify_password("a-strong-test-password-123", hashed))
        self.assertFalse(mod.verify_password("wrong-password", hashed))

    def test_fresh_install_bootstraps_admin_without_external_password_setting(self):
        env_keys = (
            "APP_ENV", "ENVIRONMENT", "RAILWAY_ENVIRONMENT_NAME",
            "RAILWAY_PROJECT_ID", "RAILWAY_SERVICE_ID",
            "ABYSS_INITIAL_ADMIN_PASSWORD", "ABYSS_TEST_MODE",
        )
        previous_env = {key: os.environ.get(key) for key in env_keys}
        try:
            for key in env_keys:
                os.environ.pop(key, None)
            os.environ["APP_ENV"] = "production"
            with mod.db() as conn:
                conn.execute("DELETE FROM panel_admins WHERE username='admin'")
                conn.execute("DELETE FROM admins WHERE id=1")

            # Void intentionally supports a simple first login; it records the
            # bootstrap credential with restrictive permissions for the owner.
            mod.init_db()
            with mod.db() as conn:
                row = conn.execute(
                    "SELECT password_hash FROM panel_admins WHERE username='admin'"
                ).fetchone()
            self.assertIsNotNone(row)
            self.assertTrue(mod.verify_password("admin", row["password_hash"]))
            credential_file = Path(mod.DATA_DIR) / "INITIAL_ADMIN_PASSWORD.txt"
            self.assertIn("Username: admin", credential_file.read_text(encoding="utf-8"))
            self.assertIn("Password: admin", credential_file.read_text(encoding="utf-8"))
        finally:
            for key, value in previous_env.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
            mod.init_db()

    def test_xray_config_has_loopback_only_inbounds(self):
        config = mod.make_xray_config()
        self.assertEqual(len(config["inbounds"]), 10)
        self.assertTrue(all(i["listen"] == "127.0.0.1" for i in config["inbounds"]))
        client_inbounds = [i for i in config["inbounds"] if "clients" in i["settings"]]
        self.assertEqual(len(client_inbounds), 9)
        self.assertTrue(all(i["settings"]["decryption"] == "none" for i in client_inbounds if i["protocol"] == "vless"))
        self.assertEqual(len({i["tag"] for i in config["inbounds"]}), len(config["inbounds"]))
        self.assertEqual(len({i["port"] for i in config["inbounds"]}), len(config["inbounds"]))

    def test_dashboard_client_listing_does_not_expose_secrets(self):
        with mod.db() as conn:
            conn.execute("INSERT OR REPLACE INTO clients(id,name,client_uuid,sub_token,enabled,created_at,note) VALUES(?,?,?,?,1,?,?)",
                ("test-id", "Test Phone", "secret-client-uuid", "secret-sub-token", mod.utc_now(), ""))
        public_row = mod.get_clients()[0]
        self.assertNotIn("client_uuid", public_row)
        self.assertNotIn("sub_token", public_row)
        self.assertEqual(mod.get_clients(include_client_uuid=True)[0]["client_uuid"], "secret-client-uuid")

    def test_disabled_clients_are_excluded_from_xray(self):
        with mod.db() as conn:
            conn.execute("INSERT OR REPLACE INTO clients(id,name,client_uuid,sub_token,enabled,created_at,note) VALUES(?,?,?,?,0,?,?)",
                ("disabled-id", "Disabled Phone", "disabled-uuid", "disabled-token", mod.utc_now(), ""))
        import json
        self.assertNotIn("disabled-uuid", json.dumps(mod.make_xray_config()))
        self.assertNotIn("disabled-token", json.dumps(mod.make_xray_config()))

    def test_valid_name(self):
        self.assertEqual(mod.valid_name("  My   Phone  "), "My Phone")
        with self.assertRaises(Exception):
            mod.valid_name(" ")
        with self.assertRaises(Exception):
            mod.valid_name("x" * 65)

    def test_database_context_closes_connection_and_persists_commit(self):
        with mod.db() as conn:
            conn.execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", ("context-close-test", "persisted"))
            raw = conn
        with self.assertRaises(Exception):
            raw.execute("SELECT 1")
        with mod.db() as conn:
            self.assertEqual(conn.execute("SELECT value FROM settings WHERE key=?", ("context-close-test",)).fetchone()["value"], "persisted")


if __name__ == "__main__":
    unittest.main()
