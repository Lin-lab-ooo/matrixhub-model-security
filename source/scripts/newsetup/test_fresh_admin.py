"""Pure temporary SQLite/ownership contracts; no Docker or crypto PASS claimed."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
import warnings
from unittest.mock import patch

import admin_setup
import fresh_admin as admin
import rules_snapshot as rules

SOURCE = Path(__file__).resolve().parents[2]
OWNER = "a" * 32
TEST_HASH = "$2b$12$" + "a" * 53


class FreshDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name).resolve() / "matrixhub.db"
        connection = sqlite3.connect(self.path)
        for path in sorted((SOURCE / "db/migrations/sql/sqlite").glob("*.up.sql")):
            connection.executescript(path.read_text(encoding="utf-8"))
        connection.executescript("CREATE TABLE schema_migrations(version INTEGER,dirty INTEGER);INSERT INTO schema_migrations VALUES(3,0);")
        connection.close()

    def tearDown(self):
        self.temp.cleanup()

    def initialize(self, owner=OWNER):
        return admin.initialize_database(self.path, owner, TEST_HASH, native=False)

    def test_fresh_exact_schema_can_initialize_and_readonly_verify(self):
        result = self.initialize()
        self.assertFalse(result["plaintextPersisted"])
        self.assertEqual(admin.verify_initialized(self.path, OWNER, native=False), result)
        connection = sqlite3.connect(self.path)
        self.assertEqual(connection.execute("SELECT username,session_version FROM users").fetchall(), [("admin", 1)])
        connection.close()

    def test_second_initialization_refuses_and_preserves_every_database_byte(self):
        self.initialize()
        before = hashlib.sha256(self.path.read_bytes()).digest()
        with self.assertRaisesRegex(admin.BootstrapRefused, "already-initialized"):
            self.initialize()
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).digest(), before)

    def test_existing_account_and_nonempty_content_refused_without_mutation(self):
        initial = self.path.read_bytes()
        for mutation in ("UPDATE users SET session_version=2", "UPDATE users SET password='different'",
                         "INSERT INTO sessions VALUES('inert',X'00',1)",
                         "INSERT INTO projects(name) VALUES('existing')"):
            with self.subTest(mutation=mutation):
                self.path.write_bytes(initial)
                connection = sqlite3.connect(self.path);connection.execute(mutation);connection.commit();connection.close()
                before = hashlib.sha256(self.path.read_bytes()).digest()
                with self.assertRaises(admin.BootstrapRefused):self.initialize()
                self.assertEqual(hashlib.sha256(self.path.read_bytes()).digest(), before)

    def test_wrong_owner_cannot_resume_and_no_password_is_returned(self):
        self.initialize()
        with self.assertRaises(admin.BootstrapRefused):admin.verify_initialized(self.path, "b" * 32, native=False)
        result = admin.verify_initialized(self.path, OWNER, native=False)
        self.assertNotIn(TEST_HASH, json.dumps(result))
        self.assertNotIn("password", result)

    def test_wrong_migration_version_fails_before_update(self):
        connection = sqlite3.connect(self.path);connection.execute("UPDATE schema_migrations SET version=2");connection.commit();connection.close()
        with self.assertRaisesRegex(admin.BootstrapRefused, "migration-version"):self.initialize()

    def test_invalid_bcrypt_and_owner_rejected(self):
        with self.assertRaises(admin.BootstrapRefused):admin.initialize_database(self.path, OWNER, "invalid", native=False)
        with self.assertRaises(admin.BootstrapRefused):self.initialize("../bad-owner")

    def test_host_checkpoint_loss_does_not_lose_committed_account(self):
        self.initialize()
        # No host JSON is needed: successful DB transaction is the authority.
        self.assertEqual(admin.verify_initialized(self.path, OWNER, native=False)["status"], "administrator-initialized")


class StdinAndOwnershipTests(unittest.TestCase):
    def test_password_bounds_use_utf8_bytes_not_characters(self):
        self.assertEqual(admin.password_bytes(b"a" * 72), b"a" * 72)
        for raw in (b"a" * 13, b"a" * 73, b"a" * 20 + b"\n", b"a" * 20 + b"\x00", b"\xff" * 20):
            with self.assertRaises(admin.BootstrapRefused):admin.password_bytes(raw)
        for good in ("中" * 24, "😀" * 18):
            self.assertEqual(len(admin.password_bytes(good.encode("utf-8"))), 72)
        for bad in ("中" * 25, "😀" * 19):
            with self.assertRaises(admin.BootstrapRefused):admin.password_bytes(bad.encode("utf-8"))

    def test_missing_native_bcrypt_fails_closed_without_fallback(self):
        with patch.object(admin.ctypes, "CDLL", side_effect=OSError), self.assertRaises(admin.BootstrapRefused):
            admin.crypt_function()

    def test_public_known_answer_mismatch_fails_before_secret_hashing(self):
        with patch.object(admin.ctypes, "CDLL") as library:
            library.return_value.crypt.return_value = ("$2b$10$" + "a" * 53).encode()
            with self.assertRaisesRegex(admin.BootstrapRefused, "known-answer"):admin.crypt_function()
            self.assertEqual(library.return_value.crypt.call_count, 1)

    def test_unknown_or_running_volume_attachment_is_refused(self):
        for labels, running in (({"matrixhub.security.owner":"unknown"}, b"false"),
                                ({"matrixhub.security.owner":OWNER,"com.docker.compose.project":"mh-sec-test"}, b"true")):
            def execute(argv):return running if "{{.State.Running}}" in argv else b"a" * 64
            with patch.object(admin_setup, "run", side_effect=execute), patch.object(admin_setup, "inspect_labels", return_value=labels):
                with self.assertRaises(rules.SetupError):admin_setup.require_stopped_attachments("mh-sec-test", OWNER, "owned-data")

    def test_tool_stdin_bound_before_process_creation(self):
        with patch.object(rules.subprocess, "Popen") as process:
            with self.assertRaises(rules.SetupError):rules.bounded(["not-executed"], input_data=b"x" * 1025)
            process.assert_not_called()

    def test_getpass_echo_fallback_warning_is_a_hard_failure(self):
        def cannot_disable_echo(*args):
            warnings.warn("public simulated terminal failure", admin_setup.getpass.GetPassWarning)
            self.fail("getpass fallback must never read a password")
        with patch.object(admin_setup.sys.stdin, "isatty", return_value=True), patch.object(admin_setup.getpass, "getpass", side_effect=cannot_disable_echo):
            with self.assertRaises(rules.SetupError):admin_setup.read_new_password(False)

    def test_running_parent_or_child_bind_writer_is_refused(self):
        for source in ("/srv/private", "/srv/private/data/child", "/srv/private/data"):
            value = {"running":True,"mounts":[{"Type":"bind","RW":True,"Source":source}]}
            with patch.object(admin_setup.os, "name", "posix"), patch.object(admin_setup, "run", side_effect=[b"a"*64,json.dumps(value).encode()]):
                with self.assertRaisesRegex(rules.SetupError, "overlapping"):admin_setup.require_no_bind_writers(["/srv/private/data"])

    def test_unrelated_or_readonly_bind_does_not_claim_write_ownership(self):
        value = {"running":True,"mounts":[{"Type":"bind","RW":True,"Source":"/srv/other"},{"Type":"bind","RW":False,"Source":"/srv/private"}]}
        with patch.object(admin_setup.os, "name", "posix"), patch.object(admin_setup, "run", side_effect=[b"a"*64,json.dumps(value).encode()]):
            admin_setup.require_no_bind_writers(["/srv/private/data"])


if __name__ == "__main__":
    unittest.main()
