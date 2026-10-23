#!/usr/bin/env python3
"""First-account bootstrap for a proved-new, private SQLite deployment.

Only the setup wrapper may mount the owned data volume here. No password is
accepted in argv/environment, read from an existing account, or printed. The
target image's libcrypt must pass a public bcrypt known-answer test first.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path
import re
import secrets
import signal
import sqlite3
import stat
import subprocess
import sys
import time
import urllib.request

SEED_HASH = "$2a$10$GD9CROEWOuDcfGRbF3vB7e2bVplplnNW35uc03mju/Lm3ACEIylde"
EMPTY_TABLES = ("registries", "projects", "models", "datasets", "labels", "models_labels",
                "datasets_labels", "sessions", "access_tokens", "ssh_keys", "robots",
                "robots_projects", "sync_policies", "sync_tasks", "sync_jobs", "security_tasks",
                "security_reports", "security_cache", "security_policies", "security_audit", "security_reviews")
MARKER = "matrixhub_security_first_admin"


class BootstrapRefused(Exception):
    pass


def require(condition, code):
    if not condition:
        raise BootstrapRefused(code)


def password_bytes(raw):
    require(type(raw) is bytes and 14 <= len(raw) <= 72 and b"\x00" not in raw
            and b"\n" not in raw and b"\r" not in raw, "password-must-be-14-to-72-utf8-bytes")
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        raise BootstrapRefused("password-must-be-utf8") from None
    return raw


def crypt_function():
    try:
        library = ctypes.CDLL("libcrypt.so.1", use_errno=True)
        native = library.crypt
        native.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        native.restype = ctypes.c_char_p
    except (OSError, AttributeError):
        raise BootstrapRefused("target-image-bcrypt-unavailable") from None

    def calculate(raw, setting):
        ctypes.set_errno(0)
        output = native(raw, setting)
        require(output is not None and ctypes.get_errno() == 0, "target-image-bcrypt-unavailable")
        result = output.decode("ascii")
        require(re.fullmatch(r"\$2b\$(10|12)\$[./A-Za-z0-9]{53}", result) is not None,
                "target-image-bcrypt-unsupported")
        return result

    expected = "$2b$10$abcdefghijklmnopqrstuuQyc9AL3aeT3GVGES8xXy5brBQ/E8Qku"
    require(calculate(b"matrixhub-v14-public-bcrypt-probe", b"$2b$10$abcdefghijklmnopqrstuu") == expected,
            "target-image-bcrypt-known-answer-failed")
    return calculate


def new_bcrypt(raw):
    raw = password_bytes(raw)
    calculate = crypt_function()
    alphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    # The final bcrypt base64 character encodes only two bits.
    salt = ("$2b$12$" + "".join(secrets.choice(alphabet) for _ in range(21)) + secrets.choice(".Oeu")).encode("ascii")
    value = calculate(raw, salt)
    require(calculate(raw, value.encode("ascii")) == value, "bcrypt-self-check-failed")
    return value


def owned_database(path, native=True):
    require(path.name == "matrixhub.db", "unexpected-database-name")
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not path.is_symlink(), "unsafe-database-file")
    if native:
        require(info.st_uid == 65532 and info.st_gid == 65532, "unsafe-database-owner")
        parent = path.parent.lstat()
        require(stat.S_ISDIR(parent.st_mode) and (parent.st_uid, parent.st_gid, stat.S_IMODE(parent.st_mode))
                == (65532, 65532, 0o750), "unsafe-data-directory")


def migrate_private(path):
    """Run only the proved-new image privately, stop/reap it before DB writes."""
    for sidecar in (path, path.with_name(path.name + "-wal"), path.with_name(path.name + "-shm")):
        if sidecar.exists() or sidecar.is_symlink():
            require(not sidecar.is_symlink() and stat.S_ISREG(sidecar.lstat().st_mode), "unsafe-database-file")
    child = subprocess.Popen(["/usr/local/bin/matrixhub", "apiserver", "-c", "/etc/matrixhub/config.yaml"],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True)
    ready = False
    try:
        end = time.monotonic() + 45
        while time.monotonic() < end and child.poll() is None:
            try:
                with urllib.request.urlopen("http://127.0.0.1:3002/healthz", timeout=1) as response:
                    ready = response.status == 200 and response.read(16) == b"OK"
                if ready:
                    break
            except (OSError, ValueError):
                pass
            time.sleep(0.2)
    finally:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)
    require(ready, "private-migration-not-ready")


def initialize_database(path, owner, bcrypt_hash, native=True):
    require(re.fullmatch(r"[0-9a-f]{32}", owner or "") is not None, "invalid-deployment-owner")
    require(re.fullmatch(r"\$2b\$12\$[./A-Za-z0-9]{53}", bcrypt_hash or "") is not None,
            "fresh-bcrypt-required")
    owned_database(path, native)
    connection = sqlite3.connect(path.as_uri() + "?mode=rw", uri=True, timeout=3)
    try:
        connection.execute("BEGIN IMMEDIATE")
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        require(MARKER not in tables, "administrator-already-initialized")
        require(set(EMPTY_TABLES) | {"users", "roles", "members_roles_projects", "schema_migrations"} <= tables,
                "unrecognized-migration-schema")
        require(connection.execute("SELECT version,dirty FROM schema_migrations").fetchall() == [(3, 0)],
                "unrecognized-migration-version")
        require(connection.execute("SELECT id,username,email,session_version FROM users").fetchall()
                == [(1, "admin", "", 0)], "database-not-fresh")
        require(connection.execute("SELECT id,name,scope FROM roles ORDER BY id").fetchall()
                == [(1, "platform_admin", "platform"), (2, "project_admin", "project"),
                    (3, "project_editor", "project"), (4, "project_viewer", "project")], "unrecognized-initial-roles")
        require(connection.execute("SELECT permissions FROM roles WHERE id=1").fetchall() == [('["*.*"]',)],
                "unrecognized-initial-admin-permissions")
        require(connection.execute("SELECT member_id,member_type,role_id,project_id FROM members_roles_projects").fetchall()
                == [(1, "user", 1, None)], "database-not-fresh")
        for table in EMPTY_TABLES:
            require(connection.execute('SELECT COUNT(*) FROM "' + table + '"').fetchone()[0] == 0,
                    "database-not-fresh")
        changed = connection.execute("UPDATE users SET password=?,session_version=1 WHERE id=1 AND username='admin' "
                                     "AND session_version=0 AND password=?", (bcrypt_hash, SEED_HASH)).rowcount
        require(changed == 1, "initial-seed-identity-mismatch")
        connection.execute("CREATE TABLE " + MARKER + " (owner TEXT PRIMARY KEY,user_id INTEGER NOT NULL,"
                           "username TEXT NOT NULL,initial_session_version INTEGER NOT NULL)")
        connection.execute("INSERT INTO " + MARKER + " VALUES (?,1,'admin',1)", (owner,))
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()
    return {"status": "administrator-initialized", "owner": owner, "userId": 1, "username": "admin",
            "credentialStorage": "bcrypt-only", "plaintextPersisted": False}


def verify_initialized(path, owner, native=True):
    require(re.fullmatch(r"[0-9a-f]{32}", owner or "") is not None, "invalid-deployment-owner")
    owned_database(path, native)
    connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=3)
    try:
        marker = connection.execute("SELECT owner,user_id,username,initial_session_version FROM " + MARKER).fetchall()
        require(marker == [(owner, 1, "admin", 1)], "bootstrap-owner-mismatch")
        row = connection.execute("SELECT id,username,session_version FROM users WHERE id=1").fetchone()
        require(row is not None and row[:2] == (1, "admin") and row[2] >= 1, "administrator-identity-mismatch")
    finally:
        connection.close()
    return {"status": "administrator-initialized", "owner": owner, "userId": 1, "username": "admin",
            "credentialStorage": "bcrypt-only", "plaintextPersisted": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("probe", "initialize", "verify"))
    parser.add_argument("--database", type=Path, default=Path("/data/matrixhub.db"))
    parser.add_argument("--owner")
    args = parser.parse_args()
    signal.alarm(90)
    try:
        if args.action == "probe":
            crypt_function()
            value = {"status": "public-bcrypt-probe-passed"}
        elif args.action == "verify":
            value = verify_initialized(args.database, args.owner)
        else:
            require(re.fullmatch(r"[0-9a-f]{32}", args.owner or "") is not None, "invalid-deployment-owner")
            raw = sys.stdin.buffer.read(1025)
            require(len(raw) <= 72, "password-input-too-long")
            password_hash = new_bcrypt(raw)
            raw = None
            # Refuse initialized DBs before starting even a private migration.
            if args.database.exists():
                owned_database(args.database)
                connection = sqlite3.connect(args.database.as_uri() + "?mode=ro", uri=True, timeout=3)
                try:
                    require(connection.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", (MARKER,)).fetchone()[0] == 0,
                            "administrator-already-initialized")
                finally:
                    connection.close()
            else:
                require(set(item.name for item in args.database.parent.iterdir())
                        <= {".matrixhub-security-owner.json"}, "new-data-directory-must-be-empty")
                migrate_private(args.database)
            value = initialize_database(args.database, args.owner, password_hash)
            password_hash = None
        print(json.dumps(value, sort_keys=True))
    except BootstrapRefused as error:
        # All BootstrapRefused values are fixed codes, never interpolated data.
        print(json.dumps({"status": "refused", "code": str(error)}), file=sys.stderr)
        return 1
    except (OSError, sqlite3.Error, ValueError):
        # Do not include raw exceptions, SQL, tool output or input values.
        print('{"status":"refused","code":"fresh-administrator-operation-refused"}', file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
