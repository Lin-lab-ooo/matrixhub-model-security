"""Docker-level tests for the in-memory rules bootstrap. Opt-in and read-only by design.

Run with:
  MATRIXHUB_DOCKER_TESTS=1 MATRIXHUB_BOOTSTRAP_IMAGE=sha256:... python -m unittest test_rules_bootstrap_docker

These tests prove the failure directions that matter for admission: a tampered or
incomplete snapshot and a non-tmpfs rules target must all stop the container
before the real scanner command runs. They use three small fixture files instead
of the real ClamAV databases. A tmpfs is always empty at start, so "reuse stale
content" cannot happen by construction and needs no separate case.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import rules_store

ENABLED = os.getenv("MATRIXHUB_DOCKER_TESTS") == "1"
IMAGE = os.getenv("MATRIXHUB_BOOTSTRAP_IMAGE", "")
DATABASES = ("main.cvd", "daily.cvd", "bytecode.cvd")
SENTINEL = "SCANNER_STARTED"
TMPFS_RULES = ["--tmpfs", "/rules:rw,noexec,nosuid,nodev,size=8m,uid=65532,gid=65532,mode=0750"]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


@unittest.skipUnless(ENABLED and IMAGE, "set MATRIXHUB_DOCKER_TESTS=1 and MATRIXHUB_BOOTSTRAP_IMAGE")
class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.snapshot = self.root / "snapshot"
        self.snapshot.mkdir()
        files = []
        for name in DATABASES:
            payload = (name + "-fixture\n").encode() * 64
            (self.snapshot / name).write_bytes(payload)
            files.append({"name": name, "size": len(payload), "sha256": digest(self.snapshot / name)})
        self.expected = {"schema": "matrixhub.rules-memory/v1", "snapshot": "a" * 64,
                         "engine": "ClamAV 1.4.6", "expiresAt": 1,
                         "files": sorted(files, key=lambda item: item["name"])}
        self.expectation = self.root / "expected.json"
        self.expectation.write_text(json.dumps(self.expected), encoding="utf-8")
        self.bootstrap = self.root / "rules-init.py"
        self.bootstrap.write_text(rules_store.INIT_SCRIPT, encoding="utf-8")

    def tearDown(self):
        self.temporary.cleanup()

    def run_bootstrap(self, rules_mount):
        argv = ["docker", "run", "--rm", "--pull=never", "--network=none", "--read-only",
                "--user=65532:65532", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
                "--pids-limit=32", "--memory=256m",
                "--mount", f"type=bind,src={self.snapshot},dst=/rules-source,readonly",
                "--mount", f"type=bind,src={self.expectation},dst=/expected.json,readonly",
                "--mount", f"type=bind,src={self.bootstrap},dst=/rules-init.py,readonly",
                *rules_mount,
                "--entrypoint=python", IMAGE, "-I", "/rules-init.py",
                "python", "-I", "-c", f"print('{SENTINEL}')"]
        return subprocess.run(argv, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=180)

    def test_complete_snapshot_is_copied_and_the_scanner_starts(self):
        result = self.run_bootstrap(TMPFS_RULES)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(SENTINEL, result.stdout)

    def test_tampered_snapshot_is_refused_even_when_the_name_matches(self):
        target = self.snapshot / "daily.cvd"
        target.write_bytes(target.read_bytes() + b"tampered")
        result = self.run_bootstrap(TMPFS_RULES)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("rules-source-invalid", (result.stdout or "") + (result.stderr or ""))
        self.assertNotIn(SENTINEL, result.stdout)

    def test_missing_snapshot_file_is_refused(self):
        (self.snapshot / "main.cvd").unlink()
        result = self.run_bootstrap(TMPFS_RULES)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(SENTINEL, result.stdout)

    def test_non_tmpfs_rules_target_is_refused(self):
        directory = self.root / "not-tmpfs"
        directory.mkdir()
        result = self.run_bootstrap(["--mount", f"type=bind,src={directory},dst=/rules"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("rules-target-not-tmpfs", (result.stdout or "") + (result.stderr or ""))
        self.assertNotIn(SENTINEL, result.stdout)


if __name__ == "__main__":
    unittest.main()