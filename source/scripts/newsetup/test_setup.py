"""Offline contract tests. Engine verification is mocked; no cryptographic PASS is claimed."""
import copy
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import rules_snapshot as rules
import setup


class ResourceLimitTests(unittest.TestCase):
    def test_compose_memory_forms_have_identical_byte_limits(self):
        for value in (4 << 30, str(4 << 30), "4g", "4G"):
            with self.subTest(value=value):
                self.assertEqual(setup.positive_resource_limit(value, memory=True), 4 << 30)
        self.assertEqual(setup.positive_resource_limit("3g", memory=True), 3 << 30)
        self.assertEqual(setup.positive_resource_limit("64m", memory=True), 64 << 20)
        self.assertEqual(setup.positive_resource_limit("1k", memory=True), 1024)
        self.assertEqual(setup.positive_resource_limit("1t", memory=True), 1 << 40)
        self.assertEqual(setup.positive_resource_limit("128"), 128)

    def test_resource_validation_rejects_ambiguous_unbounded_or_disabled_values(self):
        invalid = (True, False, 0, -1, 1.0, None, "", "0", "-1", "+1", "01",
                   " 1", "1 ", "1.5g", "4GiB", "4MB", "unlimited", "１",
                   1 << 63, str(1 << 63), "9999999999999999999t")
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(rules.SetupError):
                setup.positive_resource_limit(value, memory=True)
        with self.assertRaises(rules.SetupError):
            setup.positive_resource_limit("1k")

    def test_signed_63_bit_boundary_and_binary_unit_overflow(self):
        largest = (1 << 63) - 1
        self.assertEqual(setup.positive_resource_limit(largest), largest)
        self.assertEqual(setup.positive_resource_limit(str(largest)), largest)
        self.assertEqual(setup.positive_resource_limit("8589934591g", memory=True), 8589934591 << 30)
        with self.assertRaises(rules.SetupError):
            setup.positive_resource_limit("8589934592g", memory=True)


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.store = self.root / "store"
        self.now = int(time.time())
        self.records = [{"name": name, "version": 100, "buildEpoch": self.now - 60,
                         "signatureVerified": True, "verificationOutputSha256": "a" * 64}
                        for name in rules.DATABASES]
        for name in rules.DATABASES:
            (self.source / name).write_bytes((name.encode() + b"x" * 600))
        self.engine = patch.object(rules, "verify_engine", return_value={"engine": "ClamAV 1.4.6", "engineLoadVerified": True, "files": self.records})
        self.engine.start()

    def tearDown(self):
        self.engine.stop()
        # Snapshot permissions are deliberately read-only; undo only this test tree.
        for path in self.root.rglob("*"):
            path.chmod(0o755 if path.is_dir() else 0o644)
        self.temp.cleanup()

    def prepare(self):
        return rules.prepare(self.source, self.store, "sha256:" + "b" * 64)

    def test_complete_snapshot_roundtrip_and_expiry_binding(self):
        manifest = self.prepare()
        directory, active = rules.verify_active(self.store, now=self.now)
        self.assertEqual(set(x.name for x in directory.iterdir()), set(rules.DATABASES))
        self.assertEqual(active, manifest)
        self.assertEqual(manifest["expiresAt"], self.now - 60 + rules.MAX_AGE_SECONDS)
        self.assertFalse((directory / "manifest.json").exists())

    def test_missing_database_never_publishes(self):
        (self.source / "bytecode.cvd").unlink()
        with self.assertRaises(OSError):
            self.prepare()
        self.assertFalse((self.store / "active.json").exists())

    def test_failed_signature_never_publishes(self):
        with patch.object(rules, "verify_engine", side_effect=rules.SetupError("signature-invalid")):
            with self.assertRaisesRegex(rules.SetupError, "signature-invalid"):
                self.prepare()
        self.assertFalse((self.store / "active.json").exists())
        self.assertFalse((self.store / "prepare.lock").exists())

    def test_same_rules_can_be_prepared_again_without_deleting_active(self):
        first = self.prepare()
        original_manifest = (self.store / "manifests" / (first["snapshot"] + ".json")).read_bytes()
        with patch.object(rules.time, "time", return_value=self.now + 10):
            second = self.prepare()
        self.assertEqual(first["snapshot"], second["snapshot"])
        self.assertEqual(original_manifest, (self.store / "manifests" / (first["snapshot"] + ".json")).read_bytes())
        self.assertNotEqual(second["previousSnapshot"], second["snapshot"])
        rules.verify_active(self.store, now=self.now)

    def test_policy_change_gets_new_identity_and_preserves_old_manifest(self):
        first = self.prepare()
        old = self.store / "manifests" / (first["snapshot"] + ".json")
        data = old.read_bytes()
        second = rules.prepare(self.source, self.store, "sha256:" + "b" * 64, 86400)
        self.assertNotEqual(first["snapshot"], second["snapshot"])
        self.assertEqual(data, old.read_bytes())

    def test_automatic_prepare_preserves_a_stricter_store_policy(self):
        strict = rules.prepare(self.source, self.store, "sha256:" + "b" * 64, 86400)
        automatic = self.prepare()
        self.assertEqual(automatic["snapshot"], strict["snapshot"])
        self.assertEqual(automatic["maxAgeSeconds"], 86400)

    def test_updater_restores_only_sha_bound_owned_cache(self):
        self.store.mkdir()
        payload = b"public-freshclam-cooldown-state"
        (self.store / "freshclam.dat").write_bytes(payload)
        rules.atomic_json(self.store / "updater-gate.json", {"notBefore": 0, "cacheSha256": rules.digest(self.store / "freshclam.dat")})
        observed = []
        def fake_container(argv, **kwargs):
            directory = next(self.store.glob("download-*"))
            observed.append((directory / "freshclam.dat").read_bytes())
            return b""
        with patch.object(rules, "temporary_container", side_effect=fake_container), patch.object(rules, "prepare", return_value={"status": "mock-only"}):
            rules.update(self.store, "image", 0)
        self.assertEqual(observed, [payload, payload])
        self.assertEqual(json.loads((self.store / "updater-gate.json").read_text())["cacheSha256"], rules.digest(self.store / "freshclam.dat"))

    def test_corruption_is_rejected(self):
        manifest = self.prepare()
        file = self.store / "snapshots" / manifest["snapshot"] / "daily.cvd"
        file.chmod(0o644)
        file.write_bytes(b"changed")
        with self.assertRaisesRegex(rules.SetupError, "rule-file-changed"):
            rules.verify_active(self.store, now=self.now)

    def test_unknown_extra_file_is_rejected(self):
        manifest = self.prepare()
        directory = self.store / "snapshots" / manifest["snapshot"]
        directory.chmod(0o755)
        (directory / "custom.ndb").write_text("unverified")
        with self.assertRaisesRegex(rules.SetupError, "unexpected-rule-files"):
            rules.verify_active(self.store, now=self.now)

    def test_stale_and_future_rules_fail(self):
        for epoch in (self.now + 1, self.now - rules.MAX_AGE_SECONDS, 0):
            changed = copy.deepcopy(self.records)
            changed[1]["buildEpoch"] = epoch
            with self.assertRaises(rules.SetupError):
                rules.freshness(changed, self.now, rules.MAX_AGE_SECONDS)

    def test_version_or_time_rollback_fails(self):
        previous = {"files": self.records}
        for field in ("version", "buildEpoch"):
            changed = copy.deepcopy(self.records)
            changed[0][field] -= 1
            with self.assertRaisesRegex(rules.SetupError, "rules-rollback-rejected"):
                rules.freshness(changed, self.now, rules.MAX_AGE_SECONDS, previous)

    def test_freshness_cannot_be_extended_beyond_policy(self):
        with self.assertRaisesRegex(rules.SetupError, "invalid-freshness-policy"):
            rules.freshness(self.records, self.now, rules.MAX_AGE_SECONDS + 1)

    def test_manifest_tampering_fails(self):
        self.prepare()
        pointer = json.loads((self.store / "active.json").read_text())
        manifest = self.store / "manifests" / (pointer["snapshot"] + ".json")
        manifest.write_text("{}")
        with self.assertRaisesRegex(rules.SetupError, "manifest-changed"):
            rules.verify_active(self.store, now=self.now)

    def test_future_network_gate_does_not_launch_tool(self):
        with patch.object(rules, "run") as run:
            with self.assertRaisesRegex(rules.SetupError, "updater-cooldown-active"):
                rules.update(self.store, "image", self.now + 3600)
        run.assert_not_called()

    def test_failed_updater_keeps_gate_and_does_not_activate(self):
        with patch.object(rules, "temporary_container", side_effect=rules.SetupError("tool-failed")):
            with self.assertRaises(rules.SetupError):
                rules.update(self.store, "image", 0)
        self.assertGreater(json.loads((self.store / "updater-gate.json").read_text())["notBefore"], self.now)
        self.assertFalse((self.store / "active.json").exists())
        self.assertFalse((self.store / "update.lock").exists())

    def test_embedded_engine_verifier_is_valid_python(self):
        compile(rules.VERIFY_SCRIPT, "<engine-verifier>", "exec")
        compile(setup.PROBE_SCRIPT, "<socket-probe>", "exec")


class ToolProcessTests(unittest.TestCase):
    def test_stdout_is_bounded_while_produced(self):
        import sys
        with self.assertRaisesRegex(rules.SetupError, "tool-output-limit"):
            rules.bounded([sys.executable, "-c", "import sys; sys.stdout.write('x'*100000)"], timeout=5, limit=1024)

    def test_timeout_is_bounded_and_process_is_reaped(self):
        import sys
        with self.assertRaisesRegex(rules.SetupError, "tool-timeout"):
            rules.run([sys.executable, "-c", "import time; time.sleep(10)"], timeout=0.05)

    def test_temporary_docker_cleanup_uses_inspected_id_and_owner(self):
        identifier = "c" * 64
        def fake_bounded(argv, *args, **kwargs):
            owner = argv[-1].removeprefix("mh-sec-tool-")
            return 0, (json.dumps(identifier) + "|" + owner).encode()
        with patch.object(rules, "bounded", side_effect=fake_bounded), patch.object(rules, "run", side_effect=[rules.SetupError("tool-timeout"), b""]) as run:
            with self.assertRaisesRegex(rules.SetupError, "tool-timeout"):
                rules.temporary_container(["docker", "run", "image"], timeout=1)
            self.assertEqual(run.call_args_list[-1].args[0], ["docker", "container", "rm", "--force", identifier])


def plan():
    runtime = {"user": "65532:65532", "read_only": True, "cap_drop": ["ALL"],
               "security_opt": ["no-new-privileges:true"], "pids_limit": 32, "mem_limit": 3 * 1024**3}
    scanner = dict(copy.deepcopy(runtime), network_mode="none", environment={"SCAN_RULES_EXPIRES_AT": str(int(time.time()) + 1000)}, volumes=[
        {"type": "bind", "target": "/rules", "read_only": True},
        {"type": "volume", "target": "/input", "read_only": True}])
    api = dict(copy.deepcopy(runtime), ports=[{"host_ip": "127.0.0.1"}], volumes=[
        {"type": "volume", "target": "/input"},
        {"type": "volume", "target": "/run/matrix-security", "read_only": True}])
    init = {"user": "0:0", "network_mode": "none", "read_only": True, "cap_drop": ["ALL"],
            "cap_add": ["CHOWN", "FOWNER"], "volumes": [{"type": "volume", "target": "/data"}]}
    return {"services": {"scanner": scanner, "matrixhub": api, "init-volumes": init}, "volumes": {"data": {}, "artifacts": {}, "socket": {}}}


class PlanTests(unittest.TestCase):
    def test_safe_effective_plan_is_accepted(self):
        self.assertTrue(setup.validate_plan(plan()))

    def test_unsafe_effective_runtime_values_are_rejected(self):
        for field, value in (("user", "0:0"), ("privileged", True), ("read_only", False),
                             ("cap_add", ["SYS_ADMIN"]), ("mem_limit", 0), ("network_mode", "bridge")):
            with self.subTest(field=field):
                changed = plan()
                changed["services"]["scanner"][field] = value
                with self.assertRaises(rules.SetupError):
                    setup.validate_plan(changed)

    def test_rw_rules_or_staging_and_public_ports_are_rejected(self):
        for service, target in (("scanner", "/rules"), ("scanner", "/input"), ("matrixhub", "/run/matrix-security")):
            changed = plan()
            next(x for x in changed["services"][service]["volumes"] if x["target"] == target)["read_only"] = False
            with self.assertRaises(rules.SetupError):
                setup.validate_plan(changed)
        changed = plan()
        changed["services"]["matrixhub"]["ports"][0]["host_ip"] = "0.0.0.0"
        with self.assertRaises(rules.SetupError):
            setup.validate_plan(changed)

    def test_init_cannot_receive_arbitrary_bind_mount(self):
        changed = plan()
        changed["services"]["init-volumes"]["volumes"][0]["type"] = "bind"
        with self.assertRaisesRegex(rules.SetupError, "init-must-touch-only-owned-volumes"):
            setup.validate_plan(changed)

    def test_expired_runtime_env_is_rejected(self):
        changed = plan()
        changed["services"]["scanner"]["environment"]["SCAN_RULES_EXPIRES_AT"] = "0"
        with self.assertRaisesRegex(rules.SetupError, "scanner-rules-expiry-required"):
            setup.validate_plan(changed)


class LargeProfileTests(unittest.TestCase):
    def test_physical_copy_budget_and_default_are_distinct(self):
        profile = json.loads((setup.SOURCE / "deploy/security/profiles/large-repository.json").read_text())
        values = profile["apiSecurity"]
        self.assertEqual(values["maxTaskBytes"], 110 * 1024**3)
        self.assertEqual(values["maxStagingBytes"], 120 * 1024**3)
        self.assertEqual(values["batchBytes"], 5 * 1024**3)
        self.assertEqual(profile["twoCopiesAtTaskLimitBytes"], 2 * values["maxTaskBytes"])
        self.assertEqual(profile["minimumFreeDiskBytes"], profile["twoCopiesAtTaskLimitBytes"] + profile["freeDiskReserveBytes"])
        self.assertEqual(profile["scannerEnvironment"]["SCAN_MAX_EXPANDED_BYTES"], "134217728")
        default = (setup.SOURCE / "deploy/security/config.yaml").read_text()
        self.assertIn("maxTaskBytes: 268435456", default)
        self.assertIn("maxFileBytes: 67108864", default)

    def test_bind_directory_rejects_existing_data_and_wrong_owner(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "owned"
            directory.mkdir()
            (directory / "existing.txt").write_text("existing data")
            with self.assertRaisesRegex(rules.SetupError, "new-bind-directory-must-be-empty"):
                setup.owned_directory(directory, "a" * 32)
            (directory / "existing.txt").unlink()
            setup.owned_directory(directory, "a" * 32)
            with self.assertRaisesRegex(rules.SetupError, "bind-directory-owned-by-another-deployment"):
                setup.owned_directory(directory, "b" * 32)

    def test_effective_init_bind_must_exactly_match_owned_source_and_target(self):
        changed = plan()
        changed["services"]["init-volumes"]["volumes"] = [{"type": "bind", "target": "/input", "source": "/owned/staging"}]
        self.assertTrue(setup.validate_plan(changed, {"/input": "/owned/staging"}))
        with self.assertRaises(rules.SetupError):
            setup.validate_plan(changed, {"/input": "/other/staging"})

    def test_native_posix_preflight_failure_has_no_unsafe_fallback(self):
        with patch.object(setup, "temporary_container", side_effect=rules.SetupError("EPERM")) as container:
            with self.assertRaisesRegex(rules.SetupError, "posix-permissions-or-stable-fd-unavailable-use-linux-ext4"):
                setup.verify_posix_bindings({"/data": "/owned/data", "/input": "/owned/staging"}, "image")
        self.assertEqual(container.call_count, 1)

    def test_native_posix_probe_is_valid_python_and_restricted(self):
        compile(setup.POSIX_PROBE_SCRIPT, "<posix-probe>", "exec")
        self.assertNotIn("0o777", setup.POSIX_PROBE_SCRIPT)
        self.assertIn("os.fchmod(descriptor,0o440)", setup.POSIX_PROBE_SCRIPT)
        self.assertEqual(len(".matrixhub-posix-probe-" + "a" * 32), 55)

    def test_helm_rules_verifier_is_valid_python(self):
        path = setup.SOURCE / "deploy/security/helm/files/verify_rules.py"
        compile(path.read_text(), str(path), "exec")
        path = setup.SOURCE / "deploy/security/helm/files/verify_storage.py"
        compile(path.read_text(), str(path), "exec")


if __name__ == "__main__":
    unittest.main()
