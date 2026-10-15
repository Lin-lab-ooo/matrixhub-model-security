#!/usr/bin/env python3
# Copyright The MatrixHub Authors. Licensed under the Apache License, Version 2.0.
"""Regression tests for layout-only legacy storage inspection.

Run in the scanner's Linux image. Artifacts are inspected statically, never
loaded. Worker contract tests explicitly mock only native antivirus and process
limits; the separate protocol benchmark uses the actual ClamAV engine.
"""
import ast
import gzip
import hashlib
import importlib.util
import io
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scanner = load("legacy_io_scanner", "scanner.py")
fixtures = load("legacy_io_fixtures", "legacy_io_fixtures.py")


def sample(sizes=(4096,), protocol=2):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "fixture.bin"
        fixtures.write_fixture(path, protocol=protocol, storage_sizes=sizes)
        return path.read_bytes()


def framework_samples():
    tree = ast.parse(Path(__file__).with_name("integration_tests.py").read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and
                t.id == "EMBEDDED_LEGACY_MANIFEST" for t in node.targets):
            return ast.literal_eval(node.value)["cases"]
    raise AssertionError("real framework fixture manifest missing")


class CountingBytes(io.BytesIO):
    def __init__(self, raw):
        super().__init__(raw)
        self.read_bytes = 0

    def read(self, size=-1):
        result = super().read(size)
        self.read_bytes += len(result)
        return result

    def readline(self, size=-1):
        result = super().readline(size)
        self.read_bytes += len(result)
        return result


class LegacyLayoutTests(unittest.TestCase):
    def setUp(self):
        self.limits = scanner.limits_from_env()

    def verify(self, data, mode=True):
        inspector = scanner.StaticInspector(self.limits)
        def threat(stream, index):
            inspector.inspect_pickle(stream, stream_index_base=index)
        proof = scanner.verify_legacy_torch(data, threat, self.limits,
                                            hash_storage_payloads=mode)
        return proof, inspector.findings

    def assert_modes_equal(self, raw):
        old_stream, new_stream = CountingBytes(raw), CountingBytes(raw)
        old, old_findings = self.verify(old_stream)
        new, new_findings = self.verify(new_stream, False)
        self.assertEqual(old_findings, new_findings)
        self.assertEqual(new.pop("storageDigestMode"), "layout-only")
        for before, after in zip(old["storageRanges"], new["storageRanges"]):
            start, count = before["payloadOffset"], before["payloadBytes"]
            self.assertEqual(before["payloadSHA256"], hashlib.sha256(raw[start:start+count]).hexdigest())
            self.assertIsNone(after["payloadSHA256"])
            after["payloadSHA256"] = before["payloadSHA256"]
        self.assertEqual(old, new)
        self.assertEqual(old_stream.read_bytes - new_stream.read_bytes, old["storageBytes"])
        return old

    def test_four_framework_generated_protocol2_and_protocol4_fixtures(self):
        for case in framework_samples():
            with self.subTest(case=case["id"]):
                raw = bytes.fromhex(case["payloadHex"])
                self.assertEqual(len(raw), case["size"])
                self.assertEqual(hashlib.sha256(raw).hexdigest(), case["sha256"])
                self.assert_modes_equal(raw)

    def test_multiple_and_zero_length_storages_skip_exact_payload_bytes(self):
        for protocol in (2, 4):
            for sizes in ((0,), (1,), (0, 8192, 17), (1024, 2048)):
                with self.subTest(protocol=protocol, sizes=sizes):
                    proof = self.assert_modes_equal(sample(sizes, protocol))
                    self.assertEqual(proof["storageBytes"], sum(sizes))

    def test_invalid_mode_rejected_before_read(self):
        for invalid in (None, 0, 1, "layout-only", [], {}):
            with self.subTest(mode=repr(invalid)):
                with self.assertRaises(ValueError):
                    scanner.verify_legacy_torch(io.BytesIO(b""), lambda *_: None,
                                                self.limits, hash_storage_payloads=invalid)
                with self.assertRaises(ValueError):
                    scanner.StaticInspector(self.limits, hash_storage_payloads=invalid)

    def test_bad_storage_headers_truncation_and_tail_preserve_rejections(self):
        raw = sample((32, 17))
        proof, _ = self.verify(io.BytesIO(raw))
        first, second = proof["storageRanges"]
        offset = first["headerOffset"]
        cases = [raw[:offset+7], raw[:-1], raw+b"x",
                 raw[:offset]+struct.pack("<q", -1)+raw[offset+8:],
                 raw[:offset]+struct.pack("<q", 31)+raw[offset+8:],
                 raw[:second["headerOffset"]+7]]
        for index, malformed in enumerate(cases):
            errors = []
            for mode in (True, False):
                with self.subTest(case=index, mode=mode):
                    with self.assertRaises(scanner.LegacyTorchError) as raised:
                        self.verify(io.BytesIO(malformed), mode)
                    errors.append(raised.exception.code)
            self.assertEqual(errors[0], errors[1])

    def test_unsupported_constructor_and_dangerous_reference_keep_evidence(self):
        raw = sample((8,))
        for replacement in (b"cfixture_unknown\nconstruct\n", b"cos\nsystem\n"):
            changed = raw.replace(b"ctorch._utils\n_rebuild_tensor_v2\n", replacement, 1)
            self.assertNotEqual(changed, raw)
            outcomes = []
            for mode in (True, False):
                inspector = scanner.StaticInspector(self.limits)
                def threat(stream, index):
                    inspector.inspect_pickle(stream, stream_index_base=index)
                with self.assertRaises(scanner.LegacyTorchError) as raised:
                    scanner.verify_legacy_torch(io.BytesIO(changed), threat, self.limits,
                                                hash_storage_payloads=mode)
                outcomes.append((raised.exception.code, inspector.findings))
            self.assertEqual(outcomes[0], outcomes[1])
            if replacement == b"cos\nsystem\n":
                self.assertTrue(any(f["rule"] == "pickle.dangerous-global" for f in outcomes[0][1]))

    def test_optimized_inspector_requires_regular_descriptor(self):
        with self.assertRaisesRegex(scanner.Incomplete, "invalid_analysis_context"):
            scanner.StaticInspector(self.limits, hash_storage_payloads=False).inspect(
                io.BytesIO(sample((8,))), "model.bin")

    def test_default_and_nested_archive_inspection_retain_payload_digests(self):
        raw = sample((32,))
        zipped, tarred = io.BytesIO(), io.BytesIO()
        with zipfile.ZipFile(zipped, "w") as archive:
            archive.writestr("model.bin", raw)
        with tarfile.open(fileobj=tarred, mode="w") as archive:
            info = tarfile.TarInfo("model.bin")
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
        for name, content, optin in [("model.bin", raw, True),
                ("model.gz", gzip.compress(raw), False),
                ("model.zip", zipped.getvalue(), False),
                ("model.tar", tarred.getvalue(), False)]:
            with self.subTest(name=name):
                with mock.patch.object(scanner, "verify_legacy_torch", wraps=scanner.verify_legacy_torch) as verify:
                    scanner.StaticInspector(self.limits, hash_storage_payloads=optin).inspect(io.BytesIO(content), name)
                self.assertTrue(verify.called)
                self.assertTrue(all(call.kwargs["hash_storage_payloads"] is True for call in verify.call_args_list))


class WorkerIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.relative = "task-1-1-" + "a"*16 + "/" + "b"*32 + ".blob"
        self.path = self.root / self.relative
        self.path.parent.mkdir()
        self.raw = sample((4096,))
        self.path.write_bytes(self.raw)
        self.artifact = {"artifactId": self.relative, "sha256": hashlib.sha256(self.raw).hexdigest(),
                         "size": len(self.raw), "type": "pickle;ext=.bin"}
        self.request = {"limits": scanner.limits_from_env(), "artifact": self.artifact,
                        "evidence": {"rules": []},
                        "bundle": {"generation": "a"*64, "engines": []}}

    def run_worker(self, mutation=None):
        original = scanner.StaticInspector.inspect
        def inspect(instance, data, *args, **kwargs):
            result = original(instance, data, *args, **kwargs)
            if mutation:
                mutation()
            return result
        with mock.patch.object(scanner, "child_limits"), \
                mock.patch.object(scanner, "rule_inventory", return_value=[]), \
                mock.patch.object(scanner, "scan_clamav", return_value=[]) as antivirus, \
                mock.patch.object(scanner, "verify_held_snapshot", wraps=scanner.verify_held_snapshot) as postcheck, \
                mock.patch.object(scanner.StaticInspector, "inspect", inspect):
            try:
                return scanner.worker(self.request, str(self.root), "/unused")
            finally:
                self.assertEqual(antivirus.call_count, 1)
                self.assertEqual(postcheck.call_count, 1)

    def test_complete_worker_preserves_native_and_post_digest_calls(self):
        result = self.run_worker()
        self.assertTrue(result["complete"])
        self.assertEqual(result["findings"], [])

    def test_same_size_storage_mutation_after_static_remains_global_failure(self):
        def mutation():
            with self.path.open("r+b") as out:
                out.seek(-1, 2)
                out.write(bytes([self.raw[-1] ^ 1]))
        with self.assertRaisesRegex(scanner.Incomplete, "snapshot_digest"):
            self.run_worker(mutation)

    def test_storage_truncation_after_static_remains_global_failure(self):
        def mutation():
            with self.path.open("r+b") as out:
                out.truncate(len(self.raw)-1)
        with self.assertRaisesRegex(scanner.Incomplete, "snapshot_size"):
            self.run_worker(mutation)

    def test_bad_initial_digest_never_reaches_native_or_static_scan(self):
        self.request["artifact"] = dict(self.artifact, sha256="0"*64)
        with mock.patch.object(scanner, "child_limits"), \
                mock.patch.object(scanner, "rule_inventory", return_value=[]), \
                mock.patch.object(scanner, "scan_clamav") as native:
            with self.assertRaisesRegex(scanner.Incomplete, "snapshot_digest"):
                scanner.worker(self.request, str(self.root), "/unused")
            native.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
