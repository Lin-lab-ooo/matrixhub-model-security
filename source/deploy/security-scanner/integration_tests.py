#!/usr/bin/env python3
# Copyright The MatrixHub Authors. Licensed under the Apache License, Version 2.0.
"""Real-engine Unix protocol/fault tests; static fixtures are never executed.

Use the hardened container and complete official /rules snapshot. /tmp inputs
are owned by this test harness so integrity faults can be injected deliberately.
Production /input mount isolation is checked separately by tests.py.
"""
import hashlib
import http.client
import importlib.util
import io
import json
import os
from pathlib import Path
import resource
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
import zipfile

spec = importlib.util.spec_from_file_location("matrix_scanner", Path(__file__).with_name("scanner.py"))
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)
SAFE = b"(dp0\n."
DANGEROUS = b"]0cos\nsystem\n."


EMBEDDED_LEGACY_MANIFEST = {'cases': [{'id': 'torch280-torch-legacy-p2',
            'payloadHex': '80028a0a6cfc9c46f9206aa850192e80024de9032e80027d710028581000000070726f746f636f6c5f76657273696f6e71014de903580d0000006c6974746c655f656e6469616e710288580a000000747970655f73697a657371037d710428580500000073686f727471054b025803000000696e7471064b0458040000006c6f6e6771074b0475752e80027d71005806000000776569676874710163746f7263682e5f7574696c730a5f72656275696c645f74656e736f725f76320a71022828580700000073746f72616765710363746f7263680a466c6f617453746f726167650a7104580d000000323239323937373831323539327105580300000063707571064b0c4e747107514b004b034b048671084b044b018671098963636f6c6c656374696f6e730a4f726465726564446963740a710a2952710b74710c52710d732e80025d7100580d000000323239323937373831323539327101612e0c00000000000000000000000000803f0000004000004040000080400000a0400000c0400000e04000000041000010410000204100003041',
            'pickleProtocol': 2,
            'sha256': 'fecfea3598cfe66616dabe3e3a25499fcfce0fcc42475b3193a8658950b63c14',
            'size': 404},
           {'id': 'torch280-torch-legacy-p4',
            'payloadHex': '8004950d000000000000008a0a6cfc9c46f9206aa850192e80049504000000000000004de9032e80049558000000000000007d94288c1070726f746f636f6c5f76657273696f6e944de9038c0d6c6974746c655f656e6469616e94888c0a747970655f73697a6573947d94288c0573686f7274944b028c03696e74944b048c046c6f6e67944b0475752e800495a8000000000000007d948c06776569676874948c0c746f7263682e5f7574696c73948c125f72656275696c645f74656e736f725f763294939428288c0773746f72616765948c05746f726368948c0c466c6f617453746f726167659493948c0d32323932393737383136353132948c03637075944b0c4e7494514b004b034b0486944b044b018694898c0b636f6c6c656374696f6e73948c0b4f7264657265644469637494939429529474945294732e80049514000000000000005d948c0d3232393239373738313635313294612e0c00000000000000000000000000803f0000004000004040000080400000a0400000c0400000e04000000041000010410000204100003041',
            'pickleProtocol': 4,
            'sha256': 'd3f10a7de0e41e4bb24c8b894d47f9af609bbcee7f6c00c35ac781438e55c05e',
            'size': 404},
           {'id': 'torch291-torch-legacy-p2',
            'payloadHex': '80028a0a6cfc9c46f9206aa850192e80024de9032e80027d710028581000000070726f746f636f6c5f76657273696f6e71014de903580d0000006c6974746c655f656e6469616e710288580a000000747970655f73697a657371037d710428580500000073686f727471054b025803000000696e7471064b0458040000006c6f6e6771074b0475752e80027d71005806000000776569676874710163746f7263682e5f7574696c730a5f72656275696c645f74656e736f725f76320a71022828580700000073746f72616765710363746f7263680a466c6f617453746f726167650a7104580d000000333034313335363739393032347105580300000063707571064b0c4e747107514b004b034b048671084b044b018671098963636f6c6c656374696f6e730a4f726465726564446963740a710a2952710b74710c52710d732e80025d7100580d000000333034313335363739393032347101612e0c00000000000000000000000000803f0000004000004040000080400000a0400000c0400000e04000000041000010410000204100003041',
            'pickleProtocol': 2,
            'sha256': '0f19c92bf0d933a21f1e29d66c1f72fa505d7dea7a3e29c34f4cf519b2c3fdd8',
            'size': 404},
           {'id': 'torch291-torch-legacy-p4',
            'payloadHex': '8004950d000000000000008a0a6cfc9c46f9206aa850192e80049504000000000000004de9032e80049558000000000000007d94288c1070726f746f636f6c5f76657273696f6e944de9038c0d6c6974746c655f656e6469616e94888c0a747970655f73697a6573947d94288c0573686f7274944b028c03696e74944b048c046c6f6e67944b0475752e800495a8000000000000007d948c06776569676874948c0c746f7263682e5f7574696c73948c125f72656275696c645f74656e736f725f763294939428288c0773746f72616765948c05746f726368948c0c466c6f617453746f726167659493948c0d33303431333536373936373834948c03637075944b0c4e7494514b004b034b0486944b044b018694898c0b636f6c6c656374696f6e73948c0b4f7264657265644469637494939429529474945294732e80049514000000000000005d948c0d3330343133353637393637383494612e0c00000000000000000000000000803f0000004000004040000080400000a0400000c0400000e04000000041000010410000204100003041',
            'pickleProtocol': 4,
            'sha256': 'd797d7199ef8bf3c70e37f2ba24ac0604a9b7a10637c8fb4359a84c0fd8e0b86',
            'size': 404}],
 'status': 'PREPARED_NOT_EXECUTED'}


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout=100):
        super().__init__("scanner", timeout=timeout)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class ProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.inputs = cls.root / "input"
        cls.inputs.mkdir()
        cls.socket = cls.root / "scanner.sock"
        cls.logs = tempfile.TemporaryFile()
        cls.proc = subprocess.Popen([sys.executable, "-I", str(Path(scanner.__file__)),
                                     "--input", str(cls.inputs), "--rules", "/rules", "--socket", str(cls.socket)],
                                    stdout=cls.logs, stderr=cls.logs)
        deadline = time.monotonic() + 30
        while not cls.socket.exists():
            if cls.proc.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError("scanner failed to become ready")
            time.sleep(0.05)
        code, cls.bundle = cls.call("GET", "/v1/bundle")
        if code != 200:
            raise RuntimeError("scanner bundle unavailable")
        cls.measurements = []
        print("BUNDLE " + json.dumps(cls.bundle), flush=True)

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        cls.proc.wait(timeout=5)
        cls.logs.close()
        cls.tmp.cleanup()
        peak = Path("/sys/fs/cgroup/memory.peak")
        evidence = {"measurements": cls.measurements,
                    "child_max_rss_kib": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
                    "container_memory_peak_bytes": int(peak.read_text()) if peak.exists() else None}
        print("EVIDENCE " + json.dumps(evidence, sort_keys=True), flush=True)

    @classmethod
    def call(cls, method, path, body=None, generation=None):
        connection = UnixConnection(cls.socket)
        headers = {"Content-Type": "application/json"}
        if generation:
            headers["X-Expected-Generation"] = generation
        connection.request(method, path, body=json.dumps(body) if body is not None else None, headers=headers)
        response = connection.getresponse()
        value = json.loads(response.read())
        connection.close()
        return response.status, value

    def artifact(self, content, ext=".pkl"):
        aid = "task-1-1-0000000000000000/" + uuid.uuid4().hex + ".blob"
        p = self.inputs / aid
        p.parent.mkdir(exist_ok=True)
        p.write_bytes(content)
        p.chmod(0o440)
        return {"artifactId": aid, "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content), "type": "opaque;ext=" + ext}

    def analyze(self, artifact):
        return self.call("POST", "/v1/analyze", artifact, self.bundle["generation"])

    def assert_file_incomplete(self, code, analysis, expected):
        self.assertEqual(code, 200)
        self.assertIs(analysis["complete"], False)
        self.assertEqual(analysis["generation"], self.bundle["generation"])
        self.assertEqual(analysis["engines"], self.bundle["engines"])
        coverage = [f for f in analysis["findings"] if f["engine"] == "coverage"]
        self.assertEqual(len(coverage), 1)
        self.assertEqual(coverage[0], scanner.coverage_finding(expected))
        self.assertGreaterEqual(analysis["durationMs"], 0)

    def test_01_real_engine_complete_classifications(self):
        eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        cases = [("safe_pickle", SAFE, ".pkl", None),
                 ("dangerous_renamed_pickle", DANGEROUS, ".txt", "critical"),
                 ("unknown_global", b"\x80\x02cmatrixhub_e2e_fixture\nUnknownCallable\n.", ".pkl", "medium"),
                 ("eicar_test_string", eicar, ".com", "critical")]
        for name, content, ext, severity in cases:
            with self.subTest(name=name):
                started = time.monotonic()
                code, result = self.analyze(self.artifact(content, ext))
                elapsed = time.monotonic() - started
                self.assertEqual(code, 200, result)
                if name == "unknown_global":
                    self.assert_file_incomplete(code, result, "unsupported_container_or_serialization")
                else:
                    self.assertTrue(result["complete"])
                self.assertEqual(result["generation"], self.bundle["generation"])
                self.assertEqual(result["engines"], self.bundle["engines"])
                if severity:
                    self.assertIn(severity, [f["severity"] for f in result["findings"]])
                else:
                    self.assertEqual(result["findings"], [])
                self.measurements.append({"sample": name, "bytes": len(content), "wall_seconds": round(elapsed, 4),
                                          "worker_duration_ms": result["durationMs"]})

    def test_02_explicit_incomplete_codes(self):
        zipped = io.BytesIO()
        with zipfile.ZipFile(zipped, "w", zipfile.ZIP_DEFLATED) as out:
            out.writestr("zeros.txt", b"0" * 100000)
        for content, ext, expected, expected_http in [(b"\x93NUMPY", ".npy", "invalid_serialization", 200),
                                        (SAFE + b"broken", ".pkl", "pickle_symbol_analysis_incomplete", 200),
                                        (zipped.getvalue(), ".zip", "archive_ratio_limit", 422)]:
            with self.subTest(expected=expected):
                code, result = self.analyze(self.artifact(content, ext))
                if expected_http == 200:
                    self.assert_file_incomplete(code, result, expected)
                else:
                    self.assertEqual((code, result), (422, {"error": expected}))

    def test_03_snapshot_tamper_is_incomplete(self):
        artifact = self.artifact(SAFE)
        p = self.inputs / artifact["artifactId"]
        p.chmod(0o600)
        p.write_bytes(b"x" * len(SAFE))
        code, result = self.analyze(artifact)
        self.assertEqual((code, result), (422, {"error": "snapshot_digest"}))

    def test_04_descriptor_generation_and_request_boundary(self):
        artifact = self.artifact(SAFE)
        code, result = self.call("POST", "/v1/analyze", artifact, "0" * 64)
        self.assertEqual((code, result), (409, {"error": "generation_changed"}))
        artifact["artifactId"] = "../../etc/passwd"
        code, result = self.analyze(artifact)
        self.assertEqual((code, result), (400, {"error": "invalid_request"}))

    def test_05_wall_time_kills_whole_worker_group(self):
        artifact = self.artifact(b"N0" * 3000000 + b"N.")
        limits = scanner.limits_from_env()
        limits.update(wall_seconds=1, max_pickle_opcodes=10000000)
        bundle, evidence = scanner.create_bundle("/rules", limits)
        state = {"bundle": bundle, "evidence": evidence, "limits": limits,
                 "input": str(self.inputs), "rules": "/rules"}
        started = time.monotonic()
        with self.assertRaisesRegex(scanner.Incomplete, "scan_timeout"):
            scanner.run_worker(artifact, state)
        self.assertLess(time.monotonic() - started, 4)

    def test_06_client_cancel_and_busy_do_not_admit(self):
        artifact = self.artifact(b"N0" * 3000000 + b"N.")
        body = json.dumps(artifact).encode()
        peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        peer.connect(str(self.socket))
        peer.sendall(b"POST /v1/analyze HTTP/1.0\r\nContent-Length: " + str(len(body)).encode() +
                     b"\r\nX-Expected-Generation: " + self.bundle["generation"].encode() + b"\r\n\r\n" + body)
        time.sleep(0.2)
        code, result = self.analyze(self.artifact(SAFE))
        self.assertEqual((code, result), (503, {"error": "scanner_busy"}))
        peer.close()
        children = Path(f"/proc/{self.proc.pid}/task/{self.proc.pid}/children")
        deadline = time.monotonic() + 3
        while children.read_text().strip() and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual(children.read_text().strip(), "", "cancellation left a scanner worker alive")

    def test_07_limits_are_part_of_generation(self):
        limits = scanner.limits_from_env()
        original, evidence = scanner.create_bundle("/rules", limits)
        limits["max_members"] += 1
        changed, _ = scanner.create_bundle("/rules", limits)
        self.assertNotEqual(original["generation"], changed["generation"])
        self.assertEqual(len(evidence["rules"]), 3)
        print("RULES " + json.dumps(evidence["rules"], sort_keys=True), flush=True)

    def test_08_worker_rechecks_rule_evidence(self):
        limits = scanner.limits_from_env()
        bundle, evidence = scanner.create_bundle("/rules", limits)
        evidence["rules"][0]["sha256"] = "0" * 64
        state = {"bundle": bundle, "evidence": evidence, "limits": limits,
                 "input": str(self.inputs), "rules": "/rules"}
        with self.assertRaisesRegex(scanner.Incomplete, "rules_changed"):
            scanner.run_worker(self.artifact(SAFE), state)

    def test_09_complete_batch_binds_every_result_to_its_artifact(self):
        if not self.bundle.get("maxBatchFiles"):
            self.skipTest("legacy scanner has no batch protocol")
        eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        artifacts = [self.artifact(SAFE), self.artifact(DANGEROUS, ".txt"),
                     self.artifact(b"\x80\x02cmatrixhub_e2e_fixture\nUnknownCallable\n."),
                     self.artifact(eicar, ".com"), self.artifact(b"", ".txt")]
        started = time.monotonic()
        code, value = self.call("POST", "/v1/analyze-batch", {"artifacts": artifacts}, self.bundle["generation"])
        self.assertEqual(code, 200, value)
        self.assertEqual([x["artifactId"] for x in value["results"]], [a["artifactId"] for a in artifacts])
        self.assertEqual(len(value["results"]), len(artifacts))
        for item, severity in zip(value["results"], [None, "critical", "medium", "critical", None]):
            result = item["analysis"]
            if severity == "medium":
                self.assert_file_incomplete(code, result, "unsupported_container_or_serialization")
            else:
                self.assertTrue(result["complete"])
            self.assertEqual(result["generation"], self.bundle["generation"])
            self.assertEqual(result["engines"], self.bundle["engines"])
            if severity == "medium":
                self.assertEqual([f["severity"] for f in result["findings"] if f["engine"] != "coverage"], [severity])
            else:
                self.assertEqual([f["severity"] for f in result["findings"]], [severity] if severity else [])
        self.measurements.append({"sample": "mixed_batch_five", "bytes": sum(a["size"] for a in artifacts),
                                  "wall_seconds": round(time.monotonic() - started, 4)})

    def test_10_one_incomplete_file_preserves_other_file_evidence(self):
        if not self.bundle.get("maxBatchFiles"):
            self.skipTest("legacy scanner has no batch protocol")
        artifacts = [self.artifact(SAFE), self.artifact(b"\x93NUMPY", ".npy")]
        code, value = self.call("POST", "/v1/analyze-batch", {"artifacts": artifacts}, self.bundle["generation"])
        self.assertEqual(code, 200, value)
        self.assertEqual([item["artifactId"] for item in value["results"]], [a["artifactId"] for a in artifacts])
        self.assertEqual(len(value["results"]), 2)
        self.assertTrue(value["results"][0]["analysis"]["complete"])
        self.assertEqual(value["results"][0]["analysis"]["findings"], [])
        self.assert_file_incomplete(code, value["results"][1]["analysis"], "invalid_serialization")
        code, value = self.call("POST", "/v1/analyze-batch", {"artifacts": [artifacts[0], artifacts[0]]}, self.bundle["generation"])
        self.assertEqual((code, value), (400, {"error": "invalid_request"}))

    def test_11_safetensors_dispatch_and_renamed_pickle_fail_closed(self):
        header = json.dumps({"x": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]}},
                            separators=(",", ":")).encode().ljust(128, b" ")
        content = len(header).to_bytes(8, "little") + header + b"\x00"
        self.assertEqual(len(content), 137)
        artifact = self.artifact(content, ".safetensors")
        code, result = self.analyze(artifact)
        self.assertEqual(code, 200, result)
        self.assertTrue(result["complete"])
        self.assertEqual(result["generation"], self.bundle["generation"])
        self.assertEqual(result["engines"], self.bundle["engines"])
        self.assertEqual(result["findings"], [])
        renamed = self.artifact(DANGEROUS, ".safetensors")
        code, result = self.analyze(renamed)
        self.assert_file_incomplete(code, result, "invalid_safetensors_header")
        code, result = self.call("POST", "/v1/analyze-batch", {"artifacts": [artifact, renamed]}, self.bundle["generation"])
        self.assertEqual(code, 200, result)
        self.assertEqual([item["artifactId"] for item in result["results"]], [artifact["artifactId"], renamed["artifactId"]])
        self.assertIs(result["results"][0]["analysis"]["complete"], True)
        self.assert_file_incomplete(code, result["results"][1]["analysis"], "invalid_safetensors_header")


    def test_12_default_legacy_cpu_four_fixed_sources_have_proof_and_real_api_result(self):
        manifest = EMBEDDED_LEGACY_MANIFEST
        self.assertEqual(manifest["status"], "PREPARED_NOT_EXECUTED")
        self.assertEqual(len(manifest["cases"]), 4)
        for case in manifest["cases"]:
            with self.subTest(id=case["id"]):
                content = bytes.fromhex(case["payloadHex"])
                self.assertEqual(len(content), case["size"])
                self.assertEqual(hashlib.sha256(content).hexdigest(), case["sha256"])
                limits = scanner.limits_from_env()
                self.assertEqual(limits["max_file_bytes"], 64 << 20)
                inspection = scanner.StaticInspector(limits)
                inspection.inspect(io.BytesIO(content), "fixed-legacy.pt")
                proof = inspection.verified_legacy_torch
                self.assertTrue(proof["completeByteCoverage"])
                self.assertTrue(proof["constructorParametersVerified"])
                self.assertEqual(proof["pickleProtocol"], case["pickleProtocol"])
                self.assertEqual(proof["containerBytes"], len(content))
                self.assertEqual(proof["metadataBytes"] + proof["storageBytes"] + proof["storageHeaderBytes"], len(content))
                self.assertEqual(inspection.findings, [])
                started = time.monotonic()
                code, result = self.analyze(self.artifact(content, ".pt"))
                self.assertEqual(code, 200, result)
                self.assertIs(result["complete"], True)
                self.assertEqual(result["generation"], self.bundle["generation"])
                self.assertEqual(result["engines"], self.bundle["engines"])
                self.assertEqual(result["findings"], [])
                self.assertEqual(hashlib.sha256(bytes.fromhex(case["payloadHex"])).hexdigest(), case["sha256"])
                self.measurements.append({"sample": case["id"], "bytes": len(content),
                                          "wall_seconds": round(time.monotonic() - started, 4),
                                          "worker_duration_ms": result["durationMs"],
                                          "default_profile": True, "native_backend": "clamscan"})

    def test_13_default_profile_is_not_gb_or_persistent_clamd(self):
        self.assertEqual(os.getenv("SCAN_PROFILE", "default"), "default")
        self.assertEqual(scanner.backend_from_env(), "clamscan")
        self.assertEqual(self.bundle["maxFileBytes"], 64 << 20)
        self.assertEqual(self.bundle["maxBatchFiles"], 32)
        self.assertEqual(self.bundle["maxBatchBytes"], 256 << 20)
        self.assertEqual(set(self.bundle["engines"]), {"clamav", "picklescan"})
        self.assertNotIn("native_temp_bytes", scanner.limits_from_env())


if __name__ == "__main__":
    unittest.main(verbosity=2)
