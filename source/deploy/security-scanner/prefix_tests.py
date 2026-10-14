#!/usr/bin/env python3
# Copyright The MatrixHub Authors. Licensed under the Apache License, Version 2.0.
"""Fail-only prefix preflight tests. No artifact deserialization or model import.

Metadata-only tests explicitly mock threat classification to exercise profile
semantics. Linux tests additionally use real Picklescan and isolated children.
"""
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import pickle
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock

# Windows has no resource module. This shim only makes pure parser/protocol
# tests importable; all process limit, Unix HTTP and real-child tests are Linux.
if os.name == "nt":
    sys.modules.setdefault("resource", types.ModuleType("resource"))
    if not hasattr(socketserver, "UnixStreamServer"):
        socketserver.UnixStreamServer = socketserver.TCPServer
spec = importlib.util.spec_from_file_location("prefix_scanner", Path(__file__).with_name("scanner.py"))
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)
GENERATION = "a" * 64


def metadata(protocol=2, root=None, version=1001):
    # Serialize only known literal test values. Never load a serialized value.
    system = {"protocol_version": 1001, "little_endian": True,
              "type_sizes": {"short": 2, "int": 4, "long": 8}}
    values = [scanner.LEGACY_MAGIC, version, system, {} if root is None else root, []]
    return b"".join(pickle.dumps(value, protocol=protocol) for value in values)


def with_root_segment(segment, protocol=2):
    raw = metadata(protocol)
    data = io.BytesIO(raw)
    parts = []
    for _ in range(5):
        start = data.tell()
        list(scanner.pickletools.genops(data))
        parts.append(raw[start:data.tell()])
    parts[3] = segment
    return b"".join(parts)


def descriptor(raw, source_size=None):
    return {"prefixBase64": base64.b64encode(raw).decode("ascii"),
            "prefixSha256": hashlib.sha256(raw).hexdigest(), "prefixBytes": len(raw),
            "sourceSize": max(len(raw), 1 << 20) if source_size is None else source_size}


class PrefixProtocolTests(unittest.TestCase):
    def setUp(self):
        self.limits = scanner.limits_from_env()

    def test_unknown_and_maximum_prefix_only_remain_pending(self):
        for raw in [b"x", b"x" * scanner.MAX_PREFIX_BYTES]:
            item = descriptor(raw)
            result = scanner.probe_legacy_prefix(item, self.limits, GENERATION)
            self.assertTrue(scanner.valid_prefix_result(result, item, {"generation": GENERATION}))
            self.assertEqual(result["status"], "pending")
            self.assertEqual(result["reason"], "")
            self.assertNotIn("complete", result)
            self.assertNotIn("analysis", result)

    def test_strict_transport_binding(self):
        item = descriptor(b"ordinary")
        bad_values = [dict(item, unknown=True), dict(item, prefixBytes=True),
                      dict(item, sourceSize=True), dict(item, sourceSize=1),
                      dict(item, sourceSize=self.limits["max_file_bytes"] + 1),
                      dict(item, prefixBytes=scanner.MAX_PREFIX_BYTES + 1),
                      dict(item, prefixSha256="f" * 64), dict(item, prefixSha256="A" * 64),
                      dict(item, prefixBase64=item["prefixBase64"] + "\n"),
                      dict(item, prefixBase64="!"), dict(item, prefixBase64=None),
                      descriptor(b"x" * (scanner.MAX_PREFIX_BYTES + 1))]
        for value in bad_values:
            with self.subTest(value=list(value)):
                with self.assertRaises(scanner.Incomplete):
                    scanner.validate_prefix(value, self.limits)

    def test_response_cannot_claim_completion_or_change_binding(self):
        item = descriptor(b"ordinary")
        valid = scanner.probe_legacy_prefix(item, self.limits, GENERATION)
        invalid = [dict(valid, complete=True), dict(valid, generation="b" * 64),
                   dict(valid, prefixSha256="b" * 64), dict(valid, prefixBytes=True),
                   dict(valid, prefixBytes=item["prefixBytes"] - 1),
                   dict(valid, status="clean"), dict(valid, reason="invalid_serialization"),
                   dict(valid, status="reject", reason="raw parser content")]
        for result in invalid:
            self.assertFalse(scanner.valid_prefix_result(result, item, {"generation": GENERATION}))

    def test_every_incomplete_metadata_prefix_stays_pending(self):
        for protocol in (2, 4):
            raw = metadata(protocol)
            for stop in range(1, len(raw)):
                result = scanner.probe_legacy_prefix(descriptor(raw[:stop]), self.limits, GENERATION)
                self.assertEqual(result["status"], "pending", (protocol, stop))

    def test_malformed_or_oversized_partial_segment_does_not_become_false_reject(self):
        raw = metadata()
        first_end = raw.index(b".") + 1
        for partial in [b"\x80\x02X\xff\xff\xff\xff", b"\x80\x04\x95\xff\xff\xff\xff\xff\xff\xff\xff"]:
            result = scanner.probe_legacy_prefix(descriptor(raw[:first_end] + partial), self.limits, GENERATION)
            self.assertEqual(result["status"], "pending")

    def test_prefix_resource_envelope_is_bounded(self):
        limits = scanner.prefix_limits(self.limits)
        self.assertLessEqual(limits["wall_seconds"], 5)
        self.assertLessEqual(limits["cpu_seconds"], 2)
        self.assertLessEqual(limits["memory_bytes"], 512 << 20)
        self.assertLessEqual(limits["daemon_memory_bytes"], 512 << 20)
        self.assertLessEqual(limits["temp_bytes"], 2 << 20)
        self.assertEqual(limits["max_file_bytes"], self.limits["max_file_bytes"])


class PrefixMetadataTests(unittest.TestCase):
    def setUp(self):
        self.limits = scanner.limits_from_env()
        self.threat = mock.patch.object(scanner.StaticInspector, "inspect_pickle", autospec=True)
        self.inspect = self.threat.start()
        self.addCleanup(self.threat.stop)

    def probe(self, raw):
        return scanner.probe_legacy_prefix(descriptor(raw), self.limits, GENERATION)

    def test_complete_metadata_never_approves_missing_storage_or_tail(self):
        for protocol in (2, 4):
            raw = metadata(protocol)
            result = self.probe(raw + b"cos\nsystem\n.")
            self.assertEqual(result["status"], "pending")
            # A mandatory final format validator still rejects the extra tail.
            with self.assertRaises(scanner.LegacyTorchError):
                scanner.verify_legacy_torch(io.BytesIO(raw + b"x"), lambda *_: None, self.limits)
            complete = scanner.verify_legacy_torch(io.BytesIO(raw), lambda *_: None, self.limits)
            self.assertTrue(complete["completeByteCoverage"])
        self.assertEqual(self.inspect.call_count, 10)

    def test_same_metadata_semantic_failures_as_full_validator(self):
        samples = [metadata(version=1002), metadata(root=5),
                   with_root_segment(b"\x80\x02cos\nsystem\n."),
                   with_root_segment(b"\x80\x02cfixture_unknown\nconstruct\n.")]
        for raw in samples:
            result = self.probe(raw)
            self.assertEqual(result["status"], "reject")
            with self.assertRaises(scanner.LegacyTorchError) as error:
                scanner.verify_legacy_torch(io.BytesIO(raw), lambda *_: None, self.limits)
            self.assertEqual(result["reason"], error.exception.code)

    def test_complete_segment_threat_coverage_failure_can_only_reject(self):
        self.inspect.side_effect = scanner.Incomplete("pickle_analysis_incomplete")
        result = self.probe(metadata())
        self.assertEqual((result["status"], result["reason"]), ("reject", "pickle_analysis_incomplete"))

    def test_resource_or_internal_failure_is_not_normalized_into_artifact_rejection(self):
        self.inspect.side_effect = scanner.Incomplete("pickle_opcode_limit")
        with self.assertRaises(scanner.Incomplete):
            self.probe(metadata())
        self.inspect.side_effect = RuntimeError("untrusted detail")
        with self.assertRaises(RuntimeError):
            self.probe(metadata())

    def test_rules_are_checked_on_both_sides_in_child(self):
        request = {"limits": self.limits, "prefix": descriptor(metadata()),
                   "evidence": {"rules": ["before"]}, "bundle": {"generation": GENERATION}}
        with mock.patch.object(scanner, "child_limits"), mock.patch.object(scanner, "rule_inventory", side_effect=[["before"], ["after"]]):
            with self.assertRaisesRegex(scanner.Incomplete, "rules_changed"):
                scanner.prefix_worker(request, "unused")


@unittest.skipUnless(os.name == "posix", "requires Linux process groups and resource limits")
class PrefixIsolatedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        rules = Path(self.temp.name) / "rules"
        rules.mkdir()
        (rules / "prefix-fixture.hdb").write_bytes(b"prefix hashing fixture only; no antivirus claim\n")
        self.engine = mock.Mock()
        self.engine.healthy.return_value = True
        self.state = {"limits": scanner.limits_from_env(), "bundle": {"generation": GENERATION},
                      "evidence": {"rules": scanner.rule_inventory(rules)}, "rules": str(rules),
                      "input": self.temp.name, "backend": "clamd", "engine": self.engine,
                      "workers": set(), "workers_lock": threading.Lock(),
                      "rule_stamp": scanner.rule_stamp(rules), "semaphore": threading.BoundedSemaphore(1),
                      "closing": False, "unsafe": False}

    def test_real_picklescan_child_safe_and_dangerous_metadata(self):
        for raw, status in [(metadata(), "pending"), (metadata(4), "pending"),
                            (with_root_segment(b"\x80\x02cos\nsystem\n."), "reject")]:
            result = scanner.run_worker(descriptor(raw), self.state, probe=True)
            self.assertEqual(result["status"], status)
            self.assertNotIn("complete", result)
            self.assertFalse(self.state["workers"])
        self.engine.begin.assert_not_called()
        self.engine.abort.assert_not_called()

    def test_supervisor_timeout_reaps_prefix_child_without_native_restart(self):
        self.state["limits"]["wall_seconds"] = 1
        actual_popen = scanner.subprocess.Popen
        children = []
        def stalled(_command, **kwargs):
            child = actual_popen([sys.executable, "-I", "-c", "import sys,time;sys.stdin.buffer.read();time.sleep(20)"], **kwargs)
            children.append(child)
            return child
        with mock.patch.object(scanner.subprocess, "Popen", side_effect=stalled):
            with self.assertRaisesRegex(scanner.Incomplete, "scan_timeout"):
                scanner.run_worker(descriptor(metadata()), self.state, probe=True)
        self.assertTrue(all(child.poll() is not None and scanner.process_group_absent(child.pid) for child in children))
        self.assertFalse(self.state["workers"])
        self.engine.abort.assert_not_called()

    def test_peer_disconnect_cancels_prefix_child_without_native_restart(self):
        peer, client = socket.socketpair()
        self.addCleanup(peer.close)
        client.close()
        with self.assertRaisesRegex(scanner.Incomplete, "scan_cancelled"):
            scanner.run_worker(descriptor(metadata()), self.state, peer=peer, probe=True)
        self.assertFalse(self.state["workers"])
        self.engine.abort.assert_not_called()

    def test_real_unix_http_generation_schema_busy_and_prefix_result(self):
        address = str(Path(self.temp.name) / "prefix.sock")
        server = scanner.UnixHTTPServer(address, scanner.Handler)
        server.state = self.state
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        def cleanup():
            server.shutdown()
            server.server_close()
            thread.join(2)
        self.addCleanup(cleanup)
        def request(value, generation=GENERATION):
            payload = scanner.canonical(value)
            wire = ("POST /v1/probe-legacy-prefix HTTP/1.0\r\nX-Expected-Generation: " + generation +
                    "\r\nContent-Type: application/json\r\nContent-Length: " + str(len(payload)) + "\r\n\r\n").encode() + payload
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(10)
                client.connect(address)
                client.sendall(wire)
                chunks = []
                while block := client.recv(65536):
                    chunks.append(block)
            header, body = b"".join(chunks).split(b"\r\n\r\n", 1)
            return int(header.split()[1]), json.loads(body)
        item = descriptor(with_root_segment(b"\x80\x02cos\nsystem\n."))
        code, response = request(item)
        self.assertEqual(code, 200)
        self.assertEqual(response["status"], "reject")
        self.assertTrue(scanner.valid_prefix_result(response, item, self.state["bundle"]))
        self.assertEqual(request(item, "b" * 64), (409, {"error": "generation_changed"}))
        self.assertEqual(request(dict(item, prefixSha256="f" * 64)), (400, {"error": "invalid_request"}))
        self.state["semaphore"].acquire()
        try:
            self.assertEqual(request(item), (503, {"error": "scanner_busy"}))
        finally:
            self.state["semaphore"].release()
        self.assertFalse(self.state["workers"])
        self.engine.begin.assert_not_called()


if __name__ == "__main__":
    unittest.main()
