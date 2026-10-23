#!/usr/bin/env python3
# Copyright The MatrixHub Authors. SPDX-License-Identifier: Apache-2.0
"""Bounded scheduling tests, with mocked native transport, never AV acceptance."""
import contextlib
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import socketserver
import socket
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

if os.name == "nt":
    sys.modules.setdefault("resource", types.ModuleType("resource"))
    if not hasattr(socketserver, "UnixStreamServer"):
        socketserver.UnixStreamServer = socketserver.TCPServer
    # Constants are used only by the fake socket below. These shims cannot
    # implement Unix FD transport or native acceptance on Windows.
    socket.AF_UNIX = getattr(socket, "AF_UNIX", 1)
    socket.SCM_RIGHTS = getattr(socket, "SCM_RIGHTS", 1)


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scanner = load("parallel_scanner", "scanner.py")
fixtures = load("scale_fixture_module", "scale_fixtures.py")


class ParallelTests(unittest.TestCase):
    def limits(self, **environment):
        with mock.patch.dict(os.environ, environment, clear=True):
            return scanner.limits_from_env()

    def test_default_envelope_is_unchanged(self):
        limits = self.limits()
        self.assertEqual(limits["native_threads"], 1)
        self.assertEqual(limits["max_batch_bytes"], 256 << 20)
        self.assertEqual(limits["max_file_bytes"], 64 << 20)
        self.assertEqual(limits["native_wave_bytes"], 2 << 30)
        self.assertEqual(limits["native_wave_policy"], "ordered-greedy-verified-fd-v1")

    def test_wave_plan_uses_verified_fd_sizes_original_order_and_both_bounds(self):
        files = [types.SimpleNamespace(fileno=lambda index=index: index) for index in range(8)]
        sizes = [900 << 20, 900 << 20, 300 << 20, 400 << 20, 500 << 20, 600 << 20, 100 << 20, 100 << 20]
        def info(fd):
            return types.SimpleNamespace(st_mode=scanner.stat.S_IFREG, st_size=sizes[fd])
        with mock.patch.object(scanner.os, "fstat", side_effect=info):
            waves = scanner.native_file_waves(files, {"native_threads": 4})
        self.assertEqual([[data.fileno() for data, _ in wave] for wave in waves], [[0, 1], [2, 3, 4, 5], [6, 7]])
        self.assertTrue(all(sum(size for _, size in wave) <= 2 << 30 and len(wave) <= 4 for wave in waves))
        with mock.patch.object(scanner.os, "fstat", return_value=types.SimpleNamespace(st_mode=scanner.stat.S_IFREG, st_size=1 << 30)):
            self.assertEqual([len(wave) for wave in scanner.native_file_waves(files, {"native_threads": 4})], [2, 2, 2, 2])
        with mock.patch.object(scanner.os, "fstat", return_value=types.SimpleNamespace(st_mode=scanner.stat.S_IFREG, st_size=(2 << 30) + 1)):
            with self.assertRaisesRegex(scanner.Incomplete, "snapshot_size"):
                scanner.native_file_waves(files, {"native_threads": 4})

    def test_later_wave_failure_discards_previous_results_and_never_starts_following_wave(self):
        # Each fake wave is fully joined before the next is entered. Native
        # transport correctness is tested separately; no large files are made.
        files, visited = [object() for _ in range(6)], []
        waves = [[(files[0], 1), (files[1], 1)], [(files[2], 1), (files[3], 1)], [(files[4], 1), (files[5], 1)]]
        def run(wave, scan_one, stop):
            visited.append(wave)
            if len(visited) == 2:
                raise scanner.Incomplete("clamav_coverage_incomplete")
            return [[], []]
        with mock.patch.object(scanner, "native_file_waves", return_value=waves), \
             mock.patch.object(scanner, "scan_clamd_wave", side_effect=run):
            with self.assertRaisesRegex(scanner.Incomplete, "clamav_coverage_incomplete"):
                scanner.scan_clamd_files(files, {}, {"native_threads": 4, "wall_seconds": 5})
        self.assertEqual(visited, waves[:2])

    def test_waves_share_one_deadline_and_detect_size_change_before_fd_send(self):
        with contextlib.ExitStack() as stack:
            files = [stack.enter_context(tempfile.TemporaryFile()) for _ in range(2)]
            calls = []
            def wave(wave_files, scan_one, stop):
                calls.append(wave_files)
                if len(calls) == 1:
                    return [[]]
                scan_one(*wave_files[0])
            class Socket:
                def __enter__(self): return self
                def __exit__(self, *args): pass
                def shutdown(self, how): pass
                def settimeout(self, value): self.timeout = value
            waves = [[(files[0], 0)], [(files[1], 0)]]
            with mock.patch.object(scanner, "native_file_waves", return_value=waves), \
                 mock.patch.object(scanner, "scan_clamd_wave", side_effect=wave), \
                 mock.patch.object(scanner.time, "monotonic", side_effect=[100, 106]), \
                 mock.patch.object(scanner.socket, "socket", return_value=Socket()):
                with self.assertRaisesRegex(scanner.Incomplete, "scan_timeout"):
                    scanner.scan_clamd_files(files, {}, {"native_threads": 2, "wall_seconds": 5})
            with mock.patch.object(scanner, "native_file_waves", return_value=[[(files[0], 1)]]), \
                 mock.patch.object(scanner.socket, "socket") as socket_factory:
                with self.assertRaisesRegex(scanner.Incomplete, "snapshot_size"):
                    scanner.scan_clamd_files(files, {}, {"native_threads": 2, "wall_seconds": 5})
                socket_factory.assert_not_called()

    def test_gb_batch_is_explicit_and_file_ceiling_remains(self):
        limits = self.limits(SCAN_PROFILE="gb", SCAN_CLAMAV_BACKEND="clamd", SCAN_NATIVE_THREADS="4",
                             SCAN_MAX_BATCH_BYTES=str(5120 << 20))
        self.assertEqual(limits["max_file_bytes"], 1280 << 20)
        self.assertEqual(limits["max_batch_bytes"], 5120 << 20)
        config = scanner.clamd_configuration(".", limits, Path("/tmp/matrix-clamd-0000000000000000"))
        self.assertIn(b"MaxThreads 4\n", config)
        self.assertIn(b"MaxQueue 8\n", config)
        for environment in ({"SCAN_PROFILE": "gb", "SCAN_MAX_BATCH_BYTES": str((5120 << 20) + 1)},
                            {"SCAN_NATIVE_THREADS": "2"},
                            {"SCAN_CLAMAV_BACKEND": "clamd", "SCAN_NATIVE_THREADS": "3"},
                            {"SCAN_PROFILE": "gb-archive", "SCAN_NATIVE_TEMP": "/native-tmp",
                             "SCAN_CLAMAV_BACKEND": "clamd", "SCAN_NATIVE_THREADS": "2"}):
            with self.subTest(environment=environment), self.assertRaises(RuntimeError):
                self.limits(**environment)

    def test_parallel_transport_is_bounded_and_keeps_input_order(self):
        active = peak = 0
        lock, barrier = threading.Lock(), threading.Barrier(4, timeout=3)

        class Socket:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                nonlocal active
                with lock:
                    active -= 1
            def settimeout(self, value):
                self.timeout = value
            def connect(self, path):
                nonlocal active, peak
                with lock:
                    active += 1
                    peak = max(peak, active)
            def sendall(self, value):
                pass
            def sendmsg(self, message, rights):
                self.fd = rights[0][2][0]
                return 1
            def shutdown(self, how):
                pass

        def receive(connection):
            barrier.wait()
            time.sleep((connection.fd % 4) * .001)
            return connection.fd

        with contextlib.ExitStack() as stack:
            files = [stack.enter_context(tempfile.TemporaryFile()) for _ in range(8)]
            for data in files:
                data.write(b"inert")
                data.flush()
            with mock.patch.object(scanner.socket, "socket", side_effect=lambda *args: Socket()), \
                 mock.patch.object(scanner, "check_engine_peer"), \
                 mock.patch.object(scanner, "process_usage", return_value=(1, 0)), \
                 mock.patch.object(scanner, "receive_clamd_reply", side_effect=receive), \
                 mock.patch.object(scanner, "parse_fildes_reply", side_effect=lambda value, size: [value]):
                result = scanner.scan_clamd_files(files, {"socket": "inert", "pid": 1, "startTime": 1},
                                                   {"wall_seconds": 5, "native_threads": 4})
            self.assertEqual(result, [[data.fileno()] for data in files])
        self.assertEqual(peak, 4)
        self.assertEqual(active, 0)

    def test_failure_interrupts_siblings_and_joins_before_returning(self):
        barrier, ended = threading.Barrier(2, timeout=3), []
        lock = threading.Lock()

        class Socket:
            def __init__(self):
                self.stopped = threading.Event()
            def __enter__(self):
                return self
            def __exit__(self, *args):
                with lock:
                    ended.append(self.fd)
            def settimeout(self, value):
                pass
            def connect(self, path):
                pass
            def sendall(self, value):
                pass
            def sendmsg(self, message, rights):
                self.fd = rights[0][2][0]
                return 1
            def shutdown(self, how):
                self.stopped.set()

        with contextlib.ExitStack() as stack:
            files = [stack.enter_context(tempfile.TemporaryFile()) for _ in range(2)]
            failing_fd = files[1].fileno()
            def receive(connection):
                barrier.wait()
                if connection.fd == failing_fd:
                    raise scanner.Incomplete("clamav_coverage_incomplete")
                self.assertTrue(connection.stopped.wait(3), "sibling socket must be interrupted")
                raise scanner.Incomplete("clamav_missing_result")
            with mock.patch.object(scanner.socket, "socket", side_effect=lambda *args: Socket()), \
                 mock.patch.object(scanner, "check_engine_peer"), \
                 mock.patch.object(scanner, "receive_clamd_reply", side_effect=receive):
                with self.assertRaises(scanner.Incomplete):
                    scanner.scan_clamd_files(files, {"socket": "inert", "pid": 1, "startTime": 1},
                                              {"wall_seconds": 5, "native_threads": 2})
            self.assertCountEqual(ended, [data.fileno() for data in files])
            self.assertTrue(all(not data.closed for data in files))

    def test_budget_and_corruption_controls_never_become_clean_static_coverage(self):
        limits = self.limits()
        for name, ext, raw, expected, _category in fixtures.small_controls():
            if expected != "incomplete":
                continue  # Native acceptance covers Picklescan, absent on this host.
            with self.subTest(case=name):
                inspector = scanner.StaticInspector(limits)
                try:
                    inspector.inspect(io.BytesIO(raw), "artifact" + ext)
                except (scanner.Incomplete, *scanner.FORMAT_EXCEPTIONS):
                    continue
                self.fail("budget/corruption fixture unexpectedly completed static coverage")

    def test_rules_absolute_deadline_and_offline_compatibility(self):
        with mock.patch.object(scanner.time, "time", return_value=1000):
            scanner.check_rules_expiry({"rules_expires_at": 0})
            scanner.check_rules_expiry({"rules_expires_at": 1001})
            with self.assertRaisesRegex(scanner.Incomplete, "rules_expired"):
                scanner.check_rules_expiry({"rules_expires_at": 1000})
        for value in ("-1", "+1", " 1", "01", "1.0", "253402300800"):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                self.limits(SCAN_RULES_EXPIRES_AT=value)
        self.assertEqual(self.limits(SCAN_RULES_EXPIRES_AT="2000")["rules_expires_at"], 2000)

    def test_worker_crossing_rules_deadline_never_publishes_complete_result(self):
        limits = self.limits(SCAN_RULES_EXPIRES_AT="1000")
        artifact = {"artifactId": "task-1-1-0000000000000000/" + "0" * 32 + ".blob",
                    "sha256": hashlib.sha256(b"inert").hexdigest(), "size": 5, "type": "opaque;ext=.txt"}
        clock = [999]
        with tempfile.TemporaryFile() as data:
            data.write(b"inert")
            data.seek(0)
            def av(*args):
                clock[0] = 1000
                return []
            request = {"limits": limits, "artifact": artifact, "evidence": {"rules": []},
                       "bundle": {"generation": "0" * 64, "engines": {}}, "backend": "clamscan"}
            with mock.patch.object(scanner, "child_limits"), \
                 mock.patch.object(scanner.time, "time", side_effect=lambda: clock[0]), \
                 mock.patch.object(scanner, "rule_inventory", return_value=[]), \
                 mock.patch.object(scanner, "open_verified", return_value=contextlib.nullcontext(data)), \
                 mock.patch.object(scanner, "scan_clamav", side_effect=av), \
                 mock.patch.object(scanner.StaticInspector, "inspect"), \
                 mock.patch.object(scanner, "verify_held_snapshot") as verified:
                with self.assertRaisesRegex(scanner.Incomplete, "rules_expired"):
                    scanner.worker(request, "inert", "inert")
                verified.assert_called_once()

    def test_fixture_budget_rejects_before_writing(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "new"
            with self.assertRaises(ValueError):
                fixtures.prepare(root, [1000 * fixtures.MIB] * 100, 1 << 30, 0, False)
            self.assertFalse(root.exists())

    def test_small_fixture_manifest_covers_actual_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "new"
            summary = fixtures.prepare(root, [1024, 4096], 8192, 0, False)
            import json
            manifest = json.loads((root / "manifest.json").read_bytes())
            for item in manifest["artifacts"]:
                artifact = item["artifact"]
                raw = (root / artifact["artifactId"]).read_bytes()
                self.assertEqual(len(raw), artifact["size"])
                self.assertEqual(hashlib.sha256(raw).hexdigest(), artifact["sha256"])
            self.assertEqual(summary["bytes"], manifest["writtenBytes"])
            self.assertEqual(manifest["provenance"], "synthetic-inert-no-trained-weights")

    def test_counter_payload_is_reproducible_unique_per_shard_and_block_and_manifest_bound(self):
        first = list(fixtures.tensor_stream(2 * fixtures.MIB + 11, 1, "shake256-counter"))
        again = list(fixtures.tensor_stream(2 * fixtures.MIB + 11, 1, "shake256-counter"))
        second = list(fixtures.tensor_stream(2 * fixtures.MIB + 11, 2, "shake256-counter"))
        self.assertEqual(first, again)
        self.assertEqual(list(map(len, first[1:])), [fixtures.MIB, fixtures.MIB, 11])
        self.assertNotEqual(first[1], first[2])
        self.assertNotEqual(first[1], second[1])
        self.assertNotEqual(first[1], bytes(fixtures.MIB))
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "new"
            fixtures.prepare(root, [4096], 8192, 0, False, payload_pattern="shake256-counter")
            import json
            manifest = json.loads((root / "manifest.json").read_bytes())
            artifact = manifest["artifacts"][0]["artifact"]
            self.assertEqual(manifest["payloadPattern"], "shake256-counter")
            self.assertEqual(manifest["payloadSeedVersion"], fixtures.PAYLOAD_SEED_VERSION)
            self.assertEqual(hashlib.sha256((root / artifact["artifactId"]).read_bytes()).hexdigest(), artifact["sha256"])


if __name__ == "__main__":
    unittest.main()
