#!/usr/bin/env python3
# Copyright The MatrixHub Authors. SPDX-License-Identifier: Apache-2.0
"""Record complete scanner throughput and diagnostic phase timings as JSONL.

Run --socket against a fresh, isolated scanner for production-protocol timings.
Run --phases separately for instrumented full worker timings under the same
supervisor limits. Phase diagnostics do not publish application approvals.
No artifact contents, credentials, operands or raw native output are recorded.
"""
import argparse
import contextlib
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
import threading
import time


MAX_OUTPUT = 2 << 20
_SCANNER = None


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def load_scanner():
    global _SCANNER
    if _SCANNER is not None:
        return _SCANNER
    spec = importlib.util.spec_from_file_location("scale_scanner", Path(__file__).with_name("scanner.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _SCANNER = module
    return module


def proc_io():
    try:
        return {key: int(value) for key, value in
                (line.split(":", 1) for line in Path("/proc/self/io").read_text().splitlines())}
    except (OSError, ValueError):
        return {}


def phase_child(args):
    import resource
    scanner = load_scanner()
    metrics, before = {}, proc_io()
    measuring = threading.local()
    def timed(name, function):
        def wrapped(*values, **keywords):
            active = getattr(measuring, "active", set())
            if name in active:
                return function(*values, **keywords)
            measuring.active = active | {name}
            started = time.monotonic()
            try:
                return function(*values, **keywords)
            finally:
                metrics[name] = metrics.get(name, 0.0) + time.monotonic() - started
                measuring.active = active
        return wrapped
    for function, label in (("rule_inventory", "rulesPrePostSeconds"),
                            ("open_verified", "openFullPreHashSeconds"),
                            ("scan_clamav", "nativeAvSeconds"),
                            ("scan_clamav_batch", "nativeAvSeconds"),
                            ("scan_clamd_files", "nativeAvSeconds"),
                            ("verify_held_snapshot", "postFullHashSeconds")):
        setattr(scanner, function, timed(label, getattr(scanner, function)))
    original_wave = scanner.scan_clamd_wave
    def wave(wave_files, scan_one, stop_connections):
        attempt = {"selectedFiles": len(wave_files), "heldFdBytes": sum(size for _, size in wave_files),
                   "completed": False}
        metrics.setdefault("nativeWaveAttempts", []).append(attempt)
        result = original_wave(wave_files, scan_one, stop_connections)
        attempt["completed"] = True
        return result
    scanner.scan_clamd_wave = wave
    original = scanner.StaticInspector.inspect
    def inspect(self, data, name, depth=0, archive_chain=()):
        if depth or archive_chain:
            return original(self, data, name, depth, archive_chain)
        return timed("staticSeconds", original)(self, data, name, depth, archive_chain)
    scanner.StaticInspector.inspect = inspect
    code, result = 0, None
    try:
        request = json.loads(sys.stdin.buffer.read(1 << 20))
        metrics.update(nativeWavePolicy=request["limits"]["native_wave_policy"],
                       nativeWaveByteLimit=request["limits"]["native_wave_bytes"],
                       nativeSerialCompatibilityPath=request["limits"]["native_threads"] == 1)
        result = scanner.worker(request, args.input, args.rules)
    except scanner.Incomplete as error:
        reason = error.args[0] if error.args else None
        result, code = {"complete": False, "error": reason if reason in scanner.ERROR_CODES else "worker_failed_or_incomplete"}, 2
    except BaseException:
        result, code = {"complete": False}, 2
    finally:
        after = proc_io()
        metrics["workerIoDelta"] = {key: max(0, value - before.get(key, value)) for key, value in after.items()}
        usage = resource.getrusage(resource.RUSAGE_SELF)
        metrics.update(workerMaxRSSKiB=usage.ru_maxrss, workerCpuSeconds=usage.ru_utime + usage.ru_stime,
                       scope="instrumented-full-worker-not-application-approval")
        raw = canonical(metrics)
        if len(raw) <= 16384:
            os.write(args.metrics_fd, raw)
        os.close(args.metrics_fd)
    sys.stdout.buffer.write(canonical(result))
    return code


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout):
        super().__init__("scanner", timeout=timeout)
        self.path = path
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def call(path, method, route, payload=None, generation=None, timeout=330):
    connection = UnixConnection(path, timeout)
    headers = {"Content-Type": "application/json"}
    if generation:
        headers["X-Expected-Generation"] = generation
    try:
        connection.request(method, route, None if payload is None else canonical(payload), headers)
        response = connection.getresponse()
        raw = response.read(MAX_OUTPUT + 1)
        if len(raw) > MAX_OUTPUT:
            raise ValueError("response limit")
        return response.status, json.loads(raw)
    finally:
        connection.close()


def classify(analysis):
    if not isinstance(analysis, dict) or analysis.get("complete") is not True:
        return "incomplete"
    findings = analysis.get("findings")
    if not isinstance(findings, list):
        return "invalid"
    return "block" if any(item.get("severity") in {"high", "critical"} for item in findings) else "clean"


def summarize(value, entries, bundle):
    results = value.get("results", []) if isinstance(value, dict) else []
    if len(results) != len(entries):
        return {"protocolValid": False, "outcomes": [], "expectedMatches": 0}
    valid = load_scanner().valid_worker_result(value, [entry["artifact"] for entry in entries], bundle, batch=True)
    if not valid:
        return {"protocolValid": False, "outcomes": [], "expectedMatches": 0}
    outcomes, matches = [], 0
    for item, entry in zip(results, entries):
        analysis = item.get("analysis", {})
        outcome = classify(analysis)
        outcomes.append(outcome)
        matches += outcome == entry.get("expected")
    return {"protocolValid": bool(valid), "outcomes": outcomes, "expectedMatches": matches,
            "expectedKnown": sum(entry.get("expected") in {"clean", "incomplete", "block"} for entry in entries)}


def expected_rejection(value, entries, status):
    if (status == 422 and isinstance(value, dict) and set(value) == {"error"}
            and value["error"] in {"archive_ratio_limit", "archive_depth_limit", "archive_member_limit", "expanded_bytes_limit", "clamav_coverage_incomplete"}
            and entries and all(entry.get("expected") == "incomplete"
                                and entry.get("category") in {"inert-budget-control", "corrupt-format"}
                                and value["error"] in entry.get("expectedRequestErrors", []) for entry in entries)):
        return {"protocolValid": True, "outcomes": ["incomplete"] * len(entries),
                "expectedMatches": len(entries), "expectedKnown": len(entries),
                "expectedRejectionControl": True, "completeCoverage": False}
    return None


def plans(entries, files, byte_limit):
    batch = []
    for entry in entries:
        if batch and (len(batch) >= files or sum(item["artifact"]["size"] for item in batch) + entry["artifact"]["size"] > byte_limit):
            yield batch
            batch = []
        batch.append(entry)
    if batch:
        yield batch


def process_sample(pid):
    """Read only process accounting, never command lines, environ or memory."""
    pending, seen, rss, cpu, io_read = [pid], set(), 0, 0.0, 0
    ticks = os.sysconf("SC_CLK_TCK")
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        try:
            root = Path("/proc") / str(current)
            fields = (root / "stat").read_text().rsplit(")", 1)[1].split()
            cpu += (int(fields[11]) + int(fields[12])) / ticks
            rss += max(0, int(fields[21])) * os.sysconf("SC_PAGE_SIZE")
            for line in (root / "io").read_text().splitlines():
                if line.startswith("read_bytes:"):
                    io_read += int(line.split(":", 1)[1])
            # Include every task's children; native daemons may create threads.
            for task in (root / "task").iterdir():
                pending.extend(int(value) for value in (task / "children").read_text().split())
        except (OSError, ValueError, IndexError):
            continue
    return {"treeRSSBytes": rss, "liveTreeCpuSeconds": cpu, "liveTreeReadBytes": io_read}


def cgroup_sample():
    result = {}
    root = Path("/sys/fs/cgroup")
    try:
        result["cpuUsageUsec"] = int(dict(line.split() for line in (root / "cpu.stat").read_text().splitlines())["usage_usec"])
    except (OSError, ValueError, KeyError):
        pass
    try:
        result["memoryPeakBytes"] = int((root / "memory.peak").read_text())
    except (OSError, ValueError):
        pass
    try:
        io_read = io_write = 0
        for line in (root / "io.stat").read_text().splitlines():
            values = dict(field.split("=", 1) for field in line.split()[1:])
            io_read += int(values.get("rbytes", 0))
            io_write += int(values.get("wbytes", 0))
        result.update(ioReadBytes=io_read, ioWriteBytes=io_write)
    except (OSError, ValueError):
        pass
    return result


class Sampler:
    def __init__(self, pid):
        self.pid, self.stop, self.thread = pid, threading.Event(), None
        self.peak, self.cpu_peak, self.read_peak, self.samples = 0, 0.0, 0, 0
    def __enter__(self):
        self.cgroup_before = cgroup_sample()
        if self.pid:
            def loop():
                while not self.stop.is_set():
                    sample = process_sample(self.pid)
                    self.peak = max(self.peak, sample["treeRSSBytes"])
                    self.cpu_peak = max(self.cpu_peak, sample["liveTreeCpuSeconds"])
                    self.read_peak = max(self.read_peak, sample["liveTreeReadBytes"])
                    self.samples += 1
                    self.stop.wait(.05)
            self.thread = threading.Thread(target=loop, daemon=True)
            self.thread.start()
        return self
    def __exit__(self, *args):
        self.stop.set()
        if self.thread:
            self.thread.join()
        self.cgroup_after = cgroup_sample()
    def result(self):
        delta = {key: max(0, value - self.cgroup_before[key]) for key, value in self.cgroup_after.items()
                 if key in self.cgroup_before and key != "memoryPeakBytes"}
        return {"treeRSSPeakBytesSampled": self.peak if self.pid else None,
                "liveTreeCpuPeakSeconds": self.cpu_peak if self.pid else None,
                "liveTreeReadPeakBytes": self.read_peak if self.pid else None,
                "accountingSamples": self.samples,
                "accountingScope": "sampled-live-tree-cumulative-not-per-request-cpu-or-disk-delta",
                "cgroupCounterDelta": delta,
                "cgroupMemoryPeakBytesLifetime": self.cgroup_after.get("memoryPeakBytes"),
                "cgroupScope": "whole-cgroup-including-harness-and-any-other-processes"}


def emit(value):
    print(canonical(value).decode(), flush=True)


class WholeManifest:
    """Capacity evidence over one quiescent owned, read-only input inventory.

    This does not replace MatrixHub's immutable application revision gate.
    It verifies exact inventory closure, one result per descriptor, and a final
    full-byte rehash of every input after all batches have completed.
    """
    def __init__(self, root, manifest_path, raw, entries, bundle):
        if manifest_path != root / "manifest.json":
            raise ValueError("whole manifest requires the input-root manifest")
        self.root, self.raw, self.entries, self.bundle = root, raw, entries, bundle
        self.expected = {entry["artifact"]["artifactId"] for entry in entries}
        if len(self.expected) != len(entries):
            raise ValueError("duplicate whole-manifest descriptor")
        for entry in entries:
            load_scanner().validate_artifact(entry["artifact"], {"max_file_bytes": bundle["maxFileBytes"]})
        self.identities = self.inventory()
        self.metadata_identity = self.identity((self.root / "manifest.json").lstat())
        self.seen, self.errors, self.outcomes = set(), 0, []
        self.digest, self.batches, self.scan_seconds = hashlib.sha256(), 0, 0.0

    @staticmethod
    def identity(info):
        return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns

    def inventory(self):
        allowed_parents = {aid.split("/")[0] for aid in self.expected}
        root_items = {path.name: path for path in self.root.iterdir()}
        if set(root_items) != allowed_parents | {"manifest.json"}:
            raise ValueError("whole-manifest root inventory mismatch")
        if not stat.S_ISREG(root_items["manifest.json"].lstat().st_mode):
            raise ValueError("whole-manifest metadata is not regular")
        result = {}
        for parent in allowed_parents:
            if not stat.S_ISDIR(root_items[parent].lstat().st_mode):
                raise ValueError("whole-manifest parent is not regular directory")
            for path in root_items[parent].iterdir():
                info = path.lstat()
                aid = parent + "/" + path.name
                if aid not in self.expected or not stat.S_ISREG(info.st_mode):
                    raise ValueError("whole-manifest leaf inventory mismatch")
                result[aid] = self.identity(info)
        if set(result) != self.expected:
            raise ValueError("whole-manifest missing leaf")
        return result

    def record(self, group, status, value, elapsed):
        self.batches += 1
        self.scan_seconds += elapsed
        if status != 200 or not load_scanner().valid_worker_result(value, [entry["artifact"] for entry in group], self.bundle, batch=True):
            self.errors += 1
            return
        for entry, item in zip(group, value["results"]):
            aid = entry["artifact"]["artifactId"]
            if aid in self.seen:
                self.errors += 1
            self.seen.add(aid)
            self.outcomes.append(classify(item["analysis"]))
        self.digest.update(canonical(value))

    def finish(self):
        started, final_bytes, verification_error = time.monotonic(), 0, None
        try:
            if self.inventory() != self.identities:
                raise ValueError("whole-manifest snapshot identities changed")
            with (self.root / "manifest.json").open("rb") as metadata:
                if metadata.read((32 << 20) + 1) != self.raw:
                    raise ValueError("whole-manifest metadata changed")
            for entry in self.entries:
                artifact = entry["artifact"]
                with load_scanner().open_verified(self.root, artifact) as data:
                    if self.identity(os.fstat(data.fileno())) != self.identities[artifact["artifactId"]]:
                        raise ValueError("whole-manifest leaf identity changed")
                final_bytes += artifact["size"]
            if self.inventory() != self.identities:
                raise ValueError("whole-manifest final inventory changed")
            if self.identity((self.root / "manifest.json").lstat()) != self.metadata_identity:
                raise ValueError("whole-manifest metadata identity changed")
            with (self.root / "manifest.json").open("rb") as metadata:
                if metadata.read((32 << 20) + 1) != self.raw:
                    raise ValueError("whole-manifest final metadata changed")
        except (OSError, ValueError, load_scanner().Incomplete):
            verification_error = "whole_manifest_final_verification_failed"
        complete = self.errors == 0 and self.seen == self.expected and verification_error is None and all(outcome in {"clean", "block"} for outcome in self.outcomes)
        clean = complete and all(outcome == "clean" for outcome in self.outcomes)
        total = sum(entry["artifact"]["size"] for entry in self.entries)
        return {"event": "wholeManifestReceipt", "manifestSha256": hashlib.sha256(self.raw).hexdigest(),
                "generation": self.bundle["generation"], "expectedFiles": len(self.expected), "observedFiles": len(self.seen),
                "expectedBytes": total, "batches": self.batches, "failedBatches": self.errors,
                "completeCoverage": complete, "clean": clean, "finalFullRehashBytes": final_bytes,
                "finalVerificationError": verification_error, "finalVerificationSeconds": time.monotonic() - started,
                "scanRequestSeconds": self.scan_seconds,
                "scanMibPerSecond": total / (1 << 20) / self.scan_seconds if self.scan_seconds else None,
                "resultSequenceSha256": self.digest.hexdigest(), "applicationApprovalEstablished": False,
                "atomicApplicationVersionGateExercised": False,
                "boundary": "exact-owned-quiescent-readonly-inventory; final full rehash; standalone scanner capacity"}


def phase_run(args, entries, batch_files):
    from unittest import mock
    scanner = load_scanner()
    limits, backend = scanner.limits_from_env(), scanner.backend_from_env()
    with tempfile.TemporaryDirectory() as temporary:
        directory = scanner.engine_directory(str(Path(temporary) / "phase.sock"))
        bundle, evidence = scanner.create_bundle(args.rules, limits, backend, directory)
        engine_class = scanner.ArchivePersistentClamAV if limits.get("native_temp_bytes") else scanner.PersistentClamAV
        engine = engine_class(args.rules, limits, evidence, directory) if backend == "clamd" else None
        state = {"input": str(args.input), "rules": str(args.rules), "bundle": bundle,
                 "evidence": evidence, "limits": limits, "backend": backend, "engine": engine}
        if isinstance(engine, scanner.ArchivePersistentClamAV):
            raise ValueError("phase instrumentation does not support archive scratch ownership")
        try:
            if engine:
                engine.start()
            emit({"event": "phaseConfiguration", "limits": limits, "generation": bundle["generation"],
                  "sourceSha256": evidence["source_sha256"], "engines": bundle["engines"],
                  "harnessSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  "rulesInventorySha256": hashlib.sha256(canonical(evidence["rules"])).hexdigest()})
            for count in batch_files:
                for index, group in enumerate(plans(entries, min(count, bundle["maxBatchFiles"]), bundle["maxBatchBytes"])):
                    with tempfile.TemporaryFile() as metrics:
                        original_popen = scanner.subprocess.Popen
                        def spawn(command, *values, **keywords):
                            if "--worker" in command and str(Path(scanner.__file__).resolve()) in command:
                                command = [sys.executable, "-I", str(Path(__file__).resolve()), "--phase-child",
                                           "--metrics-fd", str(metrics.fileno()), "--input", str(args.input), "--rules", str(args.rules)]
                                keywords["pass_fds"] = (metrics.fileno(),)
                            return original_popen(command, *values, **keywords)
                        started, value, failure = time.monotonic(), None, None
                        try:
                            with mock.patch.object(scanner.subprocess, "Popen", side_effect=spawn):
                                value = scanner.run_worker([entry["artifact"] for entry in group], state, batch=True)
                        except scanner.Incomplete as error:
                            failure = error.args[0] if error.args and error.args[0] in scanner.ERROR_CODES else "scan_incomplete"
                        metrics.seek(0)
                        raw = metrics.read(16385)
                        measurements = json.loads(raw) if raw and len(raw) <= 16384 else None
                        emit({"event": "phaseBatch", "batchFilesRequested": count, "batchIndex": index,
                              "files": len(group), "bytes": sum(entry["artifact"]["size"] for entry in group),
                              "wallSeconds": time.monotonic() - started, "error": failure, "phases": measurements,
                              "summary": summarize(value, group, bundle) if value else expected_rejection({"error": failure}, group, 422)})
        finally:
            if engine:
                engine.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path("/input"))
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--rules", type=Path, default=Path("/rules"))
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--socket")
    mode.add_argument("--phases", action="store_true")
    mode.add_argument("--phase-child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--metrics-fd", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--scanner-pid", type=int)
    parser.add_argument("--batch-files", default="1,2,4,8,32")
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--category", default="all")
    parser.add_argument("--configuration-label", default="unspecified")
    parser.add_argument("--whole-manifest", action="store_true",
                        help="one complete protocol pass plus exact inventory/final full rehash")
    args = parser.parse_args()
    if args.phase_child:
        return phase_child(args)
    if sys.platform != "linux":
        parser.error("actual scanner benchmark requires Linux")
    counts = [int(value) for value in args.batch_files.split(",")]
    if not counts or any(not 1 <= value <= 32 for value in counts) or not 1 <= args.repetitions <= 10:
        parser.error("invalid bounded benchmark plan")
    if args.whole_manifest and (not args.socket or len(counts) != 1 or args.repetitions != 1 or args.category != "all"):
        parser.error("whole manifest requires --socket, one batch count, one repetition and category all")
    manifest_path = args.manifest or args.input / "manifest.json"
    with manifest_path.open("rb") as manifest_file:
        raw = manifest_file.read((32 << 20) + 1)
    if len(raw) > 32 << 20:
        parser.error("manifest limit")
    manifest = json.loads(raw)
    entries = manifest["artifacts"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= 100000:
        parser.error("invalid manifest")
    if args.category != "all":
        entries = [entry for entry in entries if entry["category"] == args.category]
    if not entries:
        parser.error("empty selected dataset")
    emit({"event": "benchmarkInputs", "manifestSha256": hashlib.sha256(raw).hexdigest(),
          "provenance": manifest["provenance"], "files": len(entries),
          "payloadPattern": manifest.get("payloadPattern") if manifest.get("payloadPattern") in {"zero", "shake256-counter"} else "upstream-or-unspecified",
          "payloadSeedVersion": manifest.get("payloadSeedVersion") if manifest.get("payloadSeedVersion") in {"zero-v1", "matrixhub-synthetic-shake256-counter-v1"} else None,
          "bytes": sum(entry["artifact"]["size"] for entry in entries),
          "configurationLabelRequested": args.configuration_label,
          "caveat": "controlled expectations and throughput are not detection accuracy or recall"})
    if args.phases:
        phase_run(args, entries, counts)
        return 0
    status, bundle = call(args.socket, "GET", "/v1/bundle")
    if status != 200:
        emit({"event": "bundleUnavailable", "httpStatus": status})
        return 2
    emit({"event": "protocolConfiguration", "bundle": bundle})
    whole = WholeManifest(args.input, manifest_path, raw, entries, bundle) if args.whole_manifest else None
    for count in counts:
        for repetition in range(args.repetitions):
            for index, group in enumerate(plans(entries, min(count, bundle["maxBatchFiles"]), bundle["maxBatchBytes"])):
                started = time.monotonic()
                with Sampler(args.scanner_pid) as sampler:
                    status, value = call(args.socket, "POST", "/v1/analyze-batch", {"artifacts": [entry["artifact"] for entry in group]}, bundle["generation"])
                elapsed, size = time.monotonic() - started, sum(entry["artifact"]["size"] for entry in group)
                if whole:
                    whole.record(group, status, value, elapsed)
                emit({"event": "protocolBatch", "batchFilesRequested": count, "repetition": repetition,
                      "batchIndex": index, "files": len(group), "bytes": size, "httpStatus": status,
                      "wallSeconds": elapsed, "mibPerSecond": size / (1 << 20) / elapsed,
                      "error": value.get("error") if status != 200 and isinstance(value, dict)
                      and value.get("error") in load_scanner().ERROR_CODES | {"invalid_request", "scanner_busy", "generation_changed", "rules_changed_restart_required"} else None,
                      "summary": summarize(value, group, bundle) if status == 200 else expected_rejection(value, group, status),
                      "resources": sampler.result()})
    if whole:
        receipt = whole.finish()
        emit(receipt)
        return 0 if receipt["clean"] else 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
