#!/usr/bin/env python3
# Copyright The MatrixHub Authors. SPDX-License-Identifier: Apache-2.0
"""Own one fresh offline scanner benchmark; emit bounded public JSONL evidence.

ROOT executes this inside the hardened, network-none container. Protocol and
phase modes are exclusive. Child stderr/raw logs are never copied to evidence.
"""
import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time


def load_benchmark():
    spec = importlib.util.spec_from_file_location("driver_benchmark", Path(__file__).with_name("scale_benchmark.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def identity(pid):
    try:
        fields = (Path("/proc") / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()
        return int(fields[19])
    except (OSError, ValueError, IndexError):
        return None


def descendants(pid):
    pending, found = [pid], {}
    while pending:
        parent = pending.pop()
        try:
            for task in (Path("/proc") / str(parent) / "task").iterdir():
                for child in map(int, (task / "children").read_text().split()):
                    start = identity(child)
                    if child not in found and start is not None:
                        found[child] = start
                        pending.append(child)
        except (OSError, ValueError):
            continue
    return found


def emit(value):
    print(json.dumps(value, sort_keys=True, separators=(",", ":")), flush=True)


def group_absent(pgid):
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return True
    return False


FIELDS = {
    "benchmarkInputs": {"manifestSha256", "provenance", "files", "bytes", "payloadPattern", "payloadSeedVersion", "configurationLabelRequested", "caveat"},
    "protocolConfiguration": {"bundle"},
    "protocolBatch": {"batchFilesRequested", "repetition", "batchIndex", "files", "bytes", "httpStatus", "wallSeconds", "mibPerSecond", "error", "summary", "resources"},
    "phaseConfiguration": {"limits", "generation", "sourceSha256", "engines", "harnessSha256", "rulesInventorySha256"},
    "phaseBatch": {"batchFilesRequested", "batchIndex", "files", "bytes", "wallSeconds", "error", "phases", "summary"},
    "wholeManifestReceipt": {"manifestSha256", "generation", "expectedFiles", "observedFiles", "expectedBytes", "batches", "failedBatches", "completeCoverage", "clean", "finalFullRehashBytes", "finalVerificationError", "finalVerificationSeconds", "scanRequestSeconds", "scanMibPerSecond", "resultSequenceSha256", "applicationApprovalEstablished", "atomicApplicationVersionGateExercised", "boundary"},
    "bundleUnavailable": {"httpStatus"},
}


def parse_records(output, max_bytes):
    output.seek(0)
    raw = output.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError("bounded-output-limit")
    records = []
    for line in raw.splitlines():
        if not line or len(line) > 65536:
            raise ValueError("bounded-jsonl-line")
        record = json.loads(line)
        event = record.get("event") if isinstance(record, dict) else None
        if event not in FIELDS or set(record) - FIELDS[event] - {"event"}:
            raise ValueError("unexpected-benchmark-schema")
        records.append(record)
    return records


def batch_pass(record):
    summary = record.get("summary")
    if not (isinstance(summary, dict) and summary.get("protocolValid") is True
            and summary.get("expectedMatches") == summary.get("expectedKnown") == record.get("files")
            and record.get("files", 0) > 0):
        return False
    if summary.get("expectedRejectionControl") is True:
        return (record.get("httpStatus", 422) == 422 and record.get("error") is not None
                and summary.get("outcomes") == ["incomplete"] * record["files"]
                and summary.get("completeCoverage") is False)
    return record.get("httpStatus", 200) == 200 and record.get("error") is None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path("/input"))
    parser.add_argument("--rules", type=Path, default=Path("/rules"))
    parser.add_argument("--mode", choices=("protocol", "phases"), default="protocol")
    parser.add_argument("--batch-files", default="1,2,4,8,32")
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--category", default="all")
    parser.add_argument("--label", default="unspecified")
    parser.add_argument("--deadline-seconds", type=int, default=1200)
    parser.add_argument("--max-output-bytes", type=int, default=8 << 20)
    parser.add_argument("--whole-manifest", action="store_true")
    args = parser.parse_args()
    if sys.platform != "linux" or not 1 <= args.deadline_seconds <= 14400 or not 1024 <= args.max_output_bytes <= 32 << 20:
        parser.error("invalid fixed Linux execution envelope")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,96}", args.label):
        parser.error("invalid public configuration label")
    if args.mode == "phases" and args.repetitions != 1:
        parser.error("phase diagnostics require one repetition per owned run")
    benchmark = load_benchmark()
    scanner = benchmark.load_scanner()
    limits, backend = scanner.limits_from_env(), scanner.backend_from_env()
    source = Path(__file__).with_name("scanner.py")
    started, cold, server, client, records, failed = time.monotonic(), None, None, None, [], None
    owned, owned_groups, forced, cleanup = {}, set(), [], False
    def census():
        owned.update(descendants(os.getpid()))
        for pid in owned:
            with contextlib.suppress(ProcessLookupError):
                pgid = os.getpgid(pid)
                if pgid != os.getpgrp():
                    owned_groups.add(pgid)
    counts = {"batchAssertionsPassed": 0, "batchAssertionsFailed": 0, "expectedRequestRejectionAssertionsPassed": 0,
              "filesObserved": 0, "bytesObserved": 0}
    source_pin = hashlib.sha256(source.read_bytes()).hexdigest()
    inventory_pin = hashlib.sha256(benchmark.canonical(scanner.rule_inventory(args.rules))).hexdigest()
    emit({"event": "driverInputs", "mode": args.mode, "sourceSha256": source_pin,
          "driverSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
          "benchmarkSha256": hashlib.sha256(Path(benchmark.__file__).read_bytes()).hexdigest(),
          "rulesInventorySha256": inventory_pin, "limits": limits, "backend": backend,
          "configurationLabel": args.label, "applicationApprovalEstablished": False})
    with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryFile() as server_logs, \
         tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        sock = str(Path(temporary) / "scanner.sock")
        try:
            if args.mode == "protocol":
                cold_started = time.monotonic()
                server = subprocess.Popen([sys.executable, "-I", str(source), "--input", str(args.input),
                                           "--rules", str(args.rules), "--socket", sock],
                                          stdin=subprocess.DEVNULL, stdout=server_logs, stderr=server_logs,
                                          start_new_session=True)
                end = min(started + args.deadline_seconds, cold_started + 125)
                while time.monotonic() < end:
                    census()
                    if server.poll() is not None or os.fstat(server_logs.fileno()).st_size > 65536:
                        raise ValueError("scanner-startup-failed")
                    try:
                        status, bundle = benchmark.call(sock, "GET", "/v1/bundle", timeout=2)
                        if status == 200:
                            cold = time.monotonic() - cold_started
                            emit({"event": "driverReady", "coldEngineStartupSeconds": cold,
                                  "coldScope": "new-native-process; operating-system-cache-not-cleared",
                                  "generation": bundle["generation"], "nativeThreads": limits["native_threads"]})
                            break
                    except (OSError, ValueError):
                        pass
                    time.sleep(.025)
                else:
                    raise ValueError("scanner-startup-deadline")
            command = [sys.executable, "-I", str(Path(benchmark.__file__).resolve()), "--input", str(args.input),
                       "--rules", str(args.rules), "--batch-files", args.batch_files, "--repetitions", str(args.repetitions),
                       "--category", args.category, "--configuration-label", args.label]
            command += (["--socket", sock, "--scanner-pid", str(server.pid)] if server else ["--phases"])
            if args.whole_manifest:
                command.append("--whole-manifest")
            client = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output, stderr=errors, start_new_session=True)
            while True:
                census()
                if os.fstat(output.fileno()).st_size > args.max_output_bytes or os.fstat(errors.fileno()).st_size > 65536:
                    raise ValueError("benchmark-output-limit")
                if time.monotonic() - started >= args.deadline_seconds:
                    raise ValueError("benchmark-deadline")
                if client.poll() is not None:
                    break
                time.sleep(.025)
            records = parse_records(output, args.max_output_bytes)
            if client.returncode != 0 or os.fstat(errors.fileno()).st_size:
                failed = "benchmark-child-failed"
            for record in records:
                if record["event"] in {"protocolBatch", "phaseBatch"}:
                    passed = batch_pass(record)
                    counts["batchAssertionsPassed" if passed else "batchAssertionsFailed"] += 1
                    if passed and record["summary"].get("expectedRejectionControl") is True:
                        counts["expectedRequestRejectionAssertionsPassed"] += 1
                    counts["filesObserved"] += record["files"]
                    counts["bytesObserved"] += record["bytes"]
                    if not passed:
                        failed = failed or "batch-assertion-failed"
                emit(record)
            if not counts["batchAssertionsPassed"] or counts["batchAssertionsFailed"]:
                failed = failed or "no-complete-batch-assertions"
            if args.whole_manifest and not any(record["event"] == "wholeManifestReceipt" and record.get("clean") is True for record in records):
                failed = failed or "whole-manifest-not-clean"
        except Exception:
            failed = failed or "driver-or-child-incomplete"
        finally:
            census()
            for process in (client, server):
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                        forced.append("benchmark" if process is client else "scanner")
            remaining = {pid: start for pid, start in owned.items() if identity(pid) == start}
            for pid, start in remaining.items():
                if identity(pid) == start:
                    with contextlib.suppress(ProcessLookupError):
                        os.kill(pid, signal.SIGKILL)
                    forced.append("owned-descendant")
            end = time.monotonic() + 3
            while remaining and time.monotonic() < end:
                with contextlib.suppress(ChildProcessError):
                    while os.waitpid(-1, os.WNOHANG)[0]:
                        pass
                remaining = {pid: start for pid, start in remaining.items() if identity(pid) == start}
                if remaining:
                    time.sleep(.025)
            cleanup = not remaining and not descendants(os.getpid()) and all(group_absent(pgid) for pgid in owned_groups)
            if forced or not cleanup:
                failed = failed or "owned-cleanup-failed"
    emit({"event": "driverReceipt", "passed": failed is None, "failure": failed,
          "wallSeconds": time.monotonic() - started, "coldEngineStartupSeconds": cold,
          "counts": counts, "ownedProcessesObserved": len(owned), "cleanupSuccess": cleanup,
          "ownedProcessGroupsAbsent": all(group_absent(pgid) for pgid in owned_groups),
          "forcedKills": len(forced), "scope": "controlled-fixture-assertions-and-performance; not accuracy or application approval"})
    return 0 if failed is None else 2


if __name__ == "__main__":
    raise SystemExit(main())
