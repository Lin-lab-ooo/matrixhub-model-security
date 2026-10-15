#!/usr/bin/env python3
# Copyright The MatrixHub Authors. Licensed under the Apache License, Version 2.0.
"""Compare legacy parser I/O on identical synthetic files, with explicit scope.

layout mode checks only format/constructor semantics with a no-op threat
callback. static mode runs the real StaticInspector/Picklescan on Linux. Neither
mode runs ClamAV, held-FD pre/post SHA checks, HTTP, or download admission; these
timings must never be described as total scanner or product performance.

Example:
  python legacy_io_benchmark.py --baseline /baseline/scanner.py \
    --candidate ./scanner.py --output-dir /evidence/legacy-io \
    --size-mib 1 --size-mib 128 --rounds 3 --mode static

Fixtures are written non-sparsely under output-dir/fixtures and retained for
independent full-scanner tests. Run in a new output directory. No loader executes
the metadata; no framework is imported and no antivirus is mocked.
"""
import argparse
import hashlib
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import platform
import socketserver
import statistics
import sys
import time
import types


class CountingReader:
    """Count logical returned bytes, not device reads or OS cache misses."""
    def __init__(self, stream, ranges):
        self.stream = stream
        self.ranges = [(item["payloadOffset"], item["payloadOffset"] + item["payloadBytes"])
                       for item in ranges]
        self.logical_read_bytes = 0
        self.payload_read_bytes = 0
        self.read_calls = 0
        self.seek_calls = 0

    def _count(self, start, raw):
        self.read_calls += 1
        self.logical_read_bytes += len(raw)
        end = start + len(raw)
        self.payload_read_bytes += sum(max(0, min(end, right) - max(start, left))
                                       for left, right in self.ranges)
        return raw

    def read(self, count=-1):
        start = self.stream.tell()
        return self._count(start, self.stream.read(count))

    def readline(self, count=-1):
        start = self.stream.tell()
        return self._count(start, self.stream.readline(count))

    def seek(self, offset, whence=0):
        self.seek_calls += 1
        return self.stream.seek(offset, whence)

    def tell(self):
        return self.stream.tell()

    def fileno(self):
        return self.stream.fileno()


def file_sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for raw in iter(lambda: stream.read(1 << 20), b""):
            digest.update(raw)
    return digest.hexdigest()


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def normalized_proof(proof):
    result = dict(proof)
    result.pop("storageDigestMode", None)
    result["storageRanges"] = [{key: value for key, value in item.items()
                                if key != "payloadSHA256"}
                               for item in result["storageRanges"]]
    return result


def inspect_once(module, label, path, manifest, mode):
    limits = module.limits_from_env()
    limits["max_file_bytes"] = max(limits["max_file_bytes"], manifest["size"])
    limits["max_scan_bytes"] = max(limits["max_scan_bytes"], manifest["size"])
    callback_count = 0

    def no_threat_check(_data, _index):
        nonlocal callback_count
        callback_count += 1

    with path.open("rb") as stream:
        counted = CountingReader(stream, manifest["storages"])
        start = time.perf_counter_ns()
        if mode == "layout":
            kwargs = {} if label == "baseline" else {"hash_storage_payloads": False}
            proof = module.verify_legacy_torch(counted, no_threat_check, limits, **kwargs)
            findings = None
        else:
            kwargs = {} if label == "baseline" else {"hash_storage_payloads": False}
            inspector = module.StaticInspector(limits, **kwargs)
            inspector.inspect(counted, path.name)
            proof = inspector.verified_legacy_torch
            findings = inspector.findings
        elapsed = time.perf_counter_ns() - start
    if proof is None or not proof["completeByteCoverage"] or not proof["constructorParametersVerified"]:
        raise AssertionError("fixture does not satisfy the bounded legacy profile")
    if label == "baseline":
        if [item["payloadSHA256"] for item in proof["storageRanges"]] != [
                item["payloadSHA256"] for item in manifest["storages"]]:
            raise AssertionError("baseline storage hashes differ from independently generated hashes")
    elif any(item["payloadSHA256"] is not None for item in proof["storageRanges"]):
        raise AssertionError("candidate unexpectedly claims per-storage payload hashes")
    record = {"variant": label, "elapsedNs": elapsed,
              "logicalReadBytes": counted.logical_read_bytes,
              "payloadReadBytes": counted.payload_read_bytes,
              "readCalls": counted.read_calls, "seekCalls": counted.seek_calls,
              "noOpThreatCallbacks": callback_count if mode == "layout" else None,
              "findings": findings,
              "layoutProof": proof}
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--size-mib", action="append", type=int)
    parser.add_argument("--protocol", action="append", type=int, choices=(2, 4))
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--mode", choices=("layout", "static"), default="layout")
    args = parser.parse_args()
    sizes, protocols = args.size_mib or [1, 128], args.protocol or [2, 4]
    if not 1 <= args.rounds <= 21 or any(size < 1 or size > 8192 for size in sizes):
        parser.error("rounds must be 1..21 and each payload size 1..8192 MiB")
    if sum(sizes) * len(protocols) > 8192:
        parser.error("combined synthetic payload is bounded to 8 GiB")
    if args.mode == "static" and os.name != "posix":
        parser.error("static mode requires Linux and the real pinned Picklescan package")
    if args.mode == "layout" and os.name == "nt":
        # Import shim only. Native sandbox/resource/HTTP paths are not exercised.
        sys.modules.setdefault("resource", types.ModuleType("resource"))
        if not hasattr(socketserver, "UnixStreamServer"):
            socketserver.UnixStreamServer = socketserver.TCPServer
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    fixtures = output / "fixtures"
    fixtures.mkdir()
    source_paths = {"baseline": args.baseline.resolve(), "candidate": args.candidate.resolve()}
    sources = {key: file_sha(path) for key, path in source_paths.items()}
    report = {"schemaVersion": 1, "status": "RUNNING", "mode": args.mode,
              "scope": "layout/constructor checks only; threat callback is a no-op" if args.mode == "layout"
              else "real StaticInspector and Picklescan; excludes antivirus and whole-file binding",
              "notMeasured": ["ClamAV", "whole-file SHA pre/post", "worker startup", "HTTP", "download admission"],
              "environment": {"platform": platform.platform(), "python": sys.version,
                              "logicalCpuCount": os.cpu_count(),
                              "perfCounterResolution": time.get_clock_info("perf_counter").resolution},
              "sources": sources, "rounds": args.rounds, "warmupRounds": 1,
              "cachePolicy": "warmup plus alternating A/B and B/A; no OS cache flush or cold-I/O claim",
              "byteCounterScope": "bytes returned by file read/readline; not physical disk bytes",
              "cases": []}
    report_path = output / "benchmark.json"
    try:
        if args.mode == "static":
            report["environment"]["picklescanVersion"] = importlib.metadata.version("picklescan")
        modules = {key: load_module("legacy_benchmark_" + key, path) for key, path in source_paths.items()}
        generator_path = Path(__file__).with_name("legacy_io_fixtures.py")
        generator = load_module("legacy_benchmark_fixtures", generator_path)
        report["fixtureGeneratorSHA256"] = file_sha(generator_path)
        report["harnessSHA256"] = file_sha(__file__)
        for protocol in protocols:
            for mib in sizes:
                path = fixtures / ("synthetic-p%d-%dmib.pt" % (protocol, mib))
                manifest = generator.write_fixture(path, protocol, (mib << 20,))
                case = {"fixture": path.name, "manifest": manifest, "measurements": []}
                report["cases"].append(case)
                if file_sha(path) != manifest["sha256"]:
                    raise AssertionError("generated fixture hash mismatch")
                reference = None
                for round_index in range(args.rounds + 1):
                    order = ("baseline", "candidate") if round_index % 2 == 0 else ("candidate", "baseline")
                    for position, label in enumerate(order):
                        record = inspect_once(modules[label], label, path, manifest, args.mode)
                        identity = (normalized_proof(record["layoutProof"]), record["findings"])
                        if reference is None:
                            reference = identity
                        elif identity != reference:
                            raise AssertionError("baseline/candidate layout proof or threat findings differ")
                        record.update({"round": round_index, "warmup": round_index == 0,
                                       "positionInPair": position})
                        case["measurements"].append(record)
                if file_sha(path) != manifest["sha256"]:
                    raise AssertionError("fixture changed during benchmark")
                medians = {}
                for label in ("baseline", "candidate"):
                    rows = [row for row in case["measurements"] if row["variant"] == label and not row["warmup"]]
                    medians[label] = {key: statistics.median(row[key] for row in rows)
                                      for key in ("elapsedNs", "logicalReadBytes", "payloadReadBytes")}
                case["medians"] = medians
                case["parserElapsedRatioBaselineOverCandidate"] = (
                    medians["baseline"]["elapsedNs"] / medians["candidate"]["elapsedNs"])
                print(json.dumps({"fixture": path.name, "mode": args.mode, "medians": medians}), flush=True)
        if sources != {key: file_sha(path) for key, path in source_paths.items()}:
            raise AssertionError("scanner source changed during benchmark")
        report["status"] = "PASS"
    except Exception as error:
        report["status"] = "FAIL"
        report["failure"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        report_path.write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "report": str(report_path)}), flush=True)


if __name__ == "__main__":
    main()
