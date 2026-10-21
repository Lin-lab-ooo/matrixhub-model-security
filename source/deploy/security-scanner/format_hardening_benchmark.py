#!/usr/bin/env python3
# Copyright The MatrixHub Authors. Licensed under the Apache License, Version 2.0.
"""Compare inert repeated-reference parsing with real pinned Picklescan.

This is a static-parser microbenchmark. It excludes AV, snapshot hashes, HTTP,
uploads and downloads. A result must never be reported as full scan throughput.
Only known literal opcode bytes are inspected; nothing is unpickled or loaded.
"""
import argparse
import hashlib
import importlib.metadata
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import socketserver
import statistics
import sys
import time
import types


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def measure(scanner, content):
    inspector = scanner.StaticInspector(scanner.limits_from_env())
    started = time.perf_counter()
    inspector.inspect(io.BytesIO(content), "repeated-ordered-dict.pkl")
    seconds = time.perf_counter() - started
    return seconds, {"findings": inspector.findings, "opcodes": inspector.opcodes,
                     "pickleFiles": inspector.pickle_files}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--references", type=int, default=20000)
    parser.add_argument("--rounds", type=int, default=5)
    args = parser.parse_args()
    if not 1 <= args.references <= 100000 or not 1 <= args.rounds <= 15:
        parser.error("bounded references/rounds required")
    if importlib.metadata.version("picklescan") != "1.0.5":
        parser.error("pinned Picklescan 1.0.5 required")
    if os.name == "nt":
        sys.modules.setdefault("resource", types.ModuleType("resource"))
        if not hasattr(socketserver, "UnixStreamServer"):
            socketserver.UnixStreamServer = socketserver.TCPServer
    paths = {"baseline": args.baseline.resolve(), "candidate": args.candidate.resolve()}
    before = {key: digest(path) for key, path in paths.items()}
    scanners = {key: load("benchmark_" + key, path) for key, path in paths.items()}
    content = b"ccollections\nOrderedDict\n0" * args.references + b"N."
    # Both variants perform an untimed warmup on the identical bytes.
    expected = None
    for scanner in scanners.values():
        _, result = measure(scanner, content)
        if expected is None:
            expected = result
        elif result != expected:
            raise RuntimeError("baseline_candidate_semantics_differ")
    samples = {key: [] for key in paths}
    order = []
    for index in range(args.rounds):
        pair = ("baseline", "candidate") if index % 2 == 0 else ("candidate", "baseline")
        order.append(list(pair))
        for key in pair:
            seconds, result = measure(scanners[key], content)
            if result != expected:
                raise RuntimeError("measurement_semantics_differ")
            samples[key].append(seconds)
    after = {key: digest(path) for key, path in paths.items()}
    if before != after:
        raise RuntimeError("source_changed_during_measurement")
    medians = {key: statistics.median(value) for key, value in samples.items()}
    print(json.dumps({"status": "PASS", "scope": "static_parser_only_no_antivirus_or_application",
        "python": platform.python_version(), "platform": platform.platform(),
        "picklescan": "1.0.5", "sourceSHA256": before,
        "inputSHA256": hashlib.sha256(content).hexdigest(), "inputBytes": len(content),
        "references": args.references, "rounds": args.rounds, "order": order,
        "warmupExcluded": True, "samplesSeconds": samples, "medianSeconds": medians,
        "medianReductionPercent": 100 * (1 - medians["candidate"] / medians["baseline"]),
        "semantics": expected, "sourceUnchanged": True}, indent=2))


if __name__ == "__main__":
    main()
