#!/usr/bin/env python3
# Copyright The MatrixHub Authors. Licensed under the Apache License, Version 2.0.
"""Actual ClamAV + Picklescan protocol comparison; no artifact is executed.

Run in the isolated scanner Linux image with read-only /input, /baseline and
/rules mounts. Large inputs are prepared separately on the host. Small safety
fixtures use private /tmp, like integration_tests.py, never a live repository.
This measures scanner requests, not MatrixHub upload/download admission.
"""
import argparse
import ast
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import time


def load_fixtures():
    spec = importlib.util.spec_from_file_location("fixtures", Path(__file__).with_name("legacy_io_fixtures.py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class UnixConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.host)


def request(path, method, endpoint, data=None, generation=None):
    connection = UnixConnection(str(path), timeout=330)
    try:
        headers = {"Content-Type": "application/json"}
        if generation:
            headers["X-Expected-Generation"] = generation
        connection.request(method, endpoint, None if data is None else json.dumps(data), headers)
        response = connection.getresponse()
        raw = response.read(2 << 20)
        return response.status, json.loads(raw)
    finally:
        connection.close()


class Server:
    def __init__(self, source, inputs, rules="/rules"):
        self.source, self.inputs, self.rules = str(source), str(inputs), str(rules)

    def __enter__(self):
        self.temp = tempfile.TemporaryDirectory(prefix="legacy-io-server-")
        self.socket = Path(self.temp.name) / "scanner.sock"
        self.log = tempfile.TemporaryFile()
        environment = dict(os.environ, SCAN_PROFILE="gb", SCAN_CLAMAV_BACKEND="clamd")
        self.process = subprocess.Popen([sys.executable, "-I", "-B", self.source,
                "--input", self.inputs, "--rules", self.rules, "--socket", str(self.socket)],
                env=environment, stdout=self.log, stderr=self.log)
        try:
            deadline = time.monotonic() + 140
            while not self.socket.exists():
                if self.process.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("scanner_startup_failed")
                time.sleep(0.1)
            status, self.bundle = request(self.socket, "GET", "/v1/bundle")
            if status != 200:
                raise RuntimeError("scanner_bundle_unavailable")
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_):
        if self.process.poll() is None:
            self.process.terminate()
        try:
            self.process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
            raise RuntimeError("scanner_shutdown_timeout")
        self.log.close()
        self.temp.cleanup()

    def analyze(self, descriptor):
        started = time.perf_counter()
        status, result = request(self.socket, "POST", "/v1/analyze", descriptor,
                                 self.bundle["generation"])
        elapsed = time.perf_counter() - started
        if status != 200:
            raise RuntimeError("analysis_http_" + str(status) + ":" + str(result.get("error", "unknown")))
        return result, elapsed


def descriptor(root, index, raw):
    artifact_id = "task-1-1-" + "a"*16 + "/" + format(index, "032x") + ".blob"
    target = root / artifact_id
    target.parent.mkdir(exist_ok=True)
    target.write_bytes(raw)
    return {"artifactId": artifact_id, "sha256": hashlib.sha256(raw).hexdigest(),
            "size": len(raw), "type": "pickle;ext=.bin"}


def normalize(result):
    return {key: value for key, value in result.items() if key not in ("generation", "durationMs")}


def correctness(sources):
    fixtures = load_fixtures()
    with tempfile.TemporaryDirectory(prefix="legacy-io-safety-") as directory:
        root = Path(directory)
        tree = ast.parse(Path(__file__).with_name("integration_tests.py").read_text())
        manifest = next(ast.literal_eval(node.value) for node in tree.body
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and
                t.id == "EMBEDDED_LEGACY_MANIFEST" for t in node.targets))
        entries = [(case["id"], bytes.fromhex(case["payloadHex"]), "clean") for case in manifest["cases"]]
        path = root / "benign.bin"
        info = fixtures.write_fixture(path, storage_sizes=(8192,))
        raw = path.read_bytes()
        entries.extend([("synthetic-byte-storage", raw, "clean"),
                        ("truncated-storage", raw[:-1], "incomplete"),
                        ("dangerous-metadata-reference", raw.replace(
                            b"ctorch._utils\n_rebuild_tensor_v2\n", b"cos\nsystem\n", 1), "risk")])
        # Harmless standard antivirus test bytes, constructed only inside Linux.
        eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        offset = info["storages"][0]["payloadOffset"] + 1024
        infected_test = raw[:offset] + eicar + raw[offset+len(eicar):]
        entries.append(("eicar-inside-numeric-storage", infected_test, "observation"))
        entries.append(("standalone-eicar", eicar, "antivirus"))
        descriptors = [descriptor(root, index+1, content) for index, (_, content, _) in enumerate(entries)]
        descriptors[-1]["type"] = "opaque;ext=.txt"
        results = {}
        for name, source in sources.items():
            with Server(source, root) as server:
                rows = []
                for (case_id, _, expected), item in zip(entries, descriptors):
                    result, elapsed = server.analyze(item)
                    findings = result["findings"]
                    print(json.dumps({"event": "safety_case", "variant": name,
                        "case": case_id, "actual": result}), flush=True)
                    valid = ((expected == "clean" and result["complete"] and not findings)
                        or (expected == "incomplete" and not result["complete"] and
                            any(f["rule"].startswith("coverage.") for f in findings))
                        or (expected == "risk" and not result["complete"] and
                            any(f["rule"] == "pickle.dangerous-global" for f in findings))
                        or (expected == "antivirus" and result["complete"] and
                            any(f["engine"] == "clamav" for f in findings))
                        or expected == "observation")
                    if not valid:
                        raise AssertionError("incorrect_outcome:" + name + ":" + case_id)
                    rows.append({"case": case_id, "expected": expected, "actual": result,
                                 "seconds": elapsed, "sha256": item["sha256"]})
                status, batch = request(server.socket, "POST", "/v1/analyze-batch",
                                        {"artifacts": descriptors}, server.bundle["generation"])
                if status != 200 or len(batch["results"]) != len(rows):
                    raise AssertionError("batch_protocol_failed")
                for row, item, entry in zip(rows, descriptors, batch["results"]):
                    if entry["artifactId"] != item["artifactId"] or normalize(entry["analysis"]) != normalize(row["actual"]):
                        raise AssertionError("single_batch_mismatch")
                results[name] = {"bundle": server.bundle, "cases": rows, "batchEquivalent": True}
        if [normalize(row["actual"]) for row in results["baseline"]["cases"]] != [normalize(row["actual"]) for row in results["candidate"]["cases"]]:
            raise AssertionError("baseline_candidate_result_mismatch")
        # An independent test-only signature checks native inspection at two
        # payload locations. It is not an addition to production malware rules.
        test_rules = root / "test-rules"
        test_rules.mkdir()
        for source in Path("/rules").iterdir():
            shutil.copyfile(source, test_rules/source.name)
        marker = b"MatrixHub-Only-A-Harmless-Numeric-Storage-Coverage-Fixture-v122"
        signature = "MatrixHub.NumericStorageCoverageTest:0:*:" + marker.hex() + "\n"
        (test_rules/"storage-coverage.ndb").write_text(signature)
        probe_path = root / "coverage.bin"
        probe_info = fixtures.write_fixture(probe_path, storage_sizes=(256 << 10,))
        probe = probe_path.read_bytes()
        payload = probe_info["storages"][0]["payloadOffset"]
        offsets = [payload + (128 << 10) + 7, len(probe)-len(marker)]
        probes = [("no-marker", probe)] + [("marker-"+str(offset),
            probe[:offset]+marker+probe[offset+len(marker):]) for offset in offsets]
        probe_descriptors = [descriptor(root, 100+index, content) for index, (_, content) in enumerate(probes)]
        coverage = {"scope": "test-only NDB marker at two offsets; not general malware detection efficacy",
                    "signatureSHA256": hashlib.sha256(signature.encode()).hexdigest(), "variants": {}}
        for name, source in sources.items():
            with Server(source, root, test_rules) as server:
                rows = []
                for (case_id, _), item in zip(probes, probe_descriptors):
                    result, _ = server.analyze(item)
                    matched = any(f["rule"] == "clamav.MatrixHub.NumericStorageCoverageTest.UNOFFICIAL"
                                  for f in result["findings"])
                    if not result["complete"] or matched != (case_id != "no-marker"):
                        raise AssertionError("native_payload_marker_mismatch:"+name+":"+case_id)
                    if case_id == "no-marker" and result["findings"]:
                        raise AssertionError("marker_negative_not_clean")
                    rows.append({"case": case_id, "actual": result})
                coverage["variants"][name] = {"bundle": server.bundle, "cases": rows}
        results["nativePayloadCoverage"] = coverage
        return results


def performance(sources, inputs, rounds):
    data = json.loads((inputs / "manifest.json").read_text())
    rows = []
    for item in data["cases"]:
        count = 1 if item["payloadBytes"] >= (1 << 30) else rounds
        for trial in range(count):
            order = ("baseline", "candidate") if trial % 2 == 0 else ("candidate", "baseline")
            for name in order:
                with Server(sources[name], inputs) as server:
                    # Warm the same artifact in each variant, outside the timed
                    # request. Neither daemon startup nor warmup is included.
                    warmup, _ = server.analyze(data["warmup"])
                    if not warmup["complete"] or warmup["findings"]:
                        raise AssertionError("warmup_not_clean")
                    large_warmup, warmup_elapsed = server.analyze(item["descriptor"])
                    if not large_warmup["complete"] or large_warmup["findings"]:
                        raise AssertionError("large_warmup_not_clean")
                    result, elapsed = server.analyze(item["descriptor"])
                    if not result["complete"] or result["findings"]:
                        raise AssertionError("performance_fixture_not_clean")
                    row = {"case": item["id"], "variant": name, "trial": trial,
                           "order": list(order), "requestSeconds": elapsed,
                           "sameArtifactWarmupSeconds": warmup_elapsed,
                           "workerDurationMs": result["durationMs"],
                           "generation": result["generation"], "size": item["descriptor"]["size"],
                           "sha256": item["descriptor"]["sha256"]}
                    rows.append(row)
                    print(json.dumps({"event": "trial_complete", **row}), flush=True)
    return {"trials": rows, "summary": [{"case": item["id"], "variant": name,
                "samples": len(selected), "medianRequestSeconds": statistics.median(selected)}
            for item in data["cases"] for name in sources
            for selected in [[row["requestSeconds"] for row in rows if row["case"] == item["id"] and row["variant"] == name]]],
            "scope": "scanner Unix API only; startup and identical large-artifact warmup excluded; alternating order; OS cache uncontrolled; 1GiB single ordered pair; no admission, cold-cache or percentile claim"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", type=Path, default=Path("/input"))
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--mode", choices=("correctness", "performance", "all"), default="all")
    args = parser.parse_args()
    if not 1 <= args.rounds <= 5:
        parser.error("rounds must be 1..5")
    sources = {"baseline": Path("/baseline/scanner.py"), "candidate": Path(__file__).with_name("scanner.py")}
    result = {"status": "RUNNING", "sourceSHA256": {key: hashlib.sha256(path.read_bytes()).hexdigest() for key, path in sources.items()},
              "python": sys.version, "startedUnix": time.time()}
    try:
        if args.mode != "performance":
            result["correctness"] = correctness(sources)
        if args.mode != "correctness":
            result["performance"] = performance(sources, args.inputs, args.rounds)
        result["status"] = "PASS"
    except Exception as error:
        result["status"] = "FAIL"
        result["failure"] = {"type": type(error).__name__, "detail": str(error)[:240]}
        raise
    finally:
        result["finishedUnix"] = time.time()
        print("RESULT " + json.dumps(result, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
