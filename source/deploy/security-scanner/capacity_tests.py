#!/usr/bin/env python3
# Copyright The MatrixHub Authors. SPDX-License-Identifier: Apache-2.0
"""Offline real-engine capacity checks. No application accounts are used.

Prepare inert ASCII snapshots on the host using --prepare DIRECTORY, then
mount that directory read-only at /input in the standard hardened scanner
container and invoke this file with --run. Inputs are outside the bounded
/tmp mount, as in production; the scanner's temporary budget is unchanged.
"""
import argparse
import hashlib
import http.client
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time


def prepare(root):
    root.mkdir(parents=True, exist_ok=True)
    if any(root.iterdir()):
        raise RuntimeError("capacity inputs require a new empty directory")
    folder = root / "task-1-1-0000000000000000"
    folder.mkdir()
    artifacts = []
    sizes = [63 << 20] + [1024] * 32 + [64 << 20] * 4 + [1]
    for index, size in enumerate(sizes):
        aid = folder.name + "/" + format(index + 1, "032x") + ".blob"
        unit = ("# INERT_CAPACITY_FIXTURE_" + str(index) + "\n").encode()
        block = (unit * ((128 << 10) // len(unit) + 1))[:128 << 10]
        digest = hashlib.sha256()
        remaining = size
        with (root / aid).open("xb") as out:
            while remaining:
                part = block[:remaining]
                out.write(part)
                digest.update(part)
                remaining -= len(part)
        artifacts.append({"artifactId": aid, "sha256": digest.hexdigest(),
                          "size": size, "type": "opaque;ext=.txt"})
    (root / "manifest.json").write_text(json.dumps(artifacts), encoding="utf-8")
    print(json.dumps({"preparedFiles": len(artifacts), "preparedBytes": sum(sizes)}))


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("scanner", timeout=100)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def run():
    import resource
    artifacts = json.loads(Path("/input/manifest.json").read_text())
    cases = [("single_63MiB", artifacts[:1], 200),
             ("batch_32_unique_1KiB", artifacts[1:33], 200),
             ("batch_33_rejected", artifacts[:33], 400),
             ("batch_exact_256MiB", artifacts[33:37], 200),
             ("batch_256MiB_plus_one_byte_rejected", artifacts[33:38], 400)]
    with tempfile.TemporaryDirectory() as tmp:
        sock = str(Path(tmp) / "scanner.sock")
        with tempfile.TemporaryFile() as logs:
            process = subprocess.Popen([sys.executable, "-I", "/opt/scanner/scanner.py", "--socket", sock],
                                       stdout=logs, stderr=logs)
            def call(method, path, body=None, generation=None):
                connection = UnixConnection(sock)
                headers = {"Content-Type": "application/json"}
                if generation:
                    headers["X-Expected-Generation"] = generation
                connection.request(method, path, body=json.dumps(body) if body is not None else None,
                                   headers=headers)
                response = connection.getresponse()
                value = json.loads(response.read())
                connection.close()
                return response.status, value
            try:
                deadline = time.monotonic() + 30
                while not Path(sock).exists():
                    if process.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError("scanner did not become ready")
                    time.sleep(.05)
                code, bundle = call("GET", "/v1/bundle")
                assert code == 200, bundle
                print("BUNDLE " + json.dumps(bundle), flush=True)
                for name, inputs, expected in cases:
                    start = time.monotonic()
                    code, result = call("POST", "/v1/analyze-batch", {"artifacts": inputs}, bundle["generation"])
                    record = {"case": name, "files": len(inputs), "bytes": sum(a["size"] for a in inputs),
                              "wallSeconds": round(time.monotonic() - start, 4), "httpStatus": code}
                    if code != 200:
                        record["response"] = result
                    print("CAPACITY " + json.dumps(record), flush=True)
                    assert code == expected, result
                    if expected == 200:
                        assert len(result["results"]) == len(inputs), result
                        for artifact, item in zip(inputs, result["results"]):
                            analysis = item["analysis"]
                            assert item["artifactId"] == artifact["artifactId"]
                            assert analysis["complete"] and analysis["generation"] == bundle["generation"]
                            assert analysis["engines"] == bundle["engines"] and not analysis["findings"], item
                    else:
                        assert result == {"error": "invalid_request"}, result
            finally:
                process.terminate()
                process.wait(timeout=5)
                peak = Path("/sys/fs/cgroup/memory.peak")
                print("RESOURCES " + json.dumps({"childMaxRSSKiB": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
                                                "containerMemoryPeakBytes": int(peak.read_text()) if peak.exists() else None}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--prepare", type=Path)
    mode.add_argument("--run", action="store_true")
    args = parser.parse_args()
    prepare(args.prepare) if args.prepare else run()
