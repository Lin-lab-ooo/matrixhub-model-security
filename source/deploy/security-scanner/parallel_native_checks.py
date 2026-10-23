#!/usr/bin/env python3
# Copyright The MatrixHub Authors. SPDX-License-Identifier: Apache-2.0
"""ROOT-executed Linux native parallel/cancel/crash checks on fresh inert input.

Prepare exactly four 63 MiB synthetic safetensors with scale_fixtures.py.
Mount inputs read-only in the hardened scanner environment. This owns only
the fresh scanner it starts; it never contacts an application or account.
"""
import argparse
import contextlib
import hashlib
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("scanner", timeout=330)
        self.path = path
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def fixed(condition, code):
    if not condition:
        raise RuntimeError(code)


def identity(pid):
    try:
        fields = (Path("/proc") / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()
        return int(fields[19])
    except (OSError, ValueError, IndexError):
        return None


def children(pid):
    result = set()
    try:
        for task in (Path("/proc") / str(pid) / "task").iterdir():
            result.update(int(value) for value in (task / "children").read_text().split())
    except (OSError, ValueError):
        pass
    return result


def socket_count(pid):
    count = 0
    try:
        for fd in (Path("/proc") / str(pid) / "fd").iterdir():
            try:
                count += os.readlink(fd).startswith("socket:[")
            except OSError:
                pass
    except OSError:
        pass
    return count


def group_absent(pid):
    try:
        os.killpg(pid, 0)
    except ProcessLookupError:
        return True
    return False


def emit(event, **values):
    print(json.dumps({"event": event, **values}, sort_keys=True), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path("/input"))
    parser.add_argument("--rules", type=Path, default=Path("/rules"))
    parser.add_argument("--scanner", type=Path, default=Path(__file__).with_name("scanner.py"))
    args = parser.parse_args()
    fixed(sys.platform == "linux", "requires-linux")
    manifest = json.loads((args.input / "manifest.json").read_bytes())
    entries = [entry for entry in manifest["artifacts"] if entry["category"] == "synthetic-capacity"]
    fixed(manifest["provenance"] == "synthetic-inert-no-trained-weights" and len(entries) == 4, "requires-four-owned-synthetic-inputs")
    fixed(all(60 << 20 <= entry["artifact"]["size"] <= 64 << 20 for entry in entries), "requires-60-to-64mib-inputs")
    artifacts = [entry["artifact"] for entry in entries]
    environment = dict(os.environ, SCAN_PROFILE="gb", SCAN_CLAMAV_BACKEND="clamd",
                       SCAN_NATIVE_THREADS="4", SCAN_MAX_BATCH_BYTES=str(5120 << 20), SCAN_RULES_EXPIRES_AT="0")
    with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryFile() as logs:
        path = str(Path(temporary) / "scanner.sock")
        process = subprocess.Popen([sys.executable, "-I", str(args.scanner), "--input", str(args.input),
                                    "--rules", str(args.rules), "--socket", path],
                                   stdout=logs, stderr=logs, env=environment, start_new_session=True)
        ready = None
        workers = set()
        owned_daemons = {}
        def native_pid():
            candidates = []
            for pid in children(process.pid):
                try:
                    is_native = os.path.basename(os.readlink(Path("/proc") / str(pid) / "exe")) == "clamd"
                except OSError:
                    continue
                start = identity(pid)
                if is_native and start is not None:
                    owned_daemons[pid] = start
                    candidates.append(pid)
            fixed(len(candidates) == 1, "owned-native-count-mismatch")
            return candidates[0]
        def call(method, route, body=None, generation=None):
            connection = UnixConnection(path)
            headers = {"Content-Type": "application/json"}
            if generation:
                headers["X-Expected-Generation"] = generation
            try:
                connection.request(method, route, json.dumps(body) if body is not None else None, headers)
                response = connection.getresponse()
                raw = response.read((2 << 20) + 1)
                fixed(len(raw) <= 2 << 20, "response-limit")
                return response.status, json.loads(raw)
            finally:
                connection.close()
        def wait_ready(deadline=125):
            end = time.monotonic() + deadline
            while time.monotonic() < end:
                fixed(process.poll() is None, "owned-scanner-exited")
                try:
                    status, value = call("GET", "/v1/bundle")
                    if status == 200:
                        native_pid()
                        return value
                except (OSError, ValueError, http.client.HTTPException):
                    pass
                time.sleep(.05)
            raise RuntimeError("readiness-deadline")
        def active_native_batch(daemon):
            connection = UnixConnection(path)
            connection.request("POST", "/v1/analyze-batch", json.dumps({"artifacts": artifacts}),
                               {"Content-Type": "application/json", "X-Expected-Generation": bundle["generation"]})
            end = time.monotonic() + 30
            while time.monotonic() < end:
                for pid in children(process.pid) - {daemon}:
                    if socket_count(pid) >= 4:
                        workers.add(pid)
                        return connection, pid, identity(pid)
                time.sleep(.005)
            connection.close()
            raise RuntimeError("four-live-fildes-sockets-not-observed")
        def wait_worker_cleanup(worker, start):
            end = time.monotonic() + 10
            while time.monotonic() < end:
                if identity(worker) != start and group_absent(worker):
                    return
                time.sleep(.025)
            raise RuntimeError("owned-worker-group-not-reaped")
        try:
            bundle = wait_ready()
            logs.seek(0)
            records = logs.read(65536).splitlines()
            ready = next((json.loads(line) for line in records if line.startswith(b'{"event": "scanner_ready"')), None)
            fixed(ready is not None and ready["nativeThreads"] == 4, "native-thread-ready-mismatch")
            daemon = ready["daemonPid"]
            fixed(daemon == native_pid(), "native-owner-mismatch")
            emit("configuration", sourceSha256=hashlib.sha256(args.scanner.read_bytes()).hexdigest(),
                 generation=bundle["generation"], nativeThreads=4, files=4,
                 bytes=sum(artifact["size"] for artifact in artifacts))
            status, value = call("POST", "/v1/analyze-batch", {"artifacts": artifacts}, bundle["generation"])
            fixed(status == 200 and len(value.get("results", [])) == 4, "clean-batch-protocol")
            for artifact, result in zip(artifacts, value["results"]):
                analysis = result["analysis"]
                fixed(result["artifactId"] == artifact["artifactId"] and analysis["complete"] is True
                      and analysis["generation"] == bundle["generation"] and analysis["engines"] == bundle["engines"]
                      and not analysis["findings"], "clean-batch-incomplete")
            emit("clean-batch", passed=True)
            connection, worker, start = active_native_batch(daemon)
            connection.sock.shutdown(socket.SHUT_RDWR)
            connection.close()
            wait_worker_cleanup(worker, start)
            recovered = wait_ready()
            fixed(recovered["generation"] == bundle["generation"], "cancel-recovery-generation")
            emit("cancel-four-live-sockets", passed=True, workerGroupAbsent=True)
            # Identify only the newly owned native executable; never read its
            # command line, environment, memory or any credential material.
            daemon = native_pid()
            daemon_start = identity(daemon)
            fixed(daemon_start is not None, "recovered-native-identity-missing")
            connection, worker, start = active_native_batch(daemon)
            fixed(identity(daemon) == daemon_start, "native-identity-changed")
            os.kill(daemon, signal.SIGKILL)
            try:
                response = connection.getresponse()
                value = json.loads(response.read(65536))
                fixed(response.status == 422 and "results" not in value and "error" in value, "native-crash-did-not-fail-closed")
            finally:
                connection.close()
            wait_worker_cleanup(worker, start)
            recovered = wait_ready()
            fixed(recovered["generation"] == bundle["generation"], "crash-recovery-generation")
            status, value = call("POST", "/v1/analyze-batch", {"artifacts": artifacts[:1]}, bundle["generation"])
            fixed(status == 200 and len(value.get("results", [])) == 1, "post-crash-protocol-failed")
            result, analysis = value["results"][0], value["results"][0]["analysis"]
            fixed(result["artifactId"] == artifacts[0]["artifactId"] and analysis["complete"] is True
                  and analysis["generation"] == bundle["generation"] and analysis["engines"] == bundle["engines"]
                  and not analysis["findings"], "post-crash-full-scan-failed")
            emit("native-crash-and-fresh-full-scan", passed=True, workerGroupAbsent=True)
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                raise RuntimeError("scanner-graceful-cleanup-failed")
            fixed(all(group_absent(worker) for worker in workers), "worker-remained-after-shutdown")
            fixed(all(group_absent(daemon) for daemon in owned_daemons), "native-remained-after-shutdown")
            emit("owned-cleanup", scannerExited=True, workerGroupsAbsent=True, nativeGroupsAbsent=True,
                 nativeGenerationsObserved=len(owned_daemons))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
