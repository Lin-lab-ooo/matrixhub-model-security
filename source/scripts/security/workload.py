#!/usr/bin/env python3
# Copyright The MatrixHub Authors. SPDX-License-Identifier: Apache-2.0
"""Measure the real application; no model deserialization or synthetic verdicts.

Install huggingface_hub from the recorded client lock, set
MATRIXHUB_E2E_PASSWORD, then run with --mode benchmark or --mode soak.
Use an isolated deployment: each run creates its own private model repository.
Byte budgets deliberately remain below the default 2 GiB retained snapshot cap.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import ctypes
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import statistics
import threading
import time

from e2e import Actor, STATES, TERMINAL, check, file_hash, run_utf8_command, utc_now


def fixture_bytes(size, seed):
    # ASCII data has no callable serialization opcodes or executable content.
    unit = ("# MATRIXHUB_STATIC_CAPACITY_FIXTURE_" + seed + "\n").encode()
    return (unit * (size // len(unit) + 1))[:size]


def percentile(values, fraction):
    ordered = sorted(values)
    check(bool(ordered) and 0 < fraction <= 1, "percentile requires nonempty samples and a valid fraction")
    return ordered[min(len(ordered) - 1, math.ceil(len(ordered) * fraction) - 1)]


class Workload:
    script_source = Path(__file__)

    def __init__(self, args):
        from huggingface_hub import HfApi
        self.args = args
        self.root = args.output_dir.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        check(not (self.root / "events.jsonl").exists() and not (self.root / "results.json").exists(),
              "use a new output directory for every execution")
        self.run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(3)
        self.actor = Actor(args.base_url.rstrip("/"), args.username, os.environ.get(args.password_env, ""))
        check(bool(self.actor.password), "credential environment is required")
        self.actor.login(self.run_id)
        self.token_started = time.monotonic()
        self.hf = HfApi(endpoint=self.actor.base, token=self.actor.token)
        self.project = "security-workload-" + self.run_id
        self.actor.json("/api/v1alpha1/projects", "POST", {"name": self.project, "type": "PROJECT_TYPE_PRIVATE"})
        self.started = time.monotonic()
        self.failures = 0
        self.summary = {"schema": 1, "startedAt": utc_now(), "mode": args.mode,
                        "baseURL": self.actor.base, "project": self.project,
                        "scriptSha256": file_hash(self.script_source), "cases": [],
                        "sourceScriptsSha256": {name: file_hash(Path(__file__).with_name(name))
                                               for name in {"e2e.py", "workload.py", self.script_source.name}},
                        "safety": "Only inert ASCII fixtures. No model was loaded or executed.",
                        "measurement": "Wall clocks include real HTTP, queue, staging and engine work; shared batch member durations are not summed.",
                        "resourceMeasurement": "Docker stats are a single sample after each case/iteration, not a case peak or continuous trace.",
                        "rangeLatencyNote": "Eight requests per case; nearest-rank p95 equals the sample maximum and does not estimate a production SLO."}
        if args.deployment_evidence:
            self.summary["deployment"] = json.loads(args.deployment_evidence.read_text(encoding="utf-8-sig"))
        (self.root / "script-snapshot.py").write_bytes(self.script_source.read_bytes())
        self.save()

    def event(self, kind, **fields):
        record = {"at": utc_now(), "elapsedSeconds": round(time.monotonic() - self.started, 3),
                  "kind": kind, **fields}
        with (self.root / "events.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        print(json.dumps(record, ensure_ascii=False), flush=True)
        return record

    def save(self):
        (self.root / "results.json").write_text(json.dumps(self.summary, indent=2), encoding="utf-8")

    def redact(self, error):
        text = str(error)
        for secret in (self.actor.token, self.actor.password):
            if secret:
                text = text.replace(secret, "[REDACTED]")
        return re.sub(r"(?i)(Bearer|Basic)\s+[^\s\"']+", r"\1 [REDACTED]", text)[:2048]

    def security_path(self, repo, suffix, revision=None):
        path = "/api/security/v1alpha1/models/" + repo + "/" + suffix
        return path + ("?revision=" + revision if revision else "")

    def renew(self):
        if time.monotonic() - self.token_started < 2400:
            return
        self.actor.revoke()
        self.actor.login(self.run_id + "-" + str(int(time.monotonic() - self.started)))
        self.hf.token = self.actor.token
        self.token_started = time.monotonic()
        self.event("credential-renewed", tokenLogged=False)

    def wait(self, repo, sha, allow_scanner_startup=False, expected_generation=None):
        began = time.monotonic()
        deadline = began + self.args.scan_timeout
        transitions = []
        while time.monotonic() < deadline:
            # Only rule/container startup may retry a transport outage or the
            # service's explicit unavailable sentinel. A persisted task failure
            # remains terminal; it cannot be hidden by this retry path.
            try:
                response = self.actor.request(self.security_path(repo, "report", sha),
                                              timeout=max(.1, min(15, deadline - time.monotonic())))
            except OSError as error:
                if not allow_scanner_startup:
                    raise
                state = "startup-transport-unavailable"
                if not transitions or transitions[-1]["state"] != state:
                    transitions.append({"state": state, "errorType": type(error).__name__, "seconds": round(time.monotonic() - began, 3)})
                time.sleep(min(.5, max(0, deadline - time.monotonic())))
                continue
            if allow_scanner_startup and response["status"] in (500, 502, 503, 504):
                state = "startup-http-" + str(response["status"])
                if not transitions or transitions[-1]["state"] != state:
                    transitions.append({"state": state, "seconds": round(time.monotonic() - began, 3)})
                time.sleep(min(.5, max(0, deadline - time.monotonic())))
                continue
            check(response["status"] == 200, "report HTTP status was " + str(response["status"]))
            report = json.loads(response["body"])
            state = report.get("state")
            check(state in STATES, "unrecognized report state")
            check(report.get("repo") == repo and report.get("revision") == sha, "report scope or revision changed")
            if not transitions or transitions[-1]["state"] != state:
                transitions.append({"state": state, "seconds": round(time.monotonic() - began, 3)})
            if allow_scanner_startup and state == "fail" and not report.get("complete") and report.get("error") == "Required scanner unavailable" and not report.get("taskId"):
                time.sleep(min(.5, max(0, deadline - time.monotonic())))
                continue
            if state in TERMINAL:
                check(expected_generation is None or report.get("generation") == expected_generation,
                      "terminal report used a different scanner generation")
                return report, round(time.monotonic() - began, 3), transitions
            time.sleep(min(.5, max(0, deadline - time.monotonic())))
        raise AssertionError("real application scan exceeded the declared wait budget")

    def verify(self, report, files):
        check(report["state"] == "pass" and report["complete"], "inert fixture did not receive complete pass")
        entries = {item["path"]: item for item in report["files"]}
        check(len(entries) == len(report["files"]) == report["expectedFiles"], "report file coverage has missing or duplicate paths")
        for item in entries.values():
            check(item["complete"] and item["generation"] == report["generation"], "file coverage or generation mismatch")
            check(bool(item["engines"].get("clamav")) and bool(item["engines"].get("picklescan")), "required engines absent")
        for name, data in files.items():
            item = entries[name]
            check(item["sha256"] == hashlib.sha256(data).hexdigest(), "scan digest differs from uploaded bytes")
            check(item["size"] == len(data), "scan size differs from uploaded bytes")

    def upload(self, repo, files):
        from huggingface_hub import CommitOperationAdd
        start = time.perf_counter()
        info = self.hf.create_commit(repo_id=repo,
                                    operations=[CommitOperationAdd(path_in_repo=name, path_or_fileobj=data)
                                                for name, data in files.items()],
                                    commit_message="Inert capacity/stability fixtures " + self.run_id)
        check(re.fullmatch("[a-f0-9]{40}", info.oid), "official upload did not return an immutable commit")
        return info.oid, round((time.perf_counter() - start) * 1000, 3)

    def reads(self, repo, sha, files, rounds=8):
        name = sorted(files)[0]
        data = files[name]
        url = "/" + repo + "/resolve/" + sha + "/" + name
        measurements = []

        def read(index):
            # Separate request openers avoid sharing cookie state across threads;
            # the same server-issued bearer identity is rechecked on every open.
            client = Actor(self.actor.base, self.actor.username, "")
            client.token = self.actor.token
            response = client.request(url, headers={"Range": "bytes=0-127"})
            check(response["status"] == 206, "approved range response was not 206")
            check(response["body"] == data[:128], "range response differs from scanned bytes")
            check(response["headers"].get("X-Repo-Commit") == sha, "range response lost commit binding")
            return response["elapsedMs"]

        with ThreadPoolExecutor(max_workers=4) as pool:
            measurements.extend(pool.map(read, range(rounds)))
        head = self.actor.request(url, "HEAD")
        check(head["status"] == 200 and not head["body"], "HEAD violated body/status contract")
        response = self.actor.request(url)
        check(response["status"] == 200, "approved GET denied")
        check(hashlib.sha256(response["body"]).digest() == hashlib.sha256(data).digest(), "download returned unscanned bytes")
        return {"rangeRequests": rounds, "totalRequests": rounds + 2, "parallelism": 4, "rangeMs": measurements,
                "percentileMethod": "nearest-rank ceil(q*n)",
                "percentileSampleCount": len(measurements),
                "rangeP95IsSampleMaximum": len(measurements) <= 19,
                "rangeMedianMs": statistics.median(measurements), "rangeP95Ms": percentile(measurements, .95),
                "headMs": head["elapsedMs"], "getMs": response["elapsedMs"], "getBytes": len(response["body"])}

    def resources(self):
        if not self.args.docker_observe:
            return None
        result = run_utf8_command(["docker", "stats", "--no-stream", "--format", "{{json .}}",
                                  self.args.docker_project + "-matrixhub-1", self.args.docker_project + "-scanner-1"], timeout=20)
        check(result.returncode == 0, "Docker resource observation failed")
        return {"observedAt": utc_now(), "method": "single docker stats --no-stream sample after case/iteration; not a peak",
                "containers": [json.loads(line) for line in result.stdout.splitlines() if line.strip()]}

    def one_benchmark(self, count, size):
        repo = self.project + f"/files-{count}-bytes-{size}"
        self.hf.create_repo(repo_id=repo, private=True)
        files = {f"fixture-{i:03d}.txt": fixture_bytes(size, self.run_id + "-" + str(i)) for i in range(count)}
        sha, upload_ms = self.upload(repo, files)
        report, scan_s, transitions = self.wait(repo, sha)
        self.verify(report, files)
        check(report["cachedFiles"] == 0, "cold upload unexpectedly reused a scan analysis")
        result = {"repo": repo, "revision": sha, "files": count, "fileBytes": size, "totalBytes": sum(map(len, files.values())),
                  "uploadMs": upload_ms, "coldWaitSeconds": scan_s, "reportDurationMs": report["durationMs"],
                  "uploadToApprovalSeconds": round(upload_ms / 1000 + scan_s, 3),
                  "expectedFiles": report["expectedFiles"], "scannedBytes": report["scannedBytes"],
                  "reportId": report["reportId"], "generation": report["generation"], "transitions": transitions,
                  "cachedFiles": report["cachedFiles"], "reads": self.reads(repo, sha, files)}
        # A fresh commit changes one small marker. Reuse is measured in the real
        # revision pipeline, while all original artifact bytes remain fixed.
        marker = {"cache-marker.txt": fixture_bytes(128, self.run_id + "-cache")}
        cached_sha, marker_ms = self.upload(repo, marker)
        cached, cached_s, cached_states = self.wait(repo, cached_sha)
        self.verify(cached, {**files, **marker})
        check(cached["cachedFiles"] >= count, "unchanged original artifacts were not reused")
        result["cacheCommit"] = {"revision": cached_sha, "uploadMs": marker_ms, "waitSeconds": cached_s,
                                 "cachedFiles": cached["cachedFiles"], "transitions": cached_states}
        task = self.actor.json(self.security_path(repo, "rescan"), "POST", {"revision": cached_sha}, (202,))
        denial = self.actor.request("/" + repo + "/resolve/" + cached_sha + "/" + sorted(files)[0], "HEAD")
        check(denial["status"] in (403, 503) and not denial["headers"].get("Location"), "forced rescan admitted a pending artifact")
        forced, forced_s, forced_states = self.wait(repo, cached_sha)
        self.verify(forced, {**files, **marker})
        check(forced["cachedFiles"] == 0, "force scan reused cached analyses")
        result["forcedRescan"] = {"taskId": task["id"], "waitSeconds": forced_s,
                                  "reportId": forced["reportId"], "transitions": forced_states,
                                  "pendingHeadStatus": denial["status"], "cachedFiles": forced["cachedFiles"]}
        result["resourceObservation"] = self.resources()
        return result

    def benchmark(self):
        # 32 files is one full batch; 33 explicitly crosses the batch boundary.
        cases = [(8, 1024), (32, 1024), (33, 1024), (8, 1 << 20), (4, 8 << 20), (1, 63 << 20)]
        self.summary["declaredBudget"] = {"cases": len(cases), "maximumFileBytes": 63 << 20,
                                          "maximumFilesPerRevision": 34,
                                          "snapshotBytesUpperBound": sum(3 * count * size + 2 * 128 for count, size in cases),
                                          "note": "Conservative sum of cold, cache-commit and forced-revision bytes; cache reuse may lower retained staging."}
        for count, size in cases:
            self.renew()
            start = time.monotonic()
            try:
                value = self.one_benchmark(count, size)
                value["status"] = "pass"
                self.event("benchmark-pass", files=count, fileBytes=size, durationSeconds=round(time.monotonic()-start, 3))
            except Exception as error:
                self.failures += 1
                value = {"files": count, "fileBytes": size, "status": "fail", "errorType": type(error).__name__, "reason": self.redact(error)}
                self.event("benchmark-fail", **value)
            self.summary["cases"].append(value)
            self.save()

    def note_soak_time(self, kind):
        now = time.monotonic()
        continuity = self.summary["soakContinuity"]
        if kind == "round-start":
            gap = now - getattr(self, "_soak_last_round_start", self.started)
            self._soak_last_round_start = now
            key = "maxRoundStartGapSeconds"
        else:
            gap = now - self._soak_last_observation
            key = "maxSuccessfulObservationGapSeconds"
            if kind == "success":
                self._soak_last_observation = now
                if not hasattr(self, "_soak_first_observation"):
                    self._soak_first_observation = now
                    continuity["firstSuccessfulObservationAt"] = utc_now()
                continuity["lastSuccessfulObservationAt"] = utc_now()
                continuity["successfulObservations"] += 1
            else:
                continuity["finalObservationGapSeconds"] = round(gap, 3)
                continuity["monitoringElapsedSeconds"] = round(now - self.started, 3)
        continuity[key] = max(continuity.get(key, 0), round(gap, 3))
        continuity["observedDurationSeconds"] = round(self._soak_last_observation - getattr(self, "_soak_first_observation", self.started), 3)
        if gap > self.args.max_observation_gap_seconds:
            continuity["interrupted"] = True
            continuity["gapViolations"] += 1
        check(gap <= self.args.max_observation_gap_seconds,
              f"soak {kind} gap {gap:.3f}s exceeded declared {self.args.max_observation_gap_seconds:.3f}s continuity limit")

    def soak(self):
        repo = self.project + "/soak"
        self.hf.create_repo(repo_id=repo, private=True)
        files = {f"fixture-{i:03d}.txt": fixture_bytes(64 << 10, self.run_id + "-" + str(i)) for i in range(8)}
        maximum_iterations = math.ceil(self.args.duration_hours * 3600 / self.args.interval_seconds)
        minimum_successful_iterations = max(1, math.floor(maximum_iterations * .8))
        self.summary["declaredBudget"] = {"durationHours": self.args.duration_hours, "intervalSeconds": self.args.interval_seconds,
                                          "forceEvery": self.args.force_every, "maximumIterations": maximum_iterations,
                                          "minimumSuccessfulIterations": minimum_successful_iterations,
                                          "maxObservationGapSeconds": self.args.max_observation_gap_seconds,
                                          "snapshotBytesUpperBound": sum(map(len, files.values())) * (1 + maximum_iterations // self.args.force_every),
                                          "note": "Conservative bound for initial upload plus scheduled forced scans; one worker runs sequentially."}
        self._soak_last_observation = self.started
        self.summary["soakContinuity"] = {"interrupted": False, "gapViolations": 0, "successfulObservations": 0,
                                          "successfulIterations": 0, "maxRoundStartGapSeconds": 0,
                                          "minimumCoverageMet": False,
                                          "maxSuccessfulObservationGapSeconds": 0,
                                          "requestedDurationSeconds": self.args.duration_hours * 3600,
                                          "scope": "Periodic successful business observations; gaps above the declared limit fail the run."}
        sha, upload_ms = self.upload(repo, files)
        report, scan_s, transitions = self.wait(repo, sha)
        self.verify(report, files)
        self.note_soak_time("success")
        self.event("soak-initial", repo=repo, revision=sha, uploadMs=upload_ms, waitSeconds=scan_s, transitions=transitions)
        self.summary["soakRepository"] = {"repo": repo, "revision": sha, "totalBytes": sum(map(len, files.values()))}
        deadline = self.started + self.args.duration_hours * 3600
        iteration = 0
        while time.monotonic() < deadline:
            begin = time.monotonic()
            iteration += 1
            try:
                self.note_soak_time("round-start")
                self.renew()
                if iteration % self.args.force_every == 0:
                    previous = self.actor.json(self.security_path(repo, "report", sha))
                    self.actor.json(self.security_path(repo, "rescan"), "POST", {"revision": sha}, (202,))
                    pending = self.actor.request("/" + repo + "/resolve/" + sha + "/fixture-000.txt", "HEAD")
                    check(pending["status"] in (403, 503), "rescan pending HEAD admitted content")
                    report, scan_s, transitions = self.wait(repo, sha)
                    self.verify(report, files)
                    check(report["cachedFiles"] == 0 and report["reportId"] != previous["reportId"], "forced soak scan lost attempt fencing")
                    history = self.actor.json(self.security_path(repo, "history/" + previous["reportId"]))
                    check(history == previous, "forced soak scan mutated the complete historical report")
                    self.event("soak-rescan", iteration=iteration, waitSeconds=scan_s, reportId=report["reportId"],
                               transitions=transitions, completeHistoricalReportUnchanged=True)
                measured = self.reads(repo, sha, files)
                report = self.actor.json(self.security_path(repo, "report", sha))
                self.verify(report, files)
                observation = self.resources()
                self.note_soak_time("success")
                self.summary["soakContinuity"]["successfulIterations"] += 1
                value = self.event("soak-iteration-pass", iteration=iteration, reads=measured,
                                   reportId=report["reportId"], resourceObservation=observation)
            except Exception as error:
                self.failures += 1
                value = self.event("soak-iteration-fail", iteration=iteration, errorType=type(error).__name__, reason=self.redact(error))
            self.summary["iterations"] = iteration
            self.summary["failedIterations"] = self.failures
            self.summary["lastEvent"] = value
            self.save()
            time.sleep(max(0, min(self.args.interval_seconds - (time.monotonic() - begin), deadline - time.monotonic())))
        self.note_soak_time("finish")
        check(self.summary["soakContinuity"]["successfulIterations"] >= minimum_successful_iterations,
              "soak successful iterations were below the declared minimum coverage")
        self.summary["soakContinuity"]["minimumCoverageMet"] = True

    def begin_soak_power_request(self):
        check(self.args.mode == "soak", "system activity is requested only for a bounded soak")
        self._power_request = None
        state = {"requestedAt": utc_now(), "platform": os.name, "applied": False,
                 "method": "SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)",
                 "flags": "0x80000001", "powerPlanChanged": False, "displayRequired": False,
                 "awayModeRequired": False, "preventsExplicitUserSleep": False,
                 "reference": "https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setthreadexecutionstate"}
        self.summary["idleSleepPrevention"] = state
        if os.name != "nt":
            state.update(status="unsupported", reason="Windows API is unavailable on this platform")
        elif threading.current_thread() is not threading.main_thread():
            state.update(status="unsupported", reason="system activity lease requires the soak main thread")
        else:
            try:
                function = ctypes.WinDLL("kernel32", use_last_error=True).SetThreadExecutionState
                function.argtypes = [ctypes.c_uint32]
                function.restype = ctypes.c_uint32
                previous = int(function(0x80000001))
                state.update(applied=bool(previous), previousThreadState=hex(previous),
                             status="applied" if previous else "unavailable")
                if previous:
                    self._power_request = (function, threading.get_ident())
                else:
                    state["reason"] = "SetThreadExecutionState returned zero"
            except (AttributeError, OSError) as error:
                state.update(status="unsupported", reason=type(error).__name__)
        self.event("soak-system-activity-request", evidence=dict(state))
        self.save()
        return state

    def clear_soak_power_request(self):
        state = self.summary.get("idleSleepPrevention")
        request = getattr(self, "_power_request", None)
        if not state or not request:
            return
        function, thread_id = request
        check(threading.get_ident() == thread_id, "system activity lease must be cleared by its original main thread")
        previous = int(function(0x80000000))
        state.update(cleared=bool(previous), clearedAt=utc_now(), clearFlags="0x80000000",
                     stateBeforeClear=hex(previous))
        check(previous, "failed to clear the soak system activity lease")
        self._power_request = None
        self.event("soak-system-activity-cleared", evidence=dict(state))

    def run(self):
        try:
            if self.args.mode == "benchmark":
                self.benchmark()
            else:
                self.begin_soak_power_request()
                self.soak()
        except Exception as error:
            self.failures += 1
            self.event("fatal", errorType=type(error).__name__, reason=self.redact(error))
        finally:
            if self.args.mode == "soak":
                try:
                    self.clear_soak_power_request()
                except Exception as error:
                    self.failures += 1
                    self.event("soak-system-activity-cleanup-fail", reason=self.redact(error))
            try:
                self.actor.revoke()
            except Exception as error:
                self.failures += 1
                self.event("credential-cleanup-fail", reason=self.redact(error))
            self.summary.update(finishedAt=utc_now(), elapsedSeconds=round(time.monotonic()-self.started, 3),
                                failures=self.failures, passed=self.failures == 0)
            self.save()
        return int(self.failures != 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("benchmark", "soak"), required=True)
    parser.add_argument("--base-url", default="http://127.0.0.1:3002")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password-env", default="MATRIXHUB_E2E_PASSWORD")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--deployment-evidence", type=Path)
    parser.add_argument("--scan-timeout", type=float, default=300)
    parser.add_argument("--docker-observe", action="store_true")
    parser.add_argument("--docker-project", choices=("matrix-security", "matrix-security-lab", "matrix-security-lab-v2", "matrix-security-lab-v3"), default="matrix-security")
    parser.add_argument("--duration-hours", type=float, default=12)
    parser.add_argument("--interval-seconds", type=float, default=60)
    parser.add_argument("--force-every", type=int, default=10)
    parser.add_argument("--max-observation-gap-seconds", type=float,
                        help="Maximum round-start or successful-observation gap; default max(180, 3 * interval).")
    args = parser.parse_args()
    if args.max_observation_gap_seconds is None:
        args.max_observation_gap_seconds = max(180, 3 * args.interval_seconds)
    check(math.isfinite(args.duration_hours) and 0 < args.duration_hours <= 24 and
          math.isfinite(args.interval_seconds) and args.interval_seconds >= 20 and args.force_every >= 2,
          "soak configuration must be bounded")
    check(math.isfinite(args.scan_timeout) and 0 < args.scan_timeout <= 600,
          "scan timeout must be finite, positive and at most 600 seconds")
    check(math.isfinite(args.max_observation_gap_seconds) and args.max_observation_gap_seconds >= args.interval_seconds,
          "soak observation gap limit must be finite and at least the requested interval")
    os.environ["HF_HUB_DISABLE_XET"] = "1"
    os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
    os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"
    os.environ["NO_PROXY"] = os.environ.get("NO_PROXY", "") + ",127.0.0.1,localhost,::1"
    return Workload(args).run()


if __name__ == "__main__":
    raise SystemExit(main())
