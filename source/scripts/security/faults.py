#!/usr/bin/env python3
# Copyright The MatrixHub Authors. SPDX-License-Identifier: Apache-2.0
"""Real, reversible faults against the dedicated loopback test composition.

This intentionally stops/kills only a selected dedicated test project.
Do not run concurrently with performance measurements or demo recording.
Credentials come from MATRIXHUB_E2E_PASSWORD. No artifact is executed.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import time

from e2e import STATES, TERMINAL, check, file_hash, run_utf8_command, utc_now
from workload import Workload, fixture_bytes


class Faults(Workload):
    script_source = Path(__file__)

    def __init__(self, args):
        expected_url = {"matrix-security": "http://127.0.0.1:3002", "matrix-security-lab": "http://127.0.0.1:3004",
                        "matrix-security-lab-v2": "http://127.0.0.1:3004", "matrix-security-lab-v3": "http://127.0.0.1:3004"}
        check(args.base_url == expected_url[args.docker_project], "faults are limited to the matching dedicated loopback deployment")
        check(args.allow_local_container_faults, "explicit local-fault execution flag is required")
        # Validate the file's own project name before applying -p; overriding
        # an unrelated file would otherwise conceal a wrong composition.
        compose_env = dict(os.environ, SCAN_RULES_DIR=str(args.rules_base.resolve()))
        result = run_utf8_command(["docker", "compose", "-f", str(args.compose_file.resolve()), "config", "--format", "json"],
                                  timeout=30, env=compose_env)
        check(result.returncode == 0, "failed to validate the dedicated Compose configuration")
        configuration = json.loads(result.stdout)
        check(configuration.get("name") == args.docker_project, "Compose file name does not match the selected test project")
        check({"matrixhub", "scanner"} <= set(configuration.get("services", {})), "test composition is missing its declared services")
        self.backend = args.docker_project + "-matrixhub-1"
        self.scanner = args.docker_project + "-scanner-1"
        for container, service in ((self.backend, "matrixhub"), (self.scanner, "scanner")):
            result = run_utf8_command(["docker", "inspect", "--format", '{{json .Config.Labels}}', container], timeout=20)
            check(result.returncode == 0, "dedicated fault-test container does not exist")
            labels = json.loads(result.stdout)
            check(labels.get("com.docker.compose.project") == args.docker_project and
                  labels.get("com.docker.compose.service") == service, "refusing a container outside the test composition")
        super().__init__(args)
        self.summary["dockerProject"] = args.docker_project
        self.summary["composeFileSha256"] = file_hash(args.compose_file)
        self.rules_switched = False
        self.repo = self.project + "/faults"
        self.hf.create_repo(repo_id=self.repo, private=True)
        self.files = {"canary.txt": b"# MATRIXHUB_GENERATION_CANARY_ONLY_FOR_INERT_FAULT_TEST\n"}
        self.sha, upload_ms = self.upload(self.repo, self.files)
        self.initial, wait_s, states = self.wait(self.repo, self.sha)
        self.verify(self.initial, self.files)
        self.event("fault-initial", repo=self.repo, revision=self.sha, uploadMs=upload_ms, waitSeconds=wait_s, states=states)

    def docker(self, *arguments, timeout=40, env=None):
        result = run_utf8_command(["docker", *arguments], timeout=timeout, env=env)
        check(result.returncode == 0, "Docker local fault operation failed: " + result.stderr[:1024])
        return result.stdout

    def health(self):
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            try:
                response = self.actor.request("/healthz", authenticated=False, timeout=max(.1, min(5, deadline - time.monotonic())))
                if response["status"] == 200 and response["body"] == b"OK":
                    return
            except OSError:
                pass
            time.sleep(.5)
        raise AssertionError("application health did not recover")

    def tasks(self, timeout=15):
        return self.actor.json(self.security_path(self.repo, "tasks") + "?limit=200", timeout=timeout)["items"]

    def task_until(self, task_id, states, timeout=300):
        # Reading tasks cannot create lazy scan work. This proves recovery by
        # the durable worker, without touching report/model_info first.
        deadline = time.monotonic() + timeout
        observed = []
        while time.monotonic() < deadline:
            matches = [item for item in self.tasks(timeout=max(.1, min(15, deadline - time.monotonic()))) if item["id"] == task_id]
            check(len(matches) == 1, "durable task disappeared from the read-only task list")
            task = matches[0]
            check(task["state"] in STATES, "task returned an unrecognized state")
            if not observed or observed[-1]["state"] != task["state"]:
                observed.append({"state": task["state"], "at": utc_now(), "attempt": task["attempt"]})
            if task["state"] in states:
                return task, observed
            check(task["state"] not in TERMINAL, "task reached an unexpected terminal state: " + json.dumps(task))
            time.sleep(min(.5, max(0, deadline - time.monotonic())))
        raise AssertionError("durable task did not reach expected states: " + json.dumps(observed))

    def denied(self, revision):
        response = self.actor.request("/" + self.repo + "/resolve/" + revision + "/canary.txt")
        check(response["status"] in (403, 503), "fault admitted original artifact")
        check(not response["headers"].get("Location") and response["body"] != self.files["canary.txt"], "denial exposed content/redirect")
        check(b"MATRIXHUB_GENERATION_CANARY_ONLY_FOR_INERT_FAULT_TEST" not in response["body"], "denial leaked wrapped canary bytes")
        return {"status": response["status"], "bodySha256": hashlib.sha256(response["body"]).hexdigest()}

    def scanner_outage(self):
        before = self.actor.json(self.security_path(self.repo, "report", self.sha))
        target_before = next(item for item in self.tasks() if item["id"] == before["taskId"])
        check(target_before["state"] == "pass" and target_before["generation"] == before["generation"],
              "offline force recovery requires the existing approved generation task")
        self.docker("stop", "--time", "5", self.scanner)
        try:
            unavailable = self.actor.json(self.security_path(self.repo, "report", self.sha))
            check(unavailable["state"] == "fail" and not unavailable["complete"], "offline scanner retained an approval")
            denied = self.denied(self.sha)
            force = self.actor.json(self.security_path(self.repo, "rescan"), "POST", {"revision": self.sha}, (202,))
            marker = {"outage-upload.txt": fixture_bytes(128, self.run_id + "-outage")}
            new_sha, upload_ms = self.upload(self.repo, marker)
            tasks = self.tasks()
            force_intent = next(item for item in tasks if item["id"] == force["id"])
            force_target = next(item for item in tasks if item["id"] == target_before["id"])
            check(force_intent["state"] == "pending" and force_intent["generation"] == "unavailable" and force_intent["force"],
                  "offline force did not retain a durable unresolved intent")
            check(force_target["state"] == "pending" and force_target["force"] and force_target["generation"] == before["generation"],
                  "offline force did not invalidate the previous generation approval")
            unbound = next(item for item in tasks if item["revision"] == new_sha and item["generation"] == "unavailable")
            check(unbound["state"] == "pending", "offline upload did not retain pending durable intent")
        finally:
            self.docker("start", self.scanner)
        # Neither tasks endpoint invokes lazy Ensure. Prove both durable intents
        # recover before report/content reads can create or merge scan work.
        recovered_force, force_states = self.task_until(force_target["id"], {"pass", "warn", "block", "fail"})
        check(recovered_force["state"] == "pass" and recovered_force["generation"] == before["generation"] and
              recovered_force["attempt"] > target_before["attempt"] and recovered_force["force"],
              "offline force was not automatically scanned as a new generation-bound attempt")
        retired_intent, _ = self.task_until(force_intent["id"], {"fail"})
        check(retired_intent["error"] == "scanner recovery intent superseded by task " + str(recovered_force["id"]),
              "offline force intent was not explicitly absorbed by its recovered task")
        task, task_states = self.task_until(unbound["id"], {"pass", "warn", "block", "fail"})
        check(task["state"] == "pass" and task["generation"] != "unavailable", "offline upload was not automatically scanned after recovery")
        restored, _, _ = self.wait(self.repo, self.sha, allow_scanner_startup=True)
        self.verify(restored, self.files)
        check(restored["reportId"] != before["reportId"] and restored["cachedFiles"] == 0,
              "offline force intent did not invalidate and replace the old approval")
        uploaded, _, _ = self.wait(self.repo, new_sha)
        self.verify(uploaded, {**self.files, **marker})
        history = self.actor.json(self.security_path(self.repo, "history/" + before["reportId"]))
        check(history == before, "offline force recovery mutated the complete historical report")
        return {"offlineState": unavailable["state"], "denied": denied, "offlineForceTaskId": force["id"],
                "offlineForceIntent": force_intent, "invalidatedForceTarget": force_target,
                "automaticForceRecoveryTask": recovered_force, "automaticForceRecoveryTransitions": force_states,
                "retiredForceIntent": retired_intent, "recoveryProofBeforeLazyReads": True,
                "offlineUploadMs": upload_ms, "automaticRecoveryTask": task, "automaticRecoveryTransitions": task_states,
                "oldReportId": before["reportId"], "newReportId": restored["reportId"], "forceCachedFiles": restored["cachedFiles"],
                "completeHistoricalReportUnchanged": True}

    def cancellation(self):
        previous = self.actor.json(self.security_path(self.repo, "report", self.sha))
        task = self.actor.json(self.security_path(self.repo, "rescan"), "POST", {"revision": self.sha}, (202,))
        scanning, states = self.task_until(task["id"], {"scanning"}, timeout=40)
        cancelled = self.actor.json(self.security_path(self.repo, f"tasks/{task['id']}/cancel"), "POST")
        check(cancelled["canceled"], "authorized cancellation was not applied")
        terminal, _ = self.task_until(task["id"], {"fail"}, timeout=10)
        denial = self.denied(self.sha)
        # A scanning claim precedes staging/engine work. Observe beyond the
        # deployed service's 120-second request budget plus cleanup and lease.
        late_window_seconds = 160
        late_deadline = time.monotonic() + late_window_seconds
        self.event("late-completion-observation-start", seconds=late_window_seconds)
        while time.monotonic() < late_deadline:
            late_task, _ = self.task_until(task["id"], {"fail"}, timeout=max(.1, min(15, late_deadline - time.monotonic())))
            check(late_task["attempt"] == terminal["attempt"], "cancelled attempt changed during the late-completion window")
            self.denied(self.sha)
            time.sleep(min(2, max(0, late_deadline - time.monotonic())))
        later = self.actor.json(self.security_path(self.repo, "report", self.sha))
        check(later["state"] == "fail" and not later["complete"], "late completion overwrote cancellation")
        historical = self.actor.json(self.security_path(self.repo, "history/" + previous["reportId"]))
        check(historical == previous, "cancellation mutated the complete historical report")
        self.actor.json(self.security_path(self.repo, "rescan"), "POST", {"revision": self.sha}, (202,))
        recovered, _, _ = self.wait(self.repo, self.sha)
        self.verify(recovered, self.files)
        return {"scanningAttempt": scanning["attempt"], "transitions": states, "cancelledState": terminal["state"],
                "downloadDenied": denial, "lateCompletionWindowSeconds": late_window_seconds,
                "observationScope": "Claimed scanning task remained cancelled and denied throughout the observation window.",
                "stateAfterLateCompletionWindow": later["state"], "historicalReportId": historical["reportId"],
                "completeHistoricalReportUnchanged": True}

    def backend_crash(self):
        task = self.actor.json(self.security_path(self.repo, "rescan"), "POST", {"revision": self.sha}, (202,))
        scanning, transitions = self.task_until(task["id"], {"scanning"}, timeout=40)
        began = time.monotonic()
        killed_at = dt.datetime.now(dt.timezone.utc)
        lease_until = dt.datetime.fromisoformat(scanning["leaseUntil"].replace("Z", "+00:00"))
        check(lease_until > killed_at, "cannot prove recovery from an already-expired lease")
        remaining_lease = (lease_until - killed_at).total_seconds()
        self.docker("kill", "--signal", "KILL", self.backend)
        stopped = json.loads(self.docker("inspect", "--format", "{{json .State}}", self.backend))
        check(not stopped["Running"] and stopped["ExitCode"] == 137,
              "backend did not stop from SIGKILL; graceful completion cannot prove lease recovery")
        self.docker("start", self.backend)
        self.health()
        denial = self.denied(self.sha)
        recovered, states = self.task_until(task["id"], {"pass", "warn", "block", "fail"}, timeout=360)
        check(recovered["state"] == "pass" and recovered["attempt"] > scanning["attempt"], "lease recovery did not create a new successful attempt")
        recovery_seconds = time.monotonic() - began
        check(recovery_seconds >= remaining_lease and dt.datetime.now(dt.timezone.utc) >= lease_until,
              "backend recovery completed before the captured claim lease expired")
        report, _, _ = self.wait(self.repo, self.sha)
        self.verify(report, self.files)
        return {"oldAttempt": scanning["attempt"], "newAttempt": recovered["attempt"], "leaseUntil": scanning["leaseUntil"],
                "recoverySeconds": round(recovery_seconds, 3), "remainingLeaseAtKillSeconds": round(remaining_lease, 3),
                "configuredClaimLeaseSeconds": 150,
                "killSignal": "SIGKILL", "stoppedExitCode": stopped["ExitCode"], "beforeKill": transitions,
                "afterRestart": states, "immediateDownloadDenied": denial, "reportId": report["reportId"]}

    def switch_rules(self, directory):
        env = dict(os.environ, SCAN_RULES_DIR=str(directory.resolve()))
        self.docker("compose", "-p", self.args.docker_project, "-f", str(self.args.compose_file.resolve()),
                    "up", "-d", "--no-deps", "--force-recreate", "scanner", env=env)

    def generation_change(self):
        previous = self.actor.json(self.security_path(self.repo, "report", self.sha))
        directory = self.root / "rules-generation-canary"
        directory.mkdir()
        for name in ("main.cvd", "daily.cvd", "bytecode.cvd"):
            source = self.args.rules_base / name
            check(source.is_file(), "complete official rules snapshot is required")
            shutil.copyfile(source, directory / name)
        canary = b"MATRIXHUB_GENERATION_CANARY_ONLY_FOR_INERT_FAULT_TEST"
        (directory / "matrixhub-canary.ndb").write_text("MatrixHub.Generation.Canary:0:*:" + canary.hex() + "\n", encoding="ascii")
        self.rules_switched = True
        try:
            self.switch_rules(directory)
            immediate_denial = self.denied(self.sha)
            blocked, wait_s, transitions = self.wait(self.repo, self.sha, allow_scanner_startup=True)
            check(blocked["generation"] != previous["generation"], "new immutable rules snapshot did not change generation")
            check(blocked["state"] == "block" and blocked["complete"], "supplemental inert canary rule did not produce complete block")
            check(blocked["cachedFiles"] == 0, "different-generation analysis reused a prior approval")
            findings = [finding for item in blocked["files"] for finding in item["findings"]]
            check(any(finding["engine"] == "clamav" and "MatrixHub.Generation.Canary" in finding["rule"] for finding in findings), "actual ClamAV canary finding absent")
            denial = self.denied(self.sha)
            old = self.actor.json(self.security_path(self.repo, "history/" + previous["reportId"]))
            check(old == previous, "rule transition mutated the complete historical report")
        finally:
            self.switch_rules(self.args.rules_base)
            self.rules_switched = False
        restored, _, _ = self.wait(self.repo, self.sha, allow_scanner_startup=True, expected_generation=previous["generation"])
        self.verify(restored, self.files)
        check(restored["generation"] == previous["generation"], "original rules snapshot was not restored")
        return {"oldGeneration": previous["generation"], "newGeneration": blocked["generation"],
                "waitSeconds": wait_s, "transitions": transitions, "findings": findings,
                "immediateDownloadDenied": immediate_denial,
                "downloadDenied": denial, "historicalReportId": old["reportId"], "completeHistoricalReportUnchanged": True,
                "restoredGeneration": restored["generation"],
                "rulePurpose": "Supplemental harmless test canary; complete official CVD databases retained."}

    def run(self):
        try:
            for name, operation in (("scanner-outage-offline-upload-and-force-recovery", self.scanner_outage),
                                    ("cancellation-and-late-completion", self.cancellation),
                                    ("sigkill-backend-durable-lease-recovery", self.backend_crash),
                                    ("immutable-rules-change-invalidates-approval", self.generation_change)):
                try:
                    evidence = operation()
                    value = self.event("fault-pass", name=name, evidence=evidence)
                    value["status"] = "pass"
                except Exception as error:
                    self.failures += 1
                    value = self.event("fault-fail", name=name, errorType=type(error).__name__, reason=self.redact(error))
                    value["status"] = "fail"
                self.summary["cases"].append(value)
                self.save()
        finally:
            if self.rules_switched:
                try:
                    self.switch_rules(self.args.rules_base)
                    self.rules_switched = False
                except Exception as error:
                    self.failures += 1
                    self.event("rules-restore-fail", reason=self.redact(error))
            try:
                self.docker("start", self.scanner, self.backend)
            except Exception as error:
                self.failures += 1
                self.event("container-restore-fail", reason=self.redact(error))
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
    parser.add_argument("--base-url", default="http://127.0.0.1:3002")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password-env", default="MATRIXHUB_E2E_PASSWORD")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--deployment-evidence", type=Path)
    parser.add_argument("--rules-base", type=Path, required=True)
    parser.add_argument("--compose-file", type=Path, default=Path("deploy/security/compose.yaml"))
    parser.add_argument("--allow-local-container-faults", action="store_true")
    parser.add_argument("--docker-project", choices=("matrix-security", "matrix-security-lab", "matrix-security-lab-v2", "matrix-security-lab-v3"), default="matrix-security")
    parser.set_defaults(mode="fault", scan_timeout=360, docker_observe=False)
    args = parser.parse_args()
    os.environ["HF_HUB_DISABLE_XET"] = "1"
    os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
    os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"
    os.environ["NO_PROXY"] = os.environ.get("NO_PROXY", "") + ",127.0.0.1,localhost,::1"
    return Faults(args).run()


if __name__ == "__main__":
    raise SystemExit(main())
