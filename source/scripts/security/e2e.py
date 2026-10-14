#!/usr/bin/env python3
# Copyright The MatrixHub Authors.
# SPDX-License-Identifier: Apache-2.0
"""Real MatrixHub/Hugging Face client security acceptance checks.

Use an isolated test deployment. Credentials come from environment variables;
tokens and passwords are never written to reports. Samples are byte strings,
never deserialized, imported, or executed. EICAR is the standard antivirus test
string, and unsafe-global.pkl contains a reference without a REDUCE call.

  MATRIXHUB_E2E_PASSWORD=... python scripts/security/e2e.py \
    --base-url http://localhost:3002 --output-dir /tmp/security-e2e

--prepare-only writes samples without contacting a server or importing the HF
client. --stage-limit-bytes can exercise the deployed file coverage limit;
zero disables this optional large-file case. A coverage error is never called
a malware detection. Each execution gets its own unique test project/users.
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import datetime as dt
import hashlib
import http.cookiejar
import importlib.metadata
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


STATES = {"pending", "scanning", "pass", "warn", "block", "fail"}
TERMINAL = {"pass", "warn", "block", "fail"}
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
SAFETENSORS_HEADER = json.dumps({"x": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]}},
                               separators=(",", ":")).encode().ljust(128, b" ")
SAMPLES = {
    "config.json": (b'{"model_type":"matrixhub-e2e","version":1}\n', "clean configuration"),
    "config-v2.json": (b'{"model_type":"matrixhub-e2e","version":2}\n', "branch move fixture"),
    "benign.pkl": (b"\x80\x04]\x94(K\x01K\x02K\x03e.", "primitive list pickle; never loaded"),
    "warning.pkl": (b"\x80\x02cmatrixhub_e2e_fixture\nUnknownCallable\n.", "unknown global reference; never imported"),
    "unsafe-global.pkl": (b"\x80\x02cos\nsystem\n.", "dangerous global reference, no invocation; never loaded"),
    "eicar.txt": (EICAR, "standard antivirus test string, no executable payload"),
    "unsupported.npy": (b"\x93NUMPY\x01\x00", "unsupported serialization coverage fixture, not malware"),
    "valid-128.safetensors": ((128).to_bytes(8, "little") + SAFETENSORS_HEADER + b"\x00",
                              "one U8 byte with a valid 128-byte header; never loaded"),
    "renamed-unsafe.safetensors": (b"\x80\x02cos\nsystem\n.",
                                  "dangerous global reference renamed as safetensors; format coverage test, never loaded"),
}


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def run_utf8_command(arguments, *, timeout, env=None):
    # Windows subprocess text-reader threads can lose a decoding exception.
    # Decode on this thread so malformed CLI output always fails the case.
    result = subprocess.run(arguments, capture_output=True, timeout=timeout, env=env)
    result.stdout = result.stdout.decode("utf-8", errors="strict")
    result.stderr = result.stderr.decode("utf-8", errors="strict")
    return result


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def file_hash(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(128 << 10), b""):
            h.update(block)
    return h.hexdigest()


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def prepare_samples(root, stage_limit_bytes):
    directory = root / "samples"
    directory.mkdir(parents=True, exist_ok=True)
    manifest = {}
    for name, (data, purpose) in SAMPLES.items():
        path = directory / name
        # Standard EICAR bytes stay in memory: the Windows host can quarantine
        # this antivirus test file before the official client opens its path.
        if name != "eicar.txt":
            path.write_bytes(data)
        manifest[name] = {"size": len(data), "sha256": sha256(data), "purpose": purpose,
                          "fixtureStorage": "memory" if name == "eicar.txt" else "file"}
    if stage_limit_bytes:
        path = directory / "stage-limit.bin"
        # Sparse-file behavior is avoided: upload/scanner limits see real bytes.
        chunk = b"MATRIXHUB_COVERAGE_LIMIT_TEST\n" * 4096
        remaining = stage_limit_bytes
        with path.open("wb") as handle:
            while remaining:
                block = chunk[:min(remaining, len(chunk))]
                handle.write(block)
                remaining -= len(block)
        manifest[path.name] = {"size": path.stat().st_size, "sha256": file_hash(path),
                               "purpose": "file coverage limit, not malware"}
    (root / "samples.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return directory, manifest


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Actor:
    def __init__(self, base, username, password):
        self.base = base
        self.username = username
        self.password = password
        self.token = None
        self.token_name = None
        self.user_id = None
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), NoRedirect())

    def request(self, path, method="GET", payload=None, headers=None, authenticated=True, timeout=60):
        url = urllib.parse.urljoin(self.base + "/", path)
        target, origin = urllib.parse.urlsplit(url), urllib.parse.urlsplit(self.base)
        loopback = {"localhost", "127.0.0.1", "::1"}
        same_origin = target.netloc == origin.netloc
        loopback_alias = target.hostname in loopback and origin.hostname in loopback and target.port == origin.port
        check(target.scheme == origin.scheme and not target.username and not target.password and (same_origin or loopback_alias),
              "action URL escaped the test deployment origin")
        request_headers = dict(headers or {})
        if target.path.endswith("/info/lfs/objects/batch"):
            request_headers.setdefault("Accept", "application/vnd.git-lfs+json")
            request_headers.setdefault("Content-Type", "application/vnd.git-lfs+json")
        if authenticated and self.token:
            request_headers["Authorization"] = "Bearer " + self.token
        body = None
        if payload is not None:
            body = json.dumps(payload).encode()
            request_headers.setdefault("Content-Type", "application/json")
        req = urllib.request.Request(url, body, request_headers, method=method)
        started = time.perf_counter()
        try:
            response = self.opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            data = response.read()
            return {"status": response.code, "headers": response.headers, "body": data,
                    "elapsedMs": round((time.perf_counter() - started) * 1000, 3)}

    def json(self, path, method="GET", payload=None, statuses=(200,), timeout=60):
        response = self.request(path, method, payload, timeout=timeout)
        check(response["status"] in statuses,
              f"{method} {path}: HTTP {response['status']}, expected {statuses}")
        try:
            return json.loads(response["body"] or b"{}")
        except ValueError as error:
            raise AssertionError(f"{method} {path}: invalid JSON response") from error

    def login(self, run_id):
        self.json("/api/v1alpha1/login", "POST", {
            "username": self.username, "password": self.password, "rememberMe": False})
        current = self.json("/api/v1alpha1/current-user")
        check(current.get("username") == self.username, "current-user identity mismatch")
        self.user_id = int(current["id"])
        self.token_name = "security-e2e-" + run_id
        token_response = self.json("/api/v1alpha1/current-user/access-tokens", "POST", {
            "name": self.token_name, "expireAt": str(int(time.time()) + 3600)})
        self.token = token_response["token"]
        # Verify this is a real server-issued token, independently of cookies.
        probe = Actor(self.base, self.username, "")
        probe.token = self.token
        check(probe.json("/api/v1alpha1/current-user")["username"] == self.username,
              "server-issued token did not retain identity")
        return {"username": self.username, "id": self.user_id}

    def revoke(self):
        if not self.token:
            return
        tokens = self.json("/api/v1alpha1/current-user/access-tokens").get("items", [])
        for token in tokens:
            if token.get("name") == self.token_name:
                self.json(f"/api/v1alpha1/current-user/access-tokens/{token['id']}", "DELETE")
        self.token = None


class Suite:
    def __init__(self, args, root, samples, manifest):
        self.args = args
        self.root = root
        self.samples = samples
        self.manifest = manifest
        self.run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(3)
        self.project = "security-e2e-" + self.run_id
        self.tenant_project = "other-e2e-" + self.run_id
        self.admin = Actor(args.base_url.rstrip("/"), args.username, os.environ.get(args.password_env, ""))
        self.actors = [self.admin]
        self.reports = {}
        self.observed_states = set()
        self.output = {"schema": 1, "startedAt": utc_now(), "runId": self.run_id,
                       "baseURL": self.admin.base, "scriptSha256": file_hash(__file__),
                       "samples": manifest, "cases": [], "repositories": {},
                       "safety": "No artifact was deserialized, imported, or executed."}
        dependency_lock = Path(__file__).resolve().parents[3] / "runtime" / "client-requirements.lock"
        if dependency_lock.is_file():
            self.output["clientRequirementsSha256"] = file_hash(dependency_lock)
        if args.deployment_evidence:
            self.output["deployment"] = json.loads(args.deployment_evidence.read_text(encoding="utf-8"))
        self.hf = None
        (root / "e2e-script-snapshot.py").write_bytes(Path(__file__).read_bytes())

    def redacted(self, value):
        text = str(value)
        for actor in self.actors:
            for secret in (actor.password, actor.token):
                if secret:
                    text = text.replace(secret, "[REDACTED]")
        return re.sub(r"(?i)(Bearer|Basic)\s+[^\s\"']+", r"\1 [REDACTED]", text)

    def save(self):
        self.output["observedStates"] = sorted(self.observed_states)
        self.output["unobservedStates"] = sorted(STATES - self.observed_states)
        (self.root / "results.json").write_text(json.dumps(self.output, indent=2), encoding="utf-8")

    def case(self, name, operation):
        began = time.perf_counter()
        result = {"name": name, "startedAt": utc_now()}
        try:
            result["evidence"] = operation()
            result["status"] = "pass"
        except Exception as error:
            result["status"] = "fail"
            result["errorType"] = type(error).__name__
            result["reason"] = self.redacted(error)
        result["elapsedMs"] = round((time.perf_counter() - began) * 1000, 3)
        self.output["cases"].append(result)
        self.save()
        print(f"{name}: {result['status']} ({result['elapsedMs']} ms)", flush=True)
        return result["status"] == "pass"

    def repo(self, name):
        return self.project + "/" + name

    def security_path(self, repo, endpoint, revision=None):
        path = "/api/security/v1alpha1/models/" + repo + "/" + endpoint
        return path + ("?" + urllib.parse.urlencode({"revision": revision}) if revision else "")

    def resolve_path(self, repo, revision, filename):
        return "/" + repo + "/resolve/" + urllib.parse.quote(revision, safe="") + "/" + filename

    def upload(self, repo, source, target=None):
        upload_source = SAMPLES[source][0] if source == "eicar.txt" else self.samples / source
        info = self.hf.upload_file(path_or_fileobj=upload_source,
                                   path_in_repo=target or source, repo_id=repo,
                                   commit_message="Security E2E fixture: " + source)
        check(re.fullmatch("[a-f0-9]{40}", info.oid), "upload did not return immutable SHA")
        return info.oid

    def wait_report(self, repo, revision):
        began = time.monotonic()
        transitions = []
        while time.monotonic() - began < self.args.scan_timeout:
            report = self.admin.json(self.security_path(repo, "report", revision))
            state = report.get("state")
            check(state in STATES, "unknown machine status in real security response")
            check(report.get("repo") == repo and report.get("revision") == revision,
                  "report does not bind the requested repository and SHA")
            self.observed_states.add(state)
            if not transitions or transitions[-1]["state"] != state:
                transitions.append({"state": state, "at": utc_now()})
            if state in TERMINAL:
                self.reports[repo] = report
                (self.root / (repo.replace("/", "--") + "--" + revision + ".json")).write_text(
                    json.dumps(report, indent=2), encoding="utf-8")
                return report, transitions
            time.sleep(self.args.poll_interval)
        raise AssertionError(f"scan timeout after {self.args.scan_timeout}s; observed {transitions}")

    def report_summary(self, report, transitions):
        return {"repo": report["repo"], "revision": report["revision"], "state": report["state"],
                "complete": report["complete"], "generation": report["generation"],
                "reportId": report.get("reportId"), "cachedFiles": report.get("cachedFiles"),
                "error": report.get("error"), "transitions": transitions}

    def verify_manifest(self, report, filename, sample):
        check(report["complete"], "scanner did not produce complete coverage")
        matching = [item for item in report["files"] if item["path"] == filename]
        check(len(matching) == 1, "expected exactly one file in immutable report manifest")
        item = matching[0]
        check(item["sha256"] == self.manifest[sample]["sha256"], "scanned digest differs from uploaded bytes")
        check(item["size"] == self.manifest[sample]["size"], "scanned size differs from uploaded bytes")
        check(item["complete"] and len(item["engines"]) >= 2, "both engines must provide complete analysis")
        check(item["generation"] == report["generation"], "file analysis engine generation differs from report")
        return item

    def download(self, repo, revision, filename, sample):
        from huggingface_hub import hf_hub_download
        target = hf_hub_download(repo_id=repo, filename=filename, revision=revision,
                                 endpoint=self.admin.base, token=self.admin.token,
                                 cache_dir=self.root / "downloads" / "cache",
                                 force_download=True)
        check(file_hash(target) == self.manifest[sample]["sha256"], "official client received different bytes")
        return {"sha256": file_hash(target), "size": Path(target).stat().st_size}

    def denied(self, response, statuses=(401, 403), expected_state=None):
        check(response["status"] in statuses, f"expected denied request, got HTTP {response['status']}")
        check(not response["headers"].get("Location"), "denied download must not expose redirect")
        if expected_state:
            body = json.loads(response["body"])
            check(body.get("state") == expected_state, "denial machine state mismatch")
        return {"status": response["status"], "code": response["headers"].get("X-Error-Code"),
                "bodySha256": sha256(response["body"])}

    def client_denied(self, repo, revision, filename):
        from huggingface_hub import hf_hub_download
        try:
            hf_hub_download(repo_id=repo, filename=filename, revision=revision,
                            endpoint=self.admin.base, token=self.admin.token,
                            cache_dir=self.root / "downloads" / "denied-cache",
                            force_download=True)
        except Exception as error:
            cause = error
            for _ in range(8):
                response = getattr(cause, "response", None)
                if response is not None:
                    status = response.status_code
                    check(status in (401, 403, 503), f"client failed for an unrelated HTTP {status}")
                    return {"exception": type(error).__name__, "httpStatus": status}
                cause = cause.__cause__ or cause.__context__
                if cause is None:
                    break
            raise AssertionError(f"official client failed without a security HTTP denial: {type(error).__name__}") from error
        raise AssertionError("official client downloaded a denied artifact")

    def setup(self):
        check(self.admin.password, f"credential environment {self.args.password_env} is required")
        from huggingface_hub import HfApi
        self.output["client"] = {"huggingface_hub": importlib.metadata.version("huggingface_hub"),
                                 "python": sys.version.split()[0]}
        identity = self.admin.login(self.run_id)
        for project in (self.project, self.tenant_project):
            self.admin.json("/api/v1alpha1/projects", "POST", {"name": project, "type": "PROJECT_TYPE_PRIVATE"})
        for label in ("viewer", "outsider"):
            actor = Actor(self.admin.base, label + "-" + self.run_id, secrets.token_urlsafe(24))
            self.actors.append(actor)
            self.admin.json("/api/v1alpha1/users", "POST", {
                "username": actor.username, "password": actor.password, "isAdmin": False})
            actor.login(self.run_id)
            setattr(self, label, actor)
        self.admin.json(f"/api/v1alpha1/projects/{self.project}/members", "POST", {
            "memberId": self.viewer.user_id, "memberType": "MEMBER_TYPE_USER", "role": "ROLE_TYPE_PROJECT_VIEWER"})
        self.admin.json(f"/api/v1alpha1/projects/{self.tenant_project}/members", "POST", {
            "memberId": self.outsider.user_id, "memberType": "MEMBER_TYPE_USER", "role": "ROLE_TYPE_PROJECT_ADMIN"})
        self.hf = HfApi(endpoint=self.admin.base, token=self.admin.token)
        return {"identity": identity, "project": self.project, "tenantProject": self.tenant_project,
                "viewerId": self.viewer.user_id, "outsiderId": self.outsider.user_id}

    def clean_and_metadata(self):
        repo = self.repo("clean")
        self.hf.create_repo(repo_id=repo, private=True)
        first_sha = self.upload(repo, "config.json")
        first, first_states = self.wait_report(repo, first_sha)
        check(first["state"] == "pass", "clean config must have pass status")
        self.verify_manifest(first, "config.json", "config.json")
        self.first_sha = first_sha
        self.clean_sha = self.upload(repo, "benign.pkl")
        report, transitions = self.wait_report(repo, self.clean_sha)
        check(report["state"] == "pass", "benign primitive pickle must have pass status")
        pickle_file = self.verify_manifest(report, "benign.pkl", "benign.pkl")
        self.verify_manifest(report, "config.json", "config.json")
        info = self.hf.model_info(repo_id=repo, revision=self.clean_sha,
                                  securityStatus=True, files_metadata=True)
        check(info.sha == self.clean_sha, "official model_info did not retain immutable SHA")
        status = info.security_repo_status
        check(status["status"] == "clean" and status["details"]["revision"] == self.clean_sha,
              "official model_info security fields are incompatible")
        sibling = next(item for item in info.siblings if item.rfilename == "benign.pkl")
        check(sibling.lfs is not None, "small pickle fixture did not exercise LFS upload")
        check(sibling.lfs.sha256 == self.manifest["benign.pkl"]["sha256"], "client LFS sha256 metadata mismatch")
        check(sibling.lfs.size == sibling.size == self.manifest["benign.pkl"]["size"], "client LFS size metadata mismatch")
        check(sibling.lfs.pointer_size > 0, "client pointerSize field missing")
        check(pickle_file["lfsOid"] == sibling.lfs.sha256, "report LFS OID differs from actual client metadata")
        self.output["repositories"]["clean"] = {"repo": repo, "firstSHA": first_sha, "cleanSHA": self.clean_sha}
        return {"initial": self.report_summary(first, first_states),
                "lfs": self.report_summary(report, transitions), "clientLFS": {
                    "sha256": sibling.lfs.sha256, "size": sibling.lfs.size, "pointerSize": sibling.lfs.pointer_size}}

    def approved_downloads(self):
        repo = self.repo("clean")
        results = {"config": self.download(repo, self.clean_sha, "config.json", "config.json"),
                   "pickle": self.download(repo, self.clean_sha, "benign.pkl", "benign.pkl")}
        for filename in ("config.json", "benign.pkl"):
            url = self.resolve_path(repo, self.clean_sha, filename)
            head = self.admin.request(url, "HEAD")
            check(head["status"] == 200 and not head["body"], "approved HEAD returned unexpected body/status")
            check(head["headers"].get("X-Repo-Commit") == self.clean_sha, "HEAD commit header mismatch")
            ranged = self.admin.request(url, headers={"Range": "bytes=0-3"})
            check(ranged["status"] == 206 and ranged["body"] == SAMPLES[filename][0][:4], "Range bytes differ from approved snapshot")
            check(ranged["headers"].get("ETag") == '"' + self.manifest[filename]["sha256"] + '"', "Range ETag not bound to bytes")
            results[filename + "-head-range"] = {"head": head["status"], "range": ranged["status"]}
            cache_path = "/api/resolve-cache/models/" + repo + "/" + self.clean_sha + "/" + filename
            cache = self.admin.request(cache_path, headers={"Range": "bytes=0-3"})
            check(cache["status"] == 206 and cache["body"] == SAMPLES[filename][0][:4], "resolve-cache bypassed verified Range content")
            results[filename + "-resolve-cache"] = {"range": cache["status"], "sha256": sha256(cache["body"])}
        self.action = self.batch_action(repo, self.clean_sha, "benign.pkl")
        action_body = self.admin.request(self.action)
        check(action_body["status"] == 200 and sha256(action_body["body"]) == self.manifest["benign.pkl"]["sha256"], "scoped LFS action returned wrong bytes")
        check("/" + self.clean_sha + "/" in self.action, "LFS action omitted immutable repository commit")
        results["lfsAction"] = {"url": self.action, "sha256": sha256(action_body["body"])}
        return results

    def batch_action(self, repo, revision, sample):
        obj = self.manifest[sample]
        batch = self.admin.json("/" + repo + ".git/info/lfs/objects/batch", "POST", {
            "operation": "download", "transfers": ["basic"], "ref": {"name": revision},
            "objects": [{"oid": obj["sha256"], "size": obj["size"]}]})
        item = batch["objects"][0]
        check("error" not in item, f"approved LFS batch object rejected: {item.get('error')}")
        return item["actions"]["download"]["href"]

    def branch_and_cache(self):
        repo = self.repo("clean")
        self.moved_sha = self.upload(repo, "config-v2.json", "config.json")
        report, transitions = self.wait_report(repo, self.moved_sha)
        check(report["state"] == "pass", "branch move clean configuration failed scan")
        check(report["cachedFiles"] >= 1, "unchanged exact artifacts did not exercise scan cache")
        latest = self.hf.model_info(repo_id=repo, revision="main", securityStatus=True, files_metadata=True)
        check(latest.sha == self.moved_sha != self.clean_sha, "main did not move to the new immutable SHA")
        old = self.download(repo, self.clean_sha, "config.json", "config.json")
        new = self.download(repo, self.moved_sha, "config.json", "config-v2.json")
        check(old["sha256"] != new["sha256"], "old SHA was incorrectly redirected to current branch bytes")
        self.output["repositories"]["clean"]["movedSHA"] = self.moved_sha
        return {"report": self.report_summary(report, transitions), "oldSHABytes": old, "newSHABytes": new}

    def forced_rescan_and_old_action(self):
        repo = self.repo("clean")
        previous = self.admin.json(self.security_path(repo, "report", self.clean_sha))
        task = self.admin.json(self.security_path(repo, "rescan"), "POST", {"revision": self.clean_sha}, (202,))
        current = self.admin.json(self.security_path(repo, "report", self.clean_sha))
        self.observed_states.add(current["state"])
        response = self.admin.request(self.action)
        check(current["state"] in {"pending", "scanning"}, "rescan completed before pending-state action probe; rerun with a slower real scanner")
        denial = self.denied(response)
        report, transitions = self.wait_report(repo, self.clean_sha)
        check(report["state"] == "pass" and report["cachedFiles"] == 0, "force rescan must bypass reusable scan analyses")
        check(report["reportId"] != previous["reportId"], "rescan report identity must include new task attempt")
        history = self.admin.json(self.security_path(repo, "history/" + previous["reportId"]))
        check(history == previous, "complete historical report was mutated by rescan")
        return {"taskId": task["id"], "oldActionDenied": denial, "report": self.report_summary(report, transitions),
                "historicalReportId": history["reportId"], "completeHistoricalReportUnchanged": True}

    def classified_fixture(self, name, sample, expected_state, engine=None, coverage=False):
        repo = self.repo(name)
        self.hf.create_repo(repo_id=repo, private=True)
        revision = self.upload(repo, sample)
        report, transitions = self.wait_report(repo, revision)
        self.output["repositories"][name] = {"repo": repo, "revision": revision}
        check(report["state"] == expected_state,
              f"fixture expected {expected_state}, actual {report['state']}; coverageError={report.get('error')}")
        if coverage:
            check(not report["complete"] and report.get("error"), "coverage failure must remain incomplete with an explicit reason")
            check(report["state"] != "block", "coverage failure must not be reported as malware")
            reason = report["error"].lower()
            if sample == "stage-limit.bin":
                check(any(word in reason for word in ("limit", "quota", "budget", "exceed")),
                      "large-file failure did not report its coverage budget cause")
            elif sample == "renamed-unsafe.safetensors":
                check("invalid_safetensors_header" in reason,
                      "renamed Pickle did not retain its safetensors header coverage failure")
            else:
                check("unsupported" in reason, "unsupported serialization failure did not retain its coverage cause")
        else:
            item = self.verify_manifest(report, sample, sample)
            if engine:
                check(any(finding["engine"] == engine for finding in item["findings"]), "expected real engine finding absent")
        downloads = {}
        if expected_state == "warn":
            downloads["officialClient"] = self.download(repo, revision, sample, sample)
        else:
            downloads["officialClientDenied"] = self.client_denied(repo, revision, sample)
            for method, headers in (("GET", {}), ("HEAD", {}), ("GET", {"Range": "bytes=0-3"})):
                response = self.admin.request(self.resolve_path(repo, revision, sample), method, headers=headers)
                downloads[method + str(bool(headers))] = self.denied(response, (403, 503))
                check(response["body"] != SAMPLES.get(sample, (None,))[0], "denied response contained original artifact")
        return {"report": self.report_summary(report, transitions), "downloads": downloads,
                "classification": "incomplete coverage, not malware" if coverage else "real static engine finding"}

    def safetensors_header_and_download(self):
        sample = "valid-128.safetensors"
        check(len(SAMPLES[sample][0]) == 137 and SAMPLES[sample][0][:2] == b"\x80\x00",
              "valid safetensors regression fixture does not exercise the 128-byte header ambiguity")
        repo = self.repo("safetensors-valid-128")
        self.hf.create_repo(repo_id=repo, private=True)
        revision = self.upload(repo, sample)
        report, transitions = self.wait_report(repo, revision)
        self.output["repositories"]["safetensors-valid-128"] = {"repo": repo, "revision": revision}
        check(report["state"] == "pass", "valid 128-byte safetensors header was not approved")
        item = self.verify_manifest(report, sample, sample)
        check(bool(item["engines"].get("clamav")) and bool(item["engines"].get("picklescan")),
              "valid safetensors did not retain both required engine versions")
        downloaded = self.download(repo, revision, sample, sample)
        info = self.hf.model_info(repo_id=repo, revision=revision, securityStatus=True, files_metadata=True)
        check(info.sha == revision and info.security_repo_status["status"] == "clean",
              "official safetensors metadata lost complete commit-bound approval")
        url = self.resolve_path(repo, revision, sample)
        head = self.admin.request(url, "HEAD")
        check(head["status"] == 200 and not head["body"] and head["headers"].get("X-Repo-Commit") == revision,
              "valid safetensors HEAD lost its immutable approval")
        ranged = self.admin.request(url, headers={"Range": "bytes=0-7"})
        check(ranged["status"] == 206 and ranged["body"] == SAMPLES[sample][0][:8],
              "valid safetensors Range returned different header bytes")
        return {"report": self.report_summary(report, transitions), "officialDownload": downloaded,
                "headStatus": head["status"], "rangeStatus": ranged["status"],
                "headerBytes": 128, "totalBytes": 137,
                "classification": "complete static coverage; no model was loaded or executed"}

    def current_policy_rechecks_old_action(self):
        repo = self.repo("warning")
        revision = self.output["repositories"]["warning"]["revision"]
        action = self.batch_action(repo, revision, "warning.pkl")
        previous = self.admin.json(self.security_path(repo, "policy"))
        try:
            tightened = self.admin.json(self.security_path(repo, "policy"), "PUT", {
                "mode": "enforce", "blockSeverity": "medium"})
            check(tightened["version"] > previous["version"], "policy mutation did not advance version fence")
            denied = self.denied(self.admin.request(action))
            direct = self.denied(self.admin.request(self.resolve_path(repo, revision, "warning.pkl")))
            audit_policy = self.admin.json(self.security_path(repo, "policy"), "PUT", {
                "mode": "audit", "blockSeverity": "medium"})
            allowed = self.admin.request(action)
            check(allowed["status"] == 200 and sha256(allowed["body"]) == self.manifest["warning.pkl"]["sha256"],
                  "audit policy did not permit the completely scanned warning bytes")
            return {"oldActionDenied": denied, "directDenied": direct, "tightenedVersion": tightened["version"],
                    "auditVersion": audit_policy["version"], "auditDownloadSHA256": sha256(allowed["body"])}
        finally:
            self.admin.json(self.security_path(repo, "policy"), "PUT", {
                "mode": previous["mode"], "blockSeverity": previous["blockSeverity"]})

    def boundary_controls(self):
        repo = self.repo("clean")
        denial = {}
        for path, method in (("/" + repo + ".git/info/refs?service=git-upload-pack", "GET"),
                             ("/" + repo + ".git/git-upload-pack", "POST"),
                             ("/objects/" + self.manifest["benign.pkl"]["sha256"], "GET"),
                             ("/objects/" + self.manifest["benign.pkl"]["sha256"], "HEAD"),
                             ("/api/models/" + repo + "/compare/" + self.clean_sha + "..." + self.moved_sha, "GET")):
            denial[method + " " + path] = self.denied(self.admin.request(path, method))
        wrong_size = self.admin.json("/" + repo + ".git/info/lfs/objects/batch", "POST", {
            "operation": "download", "ref": {"name": self.clean_sha}, "objects": [{
                "oid": self.manifest["benign.pkl"]["sha256"], "size": self.manifest["benign.pkl"]["size"] + 1}]})
        item = wrong_size["objects"][0]
        check("error" in item and "download" not in item.get("actions", {}), "wrong LFS size obtained a download action")
        commit = self.admin.json(f"/api/v1alpha1/models/{repo}/commits/{self.moved_sha}")
        check(not commit.get("diff"), "native model commit API exposed historical object content")
        blob = self.admin.json(f"/api/v1alpha1/models/{repo}/blob?" + urllib.parse.urlencode({
            "revision": self.clean_sha, "path": "config.json"}))
        check(self.clean_sha in blob["url"], "native ModelBlob URL is not pinned to requested SHA")
        resolved = self.admin.request(blob["url"])
        check(resolved["status"] == 200 and sha256(resolved["body"]) == self.manifest["config.json"]["sha256"], "native ModelBlob URL bypassed immutable approved content")
        return {"denied": denial, "wrongSizeError": item["error"], "nativeBlobURL": blob["url"]}

    def permissions(self):
        repo = self.repo("clean")
        report_path = self.security_path(repo, "report", self.clean_sha)
        check(self.viewer.json(report_path)["revision"] == self.clean_sha, "project viewer cannot read authorized report")
        outsider = self.denied(self.outsider.request(report_path))
        anonymous = Actor(self.admin.base, "anonymous", "")
        unauthenticated = self.denied(anonymous.request(report_path, authenticated=False))
        viewer_denied = {}
        for endpoint, method, body in (("rescan", "POST", {"revision": self.clean_sha}),
                                        ("policy", "PUT", {"mode": "audit", "blockSeverity": "high"})):
            viewer_denied[endpoint] = self.denied(self.viewer.request(self.security_path(repo, endpoint), method, body))
        stolen_action = self.denied(self.outsider.request(self.action))
        direct_download = self.denied(self.outsider.request(self.resolve_path(repo, self.clean_sha, "benign.pkl")))
        viewer_content = self.viewer.request(self.action)
        check(viewer_content["status"] == 200 and sha256(viewer_content["body"]) == self.manifest["benign.pkl"]["sha256"],
              "authorized viewer could not download the approved LFS snapshot")
        self.admin.json(f"/api/v1alpha1/projects/{self.project}/members", "DELETE", {
            "members": [{"memberId": self.viewer.user_id, "memberType": "MEMBER_TYPE_USER"}]})
        try:
            revoked_viewer = self.denied(self.viewer.request(self.action))
        finally:
            self.admin.json(f"/api/v1alpha1/projects/{self.project}/members", "POST", {
                "memberId": self.viewer.user_id, "memberType": "MEMBER_TYPE_USER", "role": "ROLE_TYPE_PROJECT_VIEWER"})
        # Same OID is a global content hash, never an authorization capability.
        from huggingface_hub import HfApi
        other = self.tenant_project + "/clean"
        other_client = HfApi(endpoint=self.admin.base, token=self.outsider.token)
        other_client.create_repo(repo_id=other, private=True)
        info = other_client.upload_file(path_or_fileobj=self.samples / "config.json", path_in_repo="config.json", repo_id=other)
        self.wait_report(other, info.oid)
        batch = self.outsider.json("/" + other + ".git/info/lfs/objects/batch", "POST", {
            "operation": "download", "ref": {"name": info.oid}, "objects": [{
                "oid": self.manifest["benign.pkl"]["sha256"], "size": self.manifest["benign.pkl"]["size"]}]})
        check("error" in batch["objects"][0] and "download" not in batch["objects"][0].get("actions", {}),
              "unlisted cross-tenant OID obtained download capability")
        return {"outsiderReport": outsider, "anonymousReport": unauthenticated, "viewerWriteDenied": viewer_denied,
                "stolenAction": stolen_action, "directDownload": direct_download, "viewerOldActionAfterRoleRemoval": revoked_viewer,
                "crossTenantOID": batch["objects"][0]["error"]}

    def audit(self):
        repo = self.repo("clean")
        response = self.admin.json(self.security_path(repo, "audits") + "?limit=200")
        entries = response["items"]
        origins = {entry["entry"] for entry in entries}
        check({"hf-resolve", "hf-resolve-cache", "lfs-batch", "lfs-content", "git-http"} <= origins,
              "native content controls did not retain complete audit origins")
        actions = {entry["action"] for entry in entries}
        check("policy-update" not in actions, "denied viewer policy mutation was applied")
        # Store complete audit evidence, with all immutable repository/path fields.
        (self.root / "audits.json").write_text(json.dumps(response, indent=2), encoding="utf-8")
        return {"count": len(entries), "origins": sorted(origins), "actions": sorted(actions)}

    def ssh_upload_pack(self):
        keygen, ssh = shutil.which("ssh-keygen"), shutil.which("ssh")
        check(keygen and ssh, "existing SSH tools are required for the configured SSH E2E port")
        key_dir = self.root / "ssh"
        key_dir.mkdir(parents=True, exist_ok=True)
        # A Windows shared workspace may be exFAT and cannot enforce key ACLs.
        # Keep the ephemeral private key on the user's native temporary volume;
        # only its public key and known-hosts evidence belong in the run folder.
        private_dir = Path(tempfile.mkdtemp(prefix="matrixhub-e2e-ssh-"))
        private_key = private_dir / "e2e_ed25519"
        name = "security-e2e-" + self.run_id
        registration_attempted = False
        try:
            check(private_dir.resolve().parent == Path(tempfile.gettempdir()).resolve(), "temporary key directory escaped its designated parent")
            if os.name == "nt":
                filesystem = ctypes.create_unicode_buffer(32)
                result = ctypes.windll.kernel32.GetVolumeInformationW(
                    str(private_dir.resolve().anchor), None, 0, None, None, None,
                    filesystem, len(filesystem))
                check(result and filesystem.value.upper() == "NTFS", "ephemeral private SSH keys require an NTFS temporary volume")
            generated = subprocess.run([keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(private_key)],
                                       capture_output=True, timeout=30)
            check(generated.returncode == 0, "failed to generate an ephemeral SSH test key")
            if os.name == "nt":
                # Limit only this newly generated test key. Inherited permissions on
                # the shared workspace otherwise make Windows OpenSSH reject it.
                # Native Windows identity output uses the OEM code page; Docker
                # and OpenSSH protocol text below use UTF-8 independently of it.
                identity = subprocess.check_output(["whoami", "/user", "/fo", "csv", "/nh"],
                                                   timeout=20).decode("oem", errors="strict")
                sid = next(csv.reader(identity.splitlines()))[1]
                check(re.fullmatch(r"S-1-[0-9-]+", sid), "failed to obtain the current Windows user SID")
                subprocess.run(["icacls", str(private_key), "/inheritance:r", "/grant:r", "*" + sid + ":F"],
                               capture_output=True, timeout=30, check=True)
            else:
                private_key.chmod(0o600)
            registration_attempted = True
            self.admin.json("/api/v1alpha1/current-user/ssh-keys", "POST", {
                "name": name, "publicKey": private_key.with_suffix(".pub").read_text(encoding="ascii", errors="strict").strip(),
                "expireAt": str(int(time.time()) + 3600)})
            (key_dir / "e2e_ed25519.pub").write_bytes(private_key.with_suffix(".pub").read_bytes())
            host = urllib.parse.urlsplit(self.admin.base).hostname
            result = subprocess.run([ssh, "-p", str(self.args.ssh_port), "-i", str(private_key),
                "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new",
                "-o", "UserKnownHostsFile=" + str(key_dir / "known_hosts"), "-o", "ConnectTimeout=10",
                "git@" + host, "git-upload-pack '/" + (self.args.ssh_repository or self.repo("clean")) + ".git'"], capture_output=True, timeout=30)
            message = self.redacted(result.stderr.decode("utf-8", errors="strict"))
            check(result.returncode != 0 and "RawGitDisabled" in message,
                  "real SSH command did not reach an authenticated security denial: " + message)
            check(not result.stdout, "strict SSH returned Git history bytes before denial")
            return {"exitCode": result.returncode, "stdoutSize": len(result.stdout),
                    "stderr": message, "publicKeySHA256": file_hash(private_key.with_suffix(".pub"))}
        finally:
            try:
                if registration_attempted:
                    keys = self.admin.json("/api/v1alpha1/current-user/ssh-keys").get("items", [])
                    for key in keys:
                        if key.get("name") == name:
                            self.admin.json(f"/api/v1alpha1/current-user/ssh-keys/{key['id']}", "DELETE")
            finally:
                private_key.unlink(missing_ok=True)
                private_key.with_suffix(".pub").unlink(missing_ok=True)
                private_dir.rmdir()

    def run(self):
        if self.args.ssh_repository:
            self.output["scope"] = "ssh-supplement"
            self.case("native-admin-login-for-ssh-probe", lambda: self.admin.login(self.run_id))
            if self.admin.token:
                self.case("authenticated-real-ssh-upload-pack-denied", self.ssh_upload_pack)
                self.case("revoke-test-token-admin", self.admin.revoke)
            self.output["finishedAt"] = utc_now()
            self.output["passed"] = all(case["status"] == "pass" for case in self.output["cases"])
            self.save()
            return 0 if self.output["passed"] else 1
        self.output["scope"] = "full-e2e"
        ready = self.case("native-login-token-private-project-and-roles", self.setup)
        if ready:
            clean_ready = self.case("official-upload-config-benign-pickle-model-info", self.clean_and_metadata)
            if clean_ready:
                downloads_ready = self.case("official-download-head-range-scoped-lfs", self.approved_downloads)
                branch_ready = self.case("branch-move-immutable-sha-and-scan-cache", self.branch_and_cache)
                if downloads_ready:
                    self.case("force-rescan-old-action-revalidation-history", self.forced_rescan_and_old_action)
                    self.case("cross-tenant-anonymous-viewer-rbac", self.permissions)
                if branch_ready:
                    self.case("raw-git-global-lfs-diff-and-native-blob-controls", self.boundary_controls)
            warning_ready = self.case("warning-pickle-remains-approved", lambda: self.classified_fixture("warning", "warning.pkl", "warn", "picklescan"))
            if warning_ready:
                self.case("policy-version-old-action-enforce-and-audit", self.current_policy_rechecks_old_action)
            self.case("eicar-real-clamav-block", lambda: self.classified_fixture("eicar", "eicar.txt", "block", "clamav"))
            self.case("unsafe-global-real-picklescan-block", lambda: self.classified_fixture("unsafe", "unsafe-global.pkl", "block", "picklescan"))
            self.case("valid-safetensors-128-byte-header-official-upload-download", self.safetensors_header_and_download)
            self.case("unsafe-pickle-renamed-safetensors-coverage-fail", lambda: self.classified_fixture(
                "safetensors-renamed-pickle", "renamed-unsafe.safetensors", "fail", coverage=True))
            self.case("unsupported-serialization-coverage-fail", lambda: self.classified_fixture("unsupported", "unsupported.npy", "fail", coverage=True))
            if self.args.stage_limit_bytes:
                self.case("file-limit-coverage-fail", lambda: self.classified_fixture("stage-limit", "stage-limit.bin", "fail", coverage=True))
            if clean_ready:
                if self.args.ssh_port:
                    self.case("authenticated-real-ssh-upload-pack-denied", self.ssh_upload_pack)
                self.case("native-audit-origin-and-permission-evidence", self.audit)
        for actor in reversed(self.actors):
            if actor.token:
                self.case("revoke-test-token-" + actor.username, lambda actor=actor: actor.revoke())
        self.output["finishedAt"] = utc_now()
        self.output["passed"] = all(case["status"] == "pass" for case in self.output["cases"])
        self.output["coverageNote"] = "Observed states are measured, not inferred; deterministic six-state transport coverage is also provided by Go handler tests."
        self.save()
        return 0 if self.output["passed"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", default="http://localhost:3002")
    parser.add_argument("--username", default=os.environ.get("MATRIXHUB_E2E_USERNAME", "admin"))
    parser.add_argument("--password-env", default="MATRIXHUB_E2E_PASSWORD")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--scan-timeout", type=float, default=300)
    parser.add_argument("--poll-interval", type=float, default=0.25)
    parser.add_argument("--stage-limit-bytes", type=int, default=(64 << 20) + 1)
    parser.add_argument("--ssh-port", type=int, default=2223, help="zero disables the real SSH protocol case")
    parser.add_argument("--deployment-evidence", type=Path, help="non-secret actual container/config evidence JSON")
    parser.add_argument("--ssh-repository", help="run only an SSH supplement against an existing namespace/repository")
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    args.output_dir = args.output_dir.resolve()
    check(0 <= args.stage_limit_bytes <= 256 << 20, "stage limit fixture must be between zero and 256 MiB")
    check(math.isfinite(args.scan_timeout) and 0 < args.scan_timeout <= 600,
          "scan timeout must be finite, positive and at most 600 seconds")
    check(math.isfinite(args.poll_interval) and 0 < args.poll_interval <= 30, "poll interval must be finite and bounded")
    check(0 <= args.ssh_port <= 65535, "SSH port is out of range")
    if args.ssh_repository:
        check(re.fullmatch(r"[A-Za-z0-9-]+/[A-Za-z0-9_.-]+", args.ssh_repository), "SSH probe requires a valid namespace/repository")
        args.stage_limit_bytes = 0
    # Client transport remains the real HTTP path; scanner containers never use
    # these credentials. Xet would add an unrelated external transfer mechanism.
    os.environ["HF_HUB_DISABLE_XET"] = "1"
    os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
    os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"
    os.environ["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"
    os.environ["NO_PROXY"] = os.environ.get("NO_PROXY", "") + ",localhost,127.0.0.1,::1"
    args.output_dir.mkdir(parents=True, exist_ok=True)
    if not args.prepare_only:
        check(not (args.output_dir / "results.json").exists() and not (args.output_dir / "e2e-script-snapshot.py").exists(),
              "use a new output directory for every execution")
    samples, manifest = prepare_samples(args.output_dir, args.stage_limit_bytes)
    if args.prepare_only:
        print(f"Prepared {len(manifest)} static fixtures and hash manifest in {args.output_dir}")
        return 0
    return Suite(args, args.output_dir, samples, manifest).run()


if __name__ == "__main__":
    raise SystemExit(main())
