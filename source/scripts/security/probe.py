#!/usr/bin/env python3
# Copyright The MatrixHub Authors.
# SPDX-License-Identifier: Apache-2.0
"""Operator probes for a running security deployment.

Credentials come from an environment variable (default MATRIXHUB_E2E_PASSWORD),
never from an argument. Each command prints one line of JSON with public values
only: no password, token, or artifact bytes.

  MATRIXHUB_E2E_PASSWORD=... python scripts/security/probe.py upload \
    --base-url http://127.0.0.1:3002 --repo project/name --file ./config.json

Download refuses a transport error as evidence: --expect denied accepts only a
security HTTP status (401/403/503), so an unreachable port never counts as an
admission decision. --expect match compares the delivered bytes with --sha256.

Commands exist so restart and fail-closed checks can be scripted without a
full acceptance run: upload waits for a terminal state, report reads it,
rescan forces a new attempt, and download compares the delivered bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

STATES = {"pending", "scanning", "pass", "warn", "block", "fail"}
TERMINAL = {"pass", "warn", "block", "fail"}


def utc_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


class Client:
    def __init__(self, base, username, password):
        self.base = base.rstrip("/")
        self.username = username
        self.password = password
        self.token = None
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def request(self, path, method="GET", payload=None, statuses=(200,), timeout=60):
        url = urllib.parse.urljoin(self.base + "/", path)
        body = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(url, data=body, method=method)
        if body is not None:
            request.add_header("Content-Type", "application/json")
        if self.token:
            request.add_header("Authorization", "Bearer " + self.token)
        try:
            response = self.opener.open(request, timeout=timeout)
            status, raw = response.status, response.read()
        except urllib.error.HTTPError as error:
            status, raw = error.code, error.read()
        if status not in statuses:
            raise RuntimeError(f"unexpected HTTP {status} for {path}")
        return status, raw

    def json(self, path, method="GET", payload=None, statuses=(200,), timeout=60):
        _, raw = self.request(path, method, payload, statuses, timeout)
        return json.loads(raw) if raw else {}

    def login(self):
        if not self.password:
            raise RuntimeError("credential environment variable is empty")
        self.json("/api/v1alpha1/login", "POST", {"username": self.username, "password": self.password,
                                                 "rememberMe": False})
        current = self.json("/api/v1alpha1/current-user")
        name = "deployment-probe-" + secrets.token_hex(4)
        created = self.json("/api/v1alpha1/current-user/access-tokens", "POST",
                            {"name": name, "expireAt": str(int(time.time()) + 900)})
        self.token = created["token"]
        self.token_name = name
        return current["username"]

    def report(self, repo, revision):
        return self.json("/api/security/v1alpha1/models/" + repo + "/report?revision=" +
                         urllib.parse.quote(revision, safe=""))

    def wait_terminal(self, repo, revision, timeout, interval):
        began = time.monotonic()
        transitions = []
        while time.monotonic() - began < timeout:
            report = self.report(repo, revision)
            state = report.get("state")
            if state not in STATES:
                raise RuntimeError("unknown state in security report")
            if not transitions or transitions[-1] != state:
                transitions.append(state)
            if state in TERMINAL:
                return report, transitions
            time.sleep(interval)
        return self.report(repo, revision), transitions

    def rescan(self, repo, revision):
        status, _ = self.request("/api/security/v1alpha1/models/" + repo + "/rescan", "POST",
                                 {"revision": revision}, statuses=(200, 202))
        return status


def ensure_namespace(client, repo):
    """Create the project that owns a repository, tolerating an existing one."""
    namespace = repo.split("/")[0]
    client.request("/api/v1alpha1/projects", "POST",
                   {"name": namespace, "type": "PROJECT_TYPE_PRIVATE"},
                   statuses=(200, 201, 400, 409))
    client.json("/api/v1alpha1/projects/" + namespace)
    return namespace


def hf_api(base, token):
    from huggingface_hub import HfApi
    return HfApi(endpoint=base, token=token)


def command_upload(args, client):
    source = Path(args.file)
    if not source.is_file():
        raise RuntimeError("fixture file is missing")
    ensure_namespace(client, args.repo)
    api = hf_api(args.base_url, client.token)
    api.create_repo(repo_id=args.repo, repo_type="model", private=True, exist_ok=True)
    info = api.upload_file(path_or_fileobj=str(source), path_in_repo=args.name or source.name,
                           repo_id=args.repo, commit_message="deployment probe fixture")
    revision = info.oid
    report, transitions = client.wait_terminal(args.repo, revision, args.wait, args.interval)
    return {"command": "upload", "repo": args.repo, "revision": revision,
            "state": report.get("state"), "complete": report.get("complete"),
            "transitions": transitions, "fixture": {"name": args.name or source.name,
                                                    "size": source.stat().st_size,
                                                    "sha256": sha256_file(source)}}


def report_files(report):
    files = []
    for item in (report.get("files") or [])[:400]:
        files.append({"path": item.get("path"), "size": item.get("size"), "sha256": item.get("sha256"),
                      "type": item.get("type"), "complete": item.get("complete")})
    return files


def command_report(args, client):
    report = client.report(args.repo, args.revision)
    return {"command": "report", "repo": args.repo, "revision": args.revision,
            "state": report.get("state"), "complete": report.get("complete"),
            "generation": report.get("generation"), "reportId": report.get("reportId"),
            "error": report.get("error"), "files": report_files(report)}


def command_upload_folder(args, client):
    """Upload a directory in one commit so one revision covers every shard."""
    folder = Path(args.folder)
    sources = sorted(item for item in folder.rglob("*") if item.is_file())
    if not sources:
        raise RuntimeError("fixture directory is empty")
    ensure_namespace(client, args.repo)
    api = hf_api(args.base_url, client.token)
    api.create_repo(repo_id=args.repo, repo_type="model", private=True, exist_ok=True)
    info = api.upload_folder(folder_path=str(folder), repo_id=args.repo,
                             commit_message="capacity ramp fixture")
    revision = info.oid
    report, transitions = client.wait_terminal(args.repo, revision, args.wait, args.interval)
    return {"command": "upload-folder", "repo": args.repo, "revision": revision,
            "state": report.get("state"), "complete": report.get("complete"),
            "error": report.get("error"), "transitions": transitions,
            "uploadedFiles": len(sources), "uploadedBytes": sum(item.stat().st_size for item in sources),
            "reportFiles": report_files(report)}


def command_rescan(args, client):
    status = client.rescan(args.repo, args.revision)
    return {"command": "rescan", "repo": args.repo, "revision": args.revision, "httpStatus": status}


def command_download(args, client):
    from huggingface_hub import hf_hub_download
    try:
        target = hf_hub_download(repo_id=args.repo, filename=args.name, revision=args.revision,
                                 endpoint=args.base_url, token=client.token,
                                 cache_dir=args.cache_dir, force_download=True)
    except Exception as error:  # noqa: BLE001 - the client uses its own hierarchy
        if args.expect != "denied":
            raise
        cause = error
        status = None
        for _ in range(8):
            response = getattr(cause, "response", None)
            if response is not None:
                status = response.status_code
                break
            cause = cause.__cause__ or cause.__context__
            if cause is None:
                break
        if status not in (401, 403, 503):
            raise RuntimeError("client failed without a security HTTP denial") from error
        return {"command": "download", "repo": args.repo, "revision": args.revision,
                "name": args.name, "denied": True, "httpStatus": status}
    actual = sha256_file(target)
    if args.expect == "denied":
        raise RuntimeError("download was delivered although a denial was expected")
    return {"command": "download", "repo": args.repo, "revision": args.revision, "name": args.name,
            "sha256": actual, "matches": actual == args.sha256}


def command_wait(args, client):
    report, transitions = client.wait_terminal(args.repo, args.revision, args.wait, args.interval)
    return {"command": "wait", "repo": args.repo, "revision": args.revision,
            "state": report.get("state"), "complete": report.get("complete"),
            "transitions": transitions}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=("upload", "upload-folder", "report", "rescan", "download", "wait"))
    parser.add_argument("--base-url", default="http://127.0.0.1:3002")
    parser.add_argument("--username", default=os.environ.get("MATRIXHUB_E2E_USERNAME", "admin"))
    parser.add_argument("--password-env", default="MATRIXHUB_E2E_PASSWORD")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--file", help="upload: fixture path")
    parser.add_argument("--folder", help="upload-folder: fixture directory")
    parser.add_argument("--name", help="repository file name; defaults to the fixture name")
    parser.add_argument("--revision", help="report/rescan/download: immutable revision")
    parser.add_argument("--sha256", help="download: expected digest")
    parser.add_argument("--cache-dir", default="./probe-cache")
    parser.add_argument("--expect", choices=("match", "denied"), default="match")
    parser.add_argument("--wait", type=float, default=240.0)
    parser.add_argument("--interval", type=float, default=1.0)
    args = parser.parse_args()
    try:
        if not (0 < args.wait <= 1800 and 0.05 <= args.interval <= 30):
            raise RuntimeError("bounded wait and interval are required")
        client = Client(args.base_url, args.username, os.environ.get(args.password_env, ""))
        client.login()
        command = {"upload": command_upload, "upload-folder": command_upload_folder,
                   "report": command_report, "rescan": command_rescan,
                   "download": command_download, "wait": command_wait}[args.command]
        if args.command == "upload-folder" and not args.folder:
            raise RuntimeError("--folder is required for upload-folder")
        if args.command in ("report", "rescan", "download", "wait") and not args.revision:
            raise RuntimeError("--revision is required for this command")
        if args.command == "download" and not (args.name and args.sha256):
            raise RuntimeError("--name and --sha256 are required for download")
        result = command(args, client)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (RuntimeError, KeyError, OSError, ValueError, urllib.error.URLError) as error:
        print(json.dumps({"status": "failed", "code": type(error).__name__,
                          "detail": str(error)[:200]}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())