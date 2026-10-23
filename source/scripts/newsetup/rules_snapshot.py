#!/usr/bin/env python3
"""Prepare complete ClamAV snapshots outside the offline scanner. Python stdlib only."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time
import threading
import uuid

DATABASES = ("main.cvd", "daily.cvd", "bytecode.cvd")
MAX_AGE_SECONDS = 7 * 86400
ENGINE_VERSION = "ClamAV 1.4.6"
SCHEMA = "matrixhub.rules-snapshot/v1"


class SetupError(RuntimeError):
    pass


def require(condition, code):
    if not condition:
        raise SetupError(code)


def ordinary(path: Path, directory=False):
    path = path.absolute()
    for item in (path, *path.parents):
        info = item.lstat()
        require(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
                "symlink-or-reparse-path")
    require(path.is_dir() if directory else stat.S_ISREG(path.stat().st_mode), "wrong-path-type")
    return path


def digest(path):
    ordinary(path)
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        result = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(stream.fileno())
    require((before.st_size, before.st_mtime_ns, before.st_ino) ==
            (after.st_size, after.st_mtime_ns, after.st_ino), "input-changed")
    return result


def atomic_json(path, value):
    ordinary(path.parent, directory=True)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    with temporary.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def atomic_text(path, content):
    ordinary(path.parent, directory=True)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    with temporary.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def bounded(argv, timeout=180, limit=1048576, env=None, input_data=None):
    """Bound each output pipe while it is produced; secrets never reach logs."""
    try:
        require(input_data is None or (type(input_data) is bytes and len(input_data) <= 1024), "tool-input-budget")
        process = subprocess.Popen(argv, stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    except OSError as error:
        raise SetupError("tool-unavailable") from error
    exceeded = threading.Event()
    buffers = [bytearray(), bytearray()]

    def collect(stream, destination):
        while True:
            chunk = stream.read(4096)
            if not chunk:
                return
            if len(destination) + len(chunk) > limit:
                exceeded.set()
                process.kill()
                return
            destination.extend(chunk)

    threads = [threading.Thread(target=collect, args=(stream, output), daemon=True)
               for stream, output in zip((process.stdout, process.stderr), buffers)]
    for thread in threads:
        thread.start()
    try:
        if input_data is not None:
            try:
                process.stdin.write(input_data)
                process.stdin.close()
            except (BrokenPipeError, OSError):
                process.kill()
                process.wait(timeout=10)
                raise SetupError("tool-input-refused") from None
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        process.kill()
        process.wait(timeout=10)
        raise SetupError("tool-timeout") from error
    finally:
        for thread in threads:
            thread.join(timeout=2)
        process.stdout.close()
        process.stderr.close()
    require(not exceeded.is_set(), "tool-output-limit")
    return process.returncode, bytes(buffers[0])


def run(argv, timeout=180, input_data=None):
    code, output = bounded(argv, timeout, input_data=input_data)
    require(code == 0, "tool-failed")
    return output


def temporary_container(argv, timeout=180, input_data=None):
    """Each container has an unguessable owner and is removed even if CLI dies."""
    owner = uuid.uuid4().hex
    name = "mh-sec-tool-" + owner
    require(argv[:2] == ["docker", "run"], "invalid-temporary-container-command")
    command = argv[:2] + ["--name", name, "--label", "matrixhub.security.tool-run=" + owner] + argv[2:]
    try:
        return run(command, timeout, input_data=input_data)
    finally:
        code, output = bounded(["docker", "container", "inspect", "--format",
                                '{{json .Id}}|{{index .Config.Labels "matrixhub.security.tool-run"}}', name], timeout=30)
        if code == 0:
            identifier, actual_owner = output.decode().strip().split("|", 1)
            identifier = json.loads(identifier)
            require(len(identifier) == 64 and all(c in "0123456789abcdef" for c in identifier)
                    and actual_owner == owner, "temporary-container-ownership-mismatch")
            run(["docker", "container", "rm", "--force", identifier], timeout=30)
        else:
            # Distinguish normal --rm from an unreachable daemon. The latter is
            # a cleanup failure and must never be reported as successful setup.
            run(["docker", "info", "--format", "{{.OSType}}"], timeout=30)


def image_id(image):
    value = run(["docker", "image", "inspect", "--format", "{{.Id}}", image]).decode().strip()
    require(len(value) == 71 and value.startswith("sha256:"), "invalid-local-image-id")
    return value


# sigtool validates the CVD signature. A complete engine load additionally checks
# the signed internal .info metadata against the outer CVD header (including time).
VERIFY_SCRIPT = r'''
import hashlib,json,os,subprocess
from pathlib import Path
root=Path("/rules")
def call(args):
 p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=240)
 if p.returncode: raise RuntimeError("verification-tool-failed")
 return p.stdout
version=call(["/usr/local/bin/sigtool","--version"]).decode().strip()
if not version.startswith("ClamAV 1.4.6/") and version!="ClamAV 1.4.6": raise RuntimeError("wrong-engine-version")
records=[]
for name in ("main.cvd","daily.cvd","bytecode.cvd"):
 output=call(["/usr/local/bin/sigtool","--info",str(root/name)])
 if b"Verification OK." not in output: raise RuntimeError("signature-verification-missing")
 with (root/name).open("rb") as f: fields=f.read(512).decode("ascii").rstrip(" \x00\r\n").split(":")
 if len(fields)<9 or fields[0]!="ClamAV-VDB": raise RuntimeError("invalid-cvd-header")
 records.append({"name":name,"version":int(fields[2]),"buildEpoch":int(fields[8]),"signatureVerified":True,"verificationOutputSha256":hashlib.sha256(output).hexdigest()})
probe=Path("/tmp/engine-probe.txt"); probe.write_bytes(b"MatrixHub rule initialization probe.\n")
call(["/usr/local/bin/clamscan","--database=/rules","--no-summary",str(probe)])
print(json.dumps({"engine":version,"engineLoadVerified":True,"files":records}))
'''


def verify_engine(directory, immutable_image):
    output = temporary_container(["docker", "run", "--rm", "--pull=never", "--network=none", "--read-only",
                  "--user=65532:65532", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
                  "--pids-limit=32", "--memory=3g", "--memory-swap=3g", "--cpus=1",
                  "--ulimit=core=0", "--tmpfs=/tmp:rw,size=32m,mode=1777,noexec,nosuid,nodev",
                  "--mount", f"type=bind,src={directory},dst=/rules,readonly",
                  "--entrypoint=python", immutable_image, "-I", "-c", VERIFY_SCRIPT], timeout=900)
    value = json.loads(output)
    require(value.get("engineLoadVerified") is True, "engine-load-not-verified")
    require({entry["name"] for entry in value["files"]} == set(DATABASES), "incomplete-verification")
    require(all(entry.get("signatureVerified") is True for entry in value["files"]), "signature-not-verified")
    return value


def freshness(files, now, max_age_seconds, previous=None):
    require(0 < max_age_seconds <= MAX_AGE_SECONDS, "invalid-freshness-policy")
    require(all(isinstance(x.get("version"), int) and x["version"] > 0 and
                isinstance(x.get("buildEpoch"), int) and 0 < x["buildEpoch"] <= now for x in files), "future-or-invalid-database-time")
    daily = next(item for item in files if item["name"] == "daily.cvd")
    # Future times are rejected rather than allowed to extend the freshness SLA.
    require(0 < daily["buildEpoch"] <= now, "future-or-invalid-daily-time")
    require(now - daily["buildEpoch"] < max_age_seconds, "rules-expired")
    if previous:
        old = {entry["name"]: entry for entry in previous["files"]}
        for entry in files:
            require(entry["version"] >= old[entry["name"]]["version"] and
                    entry["buildEpoch"] >= old[entry["name"]]["buildEpoch"], "rules-rollback-rejected")
    return daily["buildEpoch"] + max_age_seconds


def read_active(store):
    path = store / "active.json"
    if not path.exists():
        return None
    ordinary(path)
    active = json.loads(path.read_text(encoding="utf-8"))
    identifier = active["snapshot"]
    require(len(identifier) == 64 and all(c in "0123456789abcdef" for c in identifier), "invalid-active-pointer")
    manifest = store / "manifests" / (identifier + ".json")
    require(digest(manifest) == active["manifestSha256"], "manifest-changed")
    value = json.loads(manifest.read_text(encoding="utf-8"))
    require(value.get("schema") == SCHEMA, "unsupported-manifest")
    require(value.get("snapshot") == identifier, "snapshot-identity-mismatch")
    return value


def verify_active(store, image=None, now=None):
    store = ordinary(store, directory=True)
    manifest = read_active(store)
    require(manifest is not None, "no-active-rules")
    directory = ordinary(store / "snapshots" / manifest["snapshot"], directory=True)
    require(set(item.name for item in directory.iterdir()) == set(DATABASES), "unexpected-rule-files")
    for entry in manifest["files"]:
        file = directory / entry["name"]
        require(file.stat().st_size == entry["size"] and digest(file) == entry["sha256"], "rule-file-changed")
    now = int(time.time()) if now is None else now
    expiry = freshness(manifest["files"], now, manifest["maxAgeSeconds"])
    require(manifest["expiresAt"] == expiry, "manifest-expiry-mismatch")
    if image:
        verification = verify_engine(directory, image)
        require([(x["name"], x["version"], x["buildEpoch"]) for x in verification["files"]] ==
                [(x["name"], x["version"], x["buildEpoch"]) for x in manifest["files"]], "verified-metadata-changed")
    return directory, manifest


def remove_preparing(stage, snapshots):
    require(stage.parent == snapshots and stage.name.startswith(".preparing-"), "invalid-cleanup-target")
    ordinary(stage, directory=True)
    files = list(stage.iterdir())
    require(all(file.name in DATABASES for file in files), "unexpected-preparing-content")
    stage.chmod(0o755)
    for file in files:
        ordinary(file)
        file.chmod(0o644)
        file.unlink()
    stage.rmdir()


def prepare(source, store, image, max_age_seconds=None):
    source = ordinary(source, directory=True)
    store.mkdir(parents=True, exist_ok=True)
    store = ordinary(store, directory=True)
    for name in ("snapshots", "manifests"):
        (store / name).mkdir(exist_ok=True)
        ordinary(store / name, directory=True)
    lock = store / "prepare.lock"
    try:
        lock.mkdir()
    except FileExistsError as error:
        raise SetupError("snapshot-preparation-locked") from error
    stage = store / "snapshots" / (".preparing-" + uuid.uuid4().hex)
    stage.mkdir()
    try:
        for name in DATABASES:
            original = ordinary(source / name)
            require(512 < original.stat().st_size <= 2 * 1024**3, "invalid-database-size")
            shutil.copyfile(original, stage / name)
            (stage / name).chmod(0o444)
        verification = verify_engine(stage, image)
        files = [dict(entry, size=(stage / entry["name"]).stat().st_size,
                      sha256=digest(stage / entry["name"])) for entry in verification["files"]]
        now = int(time.time())
        previous = read_active(store)
        if max_age_seconds is None:
            max_age_seconds = previous["maxAgeSeconds"] if previous else MAX_AGE_SECONDS
        expiry = freshness(files, now, max_age_seconds, previous)
        identity = {"files": [{key: entry[key] for key in ("name", "size", "sha256", "version", "buildEpoch")} for entry in files],
                    "maxAgeSeconds": max_age_seconds, "engineImage": image}
        snapshot = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        destination = store / "snapshots" / snapshot
        if destination.exists():
            ordinary(destination, directory=True)
            require(all(digest(destination / x["name"]) == x["sha256"] for x in files), "existing-snapshot-changed")
            remove_preparing(stage, store / "snapshots")
        else:
            stage.chmod(0o555)
            stage.rename(destination)
        # Reopen after publication: exFAT rename inode identities are not assumed.
        require(set(x.name for x in destination.iterdir()) == set(DATABASES), "published-inventory-changed")
        require(all(digest(destination / x["name"]) == x["sha256"] for x in files), "published-content-changed")
        manifest = {"schema": SCHEMA, "snapshot": snapshot, "files": files,
                    "engine": verification["engine"], "engineImage": image, "engineLoadVerified": True,
                    "verifiedAt": now, "expiresAt": expiry, "maxAgeSeconds": max_age_seconds,
                    "source": "operator-provided-official-cvd", "previousSnapshot": previous["snapshot"] if previous else None}
        path = store / "manifests" / (snapshot + ".json")
        if path.exists():
            ordinary(path)
            existing = json.loads(path.read_text(encoding="utf-8"))
            require(existing.get("snapshot") == snapshot and existing.get("files") == files and
                    existing.get("maxAgeSeconds") == max_age_seconds and existing.get("engineImage") == image and
                    existing.get("expiresAt") == expiry, "immutable-manifest-conflict")
            manifest = existing
        else:
            atomic_json(path, manifest)
        atomic_json(store / "active.json", {"snapshot": snapshot, "manifestSha256": digest(path)})
        return manifest
    finally:
        if stage.exists():
            remove_preparing(stage, store / "snapshots")
        lock.rmdir()


def _update_locked(store, image, network_not_before, max_age_seconds=None):
    # Explicit operator gate plus persisted cooldown. No automatic retries.
    store.mkdir(parents=True, exist_ok=True)
    ordinary(store, directory=True)
    gate = store / "updater-gate.json"
    now = int(time.time())
    previous = json.loads(ordinary(gate).read_text()) if gate.exists() else {}
    require(now >= max(network_not_before, previous.get("notBefore", 0)), "updater-cooldown-active")
    gate_value = dict(previous, attemptedAt=now, notBefore=now + 86400)
    atomic_json(gate, gate_value)
    stage = store / ("download-" + uuid.uuid4().hex)
    stage.mkdir()
    # Named numeric user works without reading host account identity. A minimal
    # passwd file supplies FreshClam's DatabaseOwner lookup for UID 65532.
    config = store / "updater.conf"
    passwd = store / "updater.passwd"
    atomic_text(config, "DatabaseDirectory /rules\nDatabaseOwner scanner\nDatabaseMirror database.clamav.net\nForeground yes\nLogTime yes\nMaxAttempts 1\nScriptedUpdates no\n")
    atomic_text(passwd, "scanner:x:65532:65532:scanner:/tmp:/usr/sbin/nologin\n")
    cache = store / "freshclam.dat"
    if cache.exists():
        require(previous.get("cacheSha256") is not None, "unowned-updater-cache")
        ordinary(cache)
        require(digest(cache) == previous["cacheSha256"], "updater-cache-changed")
        shutil.copyfile(cache, stage / "freshclam.dat")
    else:
        require(previous.get("cacheSha256") is None, "updater-cache-missing")
    # One networkless init touches only the new updater directory, with the same
    # two capabilities as Compose volume init. The updater itself is non-root.
    temporary_container(["docker", "run", "--rm", "--pull=never", "--network=none", "--read-only",
         "--user=0:0", "--cap-drop=ALL", "--cap-add=CHOWN", "--cap-add=FOWNER",
         "--security-opt=no-new-privileges:true", "--mount", f"type=bind,src={stage},dst=/rules",
         "--entrypoint=/bin/sh", image, "-ec", "chown 65532:65532 /rules && chmod 0755 /rules; if [ -f /rules/freshclam.dat ]; then chown 65532:65532 /rules/freshclam.dat && chmod 0600 /rules/freshclam.dat; fi"])
    try:
        temporary_container(["docker", "run", "--rm", "--pull=never", "--read-only", "--user=65532:65532",
             "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--pids-limit=32", "--memory=512m",
             "--ulimit=core=0", "--tmpfs=/tmp:rw,size=32m,mode=1777,noexec,nosuid,nodev",
             "--mount", f"type=bind,src={stage},dst=/rules",
             "--mount", f"type=bind,src={config},dst=/config/freshclam.conf,readonly",
             "--mount", f"type=bind,src={passwd},dst=/etc/passwd,readonly",
             "--entrypoint=/bin/sh", image, "-c", "/usr/local/bin/freshclam --config-file=/config/freshclam.conf --stdout; code=$?; if [ -f /rules/freshclam.dat ]; then chmod 0644 /rules/freshclam.dat; fi; exit $code"], timeout=1800)
        return prepare(stage, store, image, max_age_seconds)
    finally:
        if (stage / "freshclam.dat").exists():
            ordinary(stage / "freshclam.dat")
            temporary = store / ("freshclam-cache-" + uuid.uuid4().hex + ".tmp")
            shutil.copyfile(stage / "freshclam.dat", temporary)
            os.replace(temporary, cache)
            gate_value["cacheSha256"] = digest(cache)
            atomic_json(gate, gate_value)
        # Keep a failed download for explicit diagnosis; never activate it.


def update(store, image, network_not_before, max_age_seconds=None):
    store.mkdir(parents=True, exist_ok=True)
    ordinary(store, directory=True)
    lock = store / "update.lock"
    try:
        lock.mkdir()
    except FileExistsError as error:
        raise SetupError("updater-locked") from error
    try:
        return _update_locked(store, image, network_not_before, max_age_seconds)
    finally:
        lock.rmdir()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "verify", "update"))
    parser.add_argument("--store", type=Path, required=True)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--scanner-image", default="matrixhub-security-scanner:1.4.6")
    parser.add_argument("--max-age-days", type=int, choices=range(1, 8), help="Defaults to the active store policy, or seven days for a new store")
    parser.add_argument("--network-not-before", type=int, help="Required update gate: existing CDN cooldown expiry, Unix epoch; 0 only if no previous cooldown")
    args = parser.parse_args()
    try:
        image = image_id(args.scanner_image)
        if args.action == "prepare":
            require(args.source is not None, "source-required")
            result = prepare(args.source, args.store, image, args.max_age_days * 86400 if args.max_age_days is not None else None)
        elif args.action == "update":
            require(args.network_not_before is not None, "existing-network-cooldown-gate-required")
            result = update(args.store, image, args.network_not_before, args.max_age_days * 86400 if args.max_age_days is not None else None)
        else:
            _, result = verify_active(args.store, image)
        print(json.dumps({"status": "verified", "snapshot": result["snapshot"], "expiresAt": result["expiresAt"]}))
    except (SetupError, ValueError, KeyError, OSError) as error:
        print(json.dumps({"status": "failed", "code": str(error) if isinstance(error, SetupError) else type(error).__name__}), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
