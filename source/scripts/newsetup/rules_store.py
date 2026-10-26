#!/usr/bin/env python3
"""Optional in-memory (tmpfs) rules directory for the offline scanner. Python stdlib only.

A named tmpfs volume cannot be shared between containers, so the copy into memory
has to happen inside the scanner container itself. The scanner entrypoint is
replaced by a small bootstrap that copies the already signature-verified snapshot
from a read-only bind into a private tmpfs, re-hashes both sides, and only then
execs the real scanner. Any mismatch stops the container instead of scanning with
a partially loaded or unexpected rule set.

Container-internal state is deliberately not reused across starts: each start gets
a fresh tmpfs and a fresh complete copy, which matches the measured 2.3 s copy cost
reported with the performance experiment.
"""
from __future__ import annotations

import json
from pathlib import Path

from rules_snapshot import SetupError, require

INIT_PATH = "/rules-init.py"
SOURCE_PATH = "/rules-source"
EXPECTATION_PATH = "/expected.json"
TARGET_PATH = "/rules"
MIN_BYTES = 8 * 1024**2
MAX_BYTES = 8 * 1024**3
MARKER_NAME = ".matrixhub-rules-volume.json"

INIT_SCRIPT = r'''
import hashlib,json,os,signal,stat,sys
signal.alarm(900)
SOURCE="/rules-source"; TARGET="/rules"
def filesystem_for(mountpoint):
    for line in open("/proc/self/mountinfo", encoding="utf-8"):
        fields = line.split()
        if len(fields) > 5 and fields[4] == mountpoint and "-" in fields:
            separator = fields.index("-")
            if separator + 1 < len(fields):
                return fields[separator + 1]
    return None
def hash_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1048576), b""):
            digest.update(chunk)
    return digest.hexdigest()
expected = json.load(open("/expected.json", encoding="utf-8"))
if filesystem_for(TARGET) != "tmpfs": raise SystemExit("rules-target-not-tmpfs")
if os.listdir(TARGET): raise SystemExit("rules-target-not-empty")
names = sorted(entry["name"] for entry in expected["files"])
if names != ["bytecode.cvd", "daily.cvd", "main.cvd"]: raise SystemExit("unexpected-rule-inventory")
for entry in expected["files"]:
    source = os.path.join(SOURCE, entry["name"])
    info = os.lstat(source)
    if not stat.S_ISREG(info.st_mode) or info.st_size != entry["size"]: raise SystemExit("rules-source-invalid")
    if hash_file(source) != entry["sha256"]: raise SystemExit("rules-source-hash-mismatch")
    target = os.path.join(TARGET, entry["name"])
    digest = hashlib.sha256()
    with open(source, "rb") as reader, open(target, "xb") as writer:
        for chunk in iter(lambda: reader.read(1048576), b""):
            writer.write(chunk); digest.update(chunk)
        writer.flush(); os.fsync(writer.fileno())
    os.chmod(target, 0o444)
    if digest.hexdigest() != entry["sha256"]: raise SystemExit("rules-copy-hash-mismatch")
    if hash_file(target) != entry["sha256"]: raise SystemExit("rules-copy-unstable")
if sorted(os.listdir(TARGET)) != names: raise SystemExit("rules-target-inventory")
os.execvp(sys.argv[1], sys.argv[1:])
'''


def tmpfs_options(size):
    """Mount options for the private in-memory rules directory."""
    require(type(size) is int and MIN_BYTES <= size <= MAX_BYTES, "invalid-rules-volume-size")
    return f"rw,noexec,nosuid,nodev,size={size},uid=65532,gid=65532,mode=0750"


def memory_mount(size):
    return TARGET_PATH + ":" + tmpfs_options(size)


def expected_inventory(manifest):
    files = sorted(manifest["files"], key=lambda entry: entry["name"])
    return {"schema": "matrixhub.rules-memory/v1", "snapshot": manifest["snapshot"],
            "engine": manifest["engine"], "expiresAt": manifest["expiresAt"],
            "files": [{"name": entry["name"], "size": entry["size"], "sha256": entry["sha256"]} for entry in files]}


def scanner_command(entrypoint):
    """The image entrypoint is the real scanner command executed after the copy."""
    require(isinstance(entrypoint, list) and entrypoint and len(entrypoint) <= 8, "invalid-scanner-entrypoint")
    require(all(isinstance(item, str) and item and len(item) <= 256 for item in entrypoint), "invalid-scanner-entrypoint")
    require(not any(character in item for item in entrypoint for character in "\r\n\x00"), "invalid-scanner-entrypoint")
    return entrypoint


def write_expectation(work_directory, manifest):
    directory = Path(work_directory).absolute()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "rules-memory-expected.json"
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(expected_inventory(manifest), stream, sort_keys=True, indent=2)
        stream.write("\n")
    path.unlink(missing_ok=True)
    temporary.replace(path)
    path.chmod(0o644)
    return path


def write_init_script(work_directory):
    directory = Path(work_directory).absolute()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "rules-init.py"
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(INIT_SCRIPT)
    path.unlink(missing_ok=True)
    temporary.replace(path)
    path.chmod(0o644)
    return path