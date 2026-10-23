#!/usr/bin/env python3
# Copyright The MatrixHub Authors.
# Licensed under the Apache License, Version 2.0.
"""Credential-free, offline scanner. Only this trusted wrapper is executed.

The HTTP supervisor never parses artifacts. Each request starts a bounded child
which uses ClamAV and Picklescan; no pickle.load/torch.load/import of model code.
"""
import argparse
import array
import base64
import contextlib
import concurrent.futures
import gzip
import hashlib
import http.server
import importlib.metadata
import io
import json
import logging
import os
from pathlib import Path, PurePosixPath
import pickletools
import re
import resource
import select
import signal
import socket
import socketserver
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import zipfile
import zlib

VERSION = "matrixhub-security-scanner-v15-typed-writes"
NATIVE_WAVE_BYTES = 2 << 30
NATIVE_WAVE_POLICY = "ordered-greedy-verified-fd-v1"
NESTED_DESERIALIZATION_SYMBOL = ("torch.storage", "_load_from_bytes")
NESTED_DESERIALIZATION_SYMBOL_ID = "torch-storage-load-from-bytes-v1"
MAX_EVIDENCE_CHAIN = 16
ID_RE = re.compile(r"task-[1-9][0-9]*-[1-9][0-9]*-[a-f0-9]{16}/[a-f0-9]{32}\.blob\Z")
SHA_RE = re.compile(r"[a-f0-9]{64}\Z")
TYPE_RE = re.compile(r"(opaque|zip|gzip|numpy|pickle|elf|pe);ext=(|\.[a-z0-9_-]{1,23})\Z")
PICKLE_EXT = {".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt", ".joblib", ".dat", ".data"}
UNSUPPORTED_EXT = {".7z", ".rar", ".xz", ".bz2", ".npy", ".dill", ".h5", ".hdf5"}
RULE_EXT = {".cvd", ".cld", ".hdb", ".hsb", ".ndb", ".ldb", ".cdb", ".cbc", ".ign", ".ign2"}
SAFETENSORS_BITS = {"BOOL": 8, "U8": 8, "I8": 8, "F8_E5M2": 8, "F8_E4M3": 8,
                    "F8_E8M0": 8, "F8_E4M3FNUZ": 8, "F8_E5M2FNUZ": 8,
                    "I16": 16, "U16": 16, "F16": 16, "BF16": 16,
                    "I32": 32, "U32": 32, "F32": 32,
                    "I64": 64, "U64": 64, "F64": 64, "C64": 64,
                    "F4": 4, "F6_E2M3": 6, "F6_E3M2": 6}
SAFETENSORS_MAX_RANK = 64
SAFETENSORS_MAX_TENSORS = 65536
TAR_MAX_EXTENSION_BYTES = 64 << 10
TAR_MAX_PAX_FIELDS = 256
MAX_REQUEST = 16384
MAX_PREFIX_BYTES = 64 << 10
MAX_PREFIX_REQUEST = 90 << 10
MAX_RESPONSE = 2 << 20
ERROR_CODES = frozenset("""rules_changed rules_expired invalid_descriptor invalid_artifact_id
invalid_digest file_limit invalid_analysis_context snapshot_size snapshot_digest
expanded_bytes_limit archive_depth_limit unsupported_container_or_serialization
numpy_serialization_not_supported pickle_opcode_limit pickle_argument_limit
archive_member_limit archive_member_size duplicate_archive_member encrypted_archive
archive_symlink archive_ratio_limit archive_link_or_special_file
pickle_extension_registry_unsupported malformed_pickle empty_pickle
pickle_analysis_incomplete pickle_symbol_analysis_incomplete pickle_symbol_budget
pickle_symbol_analysis_disagreement finding_limit invalid_safetensors_header
invalid_safetensors_offsets clamav_output_limit clamav_unavailable_or_failed
clamav_coverage_incomplete clamav_invalid_result clamav_unexpected_output
scan_timeout scan_cancelled worker_output_limit worker_failed_or_incomplete
request_limit invalid_serialization batch_limit batch_duplicate_artifact
clamav_missing_result clamav_unknown_result""".split())


# Only deterministic static format/semantic failures may become per-file
# coverage findings. Resource budgets, snapshot/rules binding, ClamAV coverage
# and worker/protocol failures remain fatal to the whole request.
FILE_ERROR_CODES = frozenset("""unsupported_container_or_serialization
numpy_serialization_not_supported archive_member_size duplicate_archive_member
encrypted_archive archive_symlink archive_link_or_special_file
pickle_extension_registry_unsupported malformed_pickle empty_pickle
pickle_analysis_incomplete pickle_symbol_analysis_incomplete
pickle_symbol_analysis_disagreement invalid_safetensors_header
invalid_safetensors_offsets invalid_serialization""".split())
COVERAGE_MESSAGE = "Static inspection could not completely analyze this artifact; the scan remains incomplete."
COVERAGE_REMEDIATION = "Review the source and use a trusted artifact; do not load untrusted serialized objects."
FORMAT_EXCEPTIONS = (ValueError, UnicodeError, EOFError, zipfile.BadZipFile,
                     tarfile.TarError, gzip.BadGzipFile, zlib.error)


class Incomplete(Exception):
    """Only fixed internal codes, never exception text from an artifact."""


def backend_from_env():
    # Keep existing service behavior. Warm engine is an explicit test/deploy opt-in.
    value = os.getenv("SCAN_CLAMAV_BACKEND", "clamscan")
    if value not in {"clamscan", "clamd"}:
        raise RuntimeError("invalid fixed ClamAV backend")
    return value


def limits_from_env():
    profile = os.getenv("SCAN_PROFILE", "default")
    if profile not in {"default", "gb", "gb-archive"}:
        raise RuntimeError("invalid fixed scan profile")
    archive = profile == "gb-archive"
    if archive and (os.getenv("SCAN_NATIVE_TEMP") != "/native-tmp"
                    or backend_from_env() != "clamd"):
        raise RuntimeError("archive profile requires fixed private native temp and clamd")
    gb = profile in {"gb", "gb-archive"}
    expanded = int(os.getenv("SCAN_MAX_EXPANDED_BYTES", str(128 << 20)))
    native_threads = int(os.getenv("SCAN_NATIVE_THREADS", "1"))
    if native_threads not in {1, 2, 4} or (native_threads != 1 and (backend_from_env() != "clamd" or archive)):
        raise RuntimeError("parallel native scans require the fixed non-archive clamd profile")
    values = {"max_batch_files": 32,
              "max_batch_bytes": int(os.getenv("SCAN_MAX_BATCH_BYTES", str(256 << 20))),
              "native_threads": native_threads,
              "max_file_bytes": int(os.getenv("SCAN_MAX_FILE_BYTES", str(1280 << 20 if gb else 64 << 20))),
              "max_expanded_bytes": expanded,
              "max_scan_bytes": int(os.getenv("SCAN_MAX_SCAN_BYTES", str(3072 << 20 if archive else 1536 << 20 if gb else expanded))),
              "max_members": int(os.getenv("SCAN_MAX_MEMBERS", "256")),
              "max_depth": int(os.getenv("SCAN_MAX_DEPTH", "3")),
              "max_ratio": int(os.getenv("SCAN_MAX_RATIO", "100")),
              "max_pickle_opcodes": int(os.getenv("SCAN_MAX_PICKLE_OPCODES", "2000000")),
              "max_pickle_argument": int(os.getenv("SCAN_MAX_PICKLE_ARGUMENT", str(8 << 20))),
              "wall_seconds": int(os.getenv("SCAN_WALL_SECONDS", "300" if gb else "90")),
              "cpu_seconds": int(os.getenv("SCAN_CPU_SECONDS", "240" if gb else "60")),
              "memory_bytes": int(os.getenv("SCAN_MEMORY_BYTES", str(2 << 30))),
              "daemon_memory_bytes": int(os.getenv("SCAN_DAEMON_MEMORY_BYTES", str(4 << 30 if gb else 2 << 30))),
              "startup_seconds": int(os.getenv("SCAN_STARTUP_SECONDS", "120")),
              "temp_bytes": int(os.getenv("SCAN_TEMP_BYTES", str(192 << 20)))}
    ceilings = {"max_batch_bytes": (5120 if gb else 256) << 20,
                "max_file_bytes": (1280 if gb else 64) << 20,
                "max_scan_bytes": (3072 if archive else 1536 if gb else 128) << 20,
                "max_expanded_bytes": 128 << 20, "max_members": 256, "max_depth": 3,
                "max_ratio": 100, "max_pickle_opcodes": 2000000, "max_pickle_argument": 8 << 20,
                "wall_seconds": 300 if gb else 90, "cpu_seconds": 240 if gb else 60, "memory_bytes": 2 << 30,
                "daemon_memory_bytes": (4 if gb else 2) << 30, "startup_seconds": 120, "temp_bytes": 192 << 20}
    if any(value <= 0 for value in values.values()) or any(values[key] > maximum for key, maximum in ceilings.items()):
        raise RuntimeError("scan limits exceed the fixed supported envelope")
    if values["max_scan_bytes"] < values["max_file_bytes"] or values["daemon_memory_bytes"] < values["memory_bytes"]:
        raise RuntimeError("inconsistent fixed scan limits")
    # ClamAV checks RLIMIT_FSIZE against its scan size while starting. This
    # fixed derived cap remains within the existing tmpfs/read-only sandbox.
    values["native_write_file_bytes"] = max(values["temp_bytes"], values["max_scan_bytes"])
    if archive:
        values["native_temp_bytes"] = ARCHIVE_TEMP_BYTES
    expiry = os.getenv("SCAN_RULES_EXPIRES_AT", "0")
    if not re.fullmatch(r"0|[1-9][0-9]{0,11}", expiry) or int(expiry) > 253402300799:
        raise RuntimeError("invalid trusted rules expiration epoch")
    # The trusted provisioning tool derives this absolute deadline from verified
    # signed rule metadata. Zero preserves explicit offline compatibility; it
    # does not assert rule freshness. Host UTC is part of the trusted boundary.
    values["rules_expires_at"] = int(expiry)
    # Fixed policy, never an operator knob. Both fields bind generation even
    # when the single-thread compatibility path does not need byte waves.
    values["native_wave_bytes"] = NATIVE_WAVE_BYTES
    values["native_wave_policy"] = NATIVE_WAVE_POLICY
    return values


def check_rules_expiry(limits):
    expiry = limits.get("rules_expires_at", 0)
    if expiry and time.time() >= expiry:
        raise Incomplete("rules_expired")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def stream_sha256(stream):
    """Hash every byte through a reusable bounded buffer; no digest caching."""
    h = hashlib.sha256()
    buffer = bytearray(1 << 20)
    view = memoryview(buffer)
    while True:
        count = stream.readinto(buffer)
        if type(count) is not int or not 0 <= count <= len(buffer):
            raise OSError("invalid blocking digest read")
        if count == 0:
            break
        h.update(view[:count])
    return h.hexdigest()


def file_sha(path):
    with open(path, "rb") as f:
        return stream_sha256(f)


def rule_inventory(root):
    entries = []
    for p in sorted(Path(root).iterdir()):
        if p.suffix.lower() not in RULE_EXT:
            continue
        if p.is_symlink() or not p.is_file():
            raise RuntimeError("rules must be regular immutable files")
        entries.append({"name": p.name, "size": p.stat().st_size, "sha256": file_sha(p)})
    if not entries:
        raise RuntimeError("ClamAV rules are required; no clean fallback")
    return entries


def rule_stamp(root):
    # Rules are an immutable, read-only deployment input. This cheap fence
    # detects a trusted updater accidentally changing/replacing that input;
    # each worker additionally rehashes the complete rules before and after.
    result = []
    for p in sorted(Path(root).iterdir()):
        if p.suffix.lower() in RULE_EXT:
            s = p.lstat()
            if not stat.S_ISREG(s.st_mode):
                raise Incomplete("rules_changed")
            result.append((p.name, s.st_size, s.st_mtime_ns, s.st_ino))
    return result


def engine_directory(api_socket="/run/matrix-security/scanner.sock"):
    identity = hashlib.sha256(os.fsencode(api_socket)).hexdigest()[:16]
    return Path("/tmp/matrix-clamd-" + identity)


def clamd_configuration(rules, limits, directory=None):
    directory = engine_directory() if directory is None else Path(directory)
    rules = str(Path(rules).resolve())
    if any(character in rules + str(directory) for character in "\r\n\x00"):
        raise RuntimeError("invalid trusted engine path")
    values = {"DatabaseDirectory": rules, "LocalSocket": str(directory / "engine.sock"),
              "LocalSocketMode": "600", "FixStaleSocket": "no", "Foreground": "yes",
              "SelfCheck": "0", "ConcurrentDatabaseReload": "no", "DisableCache": "yes",
              "MaxThreads": str(limits.get("native_threads", 1)),
              "MaxQueue": str(2 * limits.get("native_threads", 1)),
              "ReadTimeout": "5", "CommandReadTimeout": "5",
              "SendBufTimeout": "200", "ExitOnOOM": "yes", "LogClean": "no", "LogVerbose": "no",
              "LogSyslog": "no", "LogTime": "no", "Debug": "no", "GenerateMetadataJson": "no",
              "LeaveTemporaryFiles": "no", "MaxFileSize": str(limits["max_file_bytes"]),
              "PCREMaxFileSize": str(limits["max_file_bytes"]), "MaxScanSize": str(limits["max_scan_bytes"]),
              "MaxScanTime": str(limits["wall_seconds"] * 1000), "MaxFiles": str(limits["max_members"]),
              "MaxRecursion": str(limits["max_depth"] + 2), "AlertExceedsMax": "yes", "AlertEncrypted": "yes",
              "AlertBrokenExecutables": "yes", "AlertBrokenMedia": "yes"}
    if limits.get("native_temp_bytes"):
        values["TemporaryDirectory"] = str(native_scratch_path(directory))
    return "".join(key + " " + value + "\n" for key, value in values.items()).encode()


def create_bundle(rules, limits, backend=None, directory=None):
    backend = backend_from_env() if backend is None else backend
    if backend not in {"clamscan", "clamd"}:
        raise RuntimeError("invalid fixed ClamAV backend")
    version = subprocess.run(["/usr/local/bin/clamscan", "--version"], capture_output=True, timeout=15, check=True)
    engine = version.stdout.decode("ascii", "strict").strip()
    if not engine.startswith("ClamAV 1.4.6") or len(engine) > 256:
        raise RuntimeError("invalid ClamAV version")
    engines = {"clamav": engine, "picklescan": importlib.metadata.version("picklescan")}
    if engines["picklescan"] != "1.0.5":
        raise RuntimeError("unexpected Picklescan dependency version")
    binary = "/usr/local/sbin/clamd" if backend == "clamd" else "/usr/local/bin/clamscan"
    evidence = {"wrapper": VERSION, "source_sha256": file_sha(__file__), "engines": engines,
                "rules": rule_inventory(rules), "limits": limits, "python": sys.version.split()[0],
                "backend": backend, "profile": os.getenv("SCAN_PROFILE", "default"),
                "engine_config_sha256": hashlib.sha256(clamd_configuration(rules, limits, directory)).hexdigest(),
                "engine_binary_sha256": file_sha(binary)}
    return {"generation": hashlib.sha256(canonical(evidence)).hexdigest(), "engines": engines,
            "maxFileBytes": limits["max_file_bytes"], "maxBatchFiles": limits["max_batch_files"],
            "maxBatchBytes": limits["max_batch_bytes"], "maxPrefixBytes": MAX_PREFIX_BYTES}, evidence


def validate_artifact(value, limits):
    if not isinstance(value, dict) or set(value) != {"artifactId", "sha256", "size", "type"}:
        raise Incomplete("invalid_descriptor")
    if not isinstance(value["artifactId"], str) or not ID_RE.fullmatch(value["artifactId"]):
        raise Incomplete("invalid_artifact_id")
    if not isinstance(value["sha256"], str) or not SHA_RE.fullmatch(value["sha256"]):
        raise Incomplete("invalid_digest")
    if type(value["size"]) is not int or not 0 <= value["size"] <= limits["max_file_bytes"]:
        raise Incomplete("file_limit")
    if not isinstance(value["type"], str) or not TYPE_RE.fullmatch(value["type"]):
        raise Incomplete("invalid_analysis_context")
    return value


def validate_batch(value, limits):
    if not isinstance(value, dict) or set(value) != {"artifacts"} or not isinstance(value["artifacts"], list):
        raise Incomplete("invalid_descriptor")
    artifacts = value["artifacts"]
    if not 1 <= len(artifacts) <= limits["max_batch_files"]:
        raise Incomplete("batch_limit")
    for artifact in artifacts:
        validate_artifact(artifact, limits)
    if sum(a["size"] for a in artifacts) > limits["max_batch_bytes"]:
        raise Incomplete("batch_limit")
    if len({a["artifactId"] for a in artifacts}) != len(artifacts):
        raise Incomplete("batch_duplicate_artifact")
    return artifacts



def validate_prefix(value, limits):
    """Validate transport only; artifact parsing belongs to the bounded child."""
    if type(value) is not dict or set(value) != {"prefixBase64", "prefixSha256", "prefixBytes", "sourceSize"}:
        raise Incomplete("invalid_descriptor")
    if type(value["prefixBytes"]) is not int or not 1 <= value["prefixBytes"] <= MAX_PREFIX_BYTES:
        raise Incomplete("request_limit")
    if (type(value["sourceSize"]) is not int or
            not value["prefixBytes"] <= value["sourceSize"] <= min(limits["max_file_bytes"], limits["max_scan_bytes"])):
        raise Incomplete("file_limit")
    if type(value["prefixSha256"]) is not str or not SHA_RE.fullmatch(value["prefixSha256"]):
        raise Incomplete("invalid_digest")
    encoded = value["prefixBase64"]
    if type(encoded) is not str or len(encoded) > 4 * ((MAX_PREFIX_BYTES + 2) // 3):
        raise Incomplete("request_limit")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, UnicodeError):
        raise Incomplete("invalid_descriptor") from None
    if (len(raw) != value["prefixBytes"] or base64.b64encode(raw).decode("ascii") != encoded or
            hashlib.sha256(raw).hexdigest() != value["prefixSha256"]):
        raise Incomplete("invalid_digest")
    return value


def valid_prefix_result(value, descriptor, bundle):
    if type(value) is not dict or set(value) != {"generation", "prefixSha256", "prefixBytes", "status", "reason"}:
        return False
    return (value["generation"] == bundle["generation"] and
            value["prefixSha256"] == descriptor["prefixSha256"] and
            type(value["prefixBytes"]) is int and value["prefixBytes"] == descriptor["prefixBytes"] and
            ((value["status"] == "pending" and value["reason"] == "") or
             (value["status"] == "reject" and type(value["reason"]) is str and value["reason"] in FILE_ERROR_CODES)))


def prefix_limits(limits):
    bounded = dict(limits)
    bounded.update(wall_seconds=min(5, limits["wall_seconds"]),
                   cpu_seconds=min(2, limits["cpu_seconds"]),
                   memory_bytes=min(512 << 20, limits["memory_bytes"]),
                   daemon_memory_bytes=min(512 << 20, limits["daemon_memory_bytes"]),
                   temp_bytes=min(2 << 20, limits["temp_bytes"]),
                   native_write_file_bytes=min(2 << 20, limits["native_write_file_bytes"]))
    return bounded


def open_verified(root, artifact):
    # Open each component relative to a held directory FD with O_NOFOLLOW.
    # The returned artifact FD is then hashed and scanned without reopening.
    rootfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parent, filename = artifact["artifactId"].split("/")
        parentfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=rootfd)
        try:
            fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parentfd)
        finally:
            os.close(parentfd)
    finally:
        os.close(rootfd)
    f = os.fdopen(fd, "rb")
    try:
        info = os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size != artifact["size"]:
            raise Incomplete("snapshot_size")
        actual = stream_sha256(f)
        after = os.fstat(f.fileno())
        if ((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                or actual != artifact["sha256"]):
            raise Incomplete("snapshot_digest")
        f.seek(0)
        return f
    except BaseException:
        f.close()
        raise


def finding(engine, rule, severity, message, evidence=None):
    result = {"engine": engine, "rule": rule, "severity": severity, "message": message,
              "remediation": "Review the source and use a trusted artifact; do not load untrusted serialized objects."}
    if evidence is not None:
        result["evidence"] = evidence
    return result


def coverage_finding(code):
    if code not in FILE_ERROR_CODES:
        raise Incomplete("worker_failed_or_incomplete")
    return {"engine": "coverage", "rule": "coverage." + code, "severity": "high",
            "message": COVERAGE_MESSAGE, "remediation": COVERAGE_REMEDIATION}


def valid_worker_analysis(value, bundle):
    # Validate every member before the supervisor publishes any batch result.
    # A false completion bit is meaningful only with one fixed local failure;
    # it must never turn a global worker/protocol error into retained evidence.
    if not isinstance(value, dict) or set(value) != {"generation", "complete", "engines", "findings", "durationMs"}:
        return False
    if (value["generation"] != bundle["generation"] or value["engines"] != bundle["engines"]
            or type(value["complete"]) is not bool or type(value["durationMs"]) is not int
            or not 0 <= value["durationMs"] <= (1 << 53) - 1):
        return False
    findings = value["findings"]
    if not isinstance(findings, list) or len(findings) > 4096:
        return False
    coverage = 0
    for item in findings:
        required = {"engine", "rule", "severity", "message", "remediation"}
        if not isinstance(item, dict) or not required <= set(item) or set(item) - required - {"evidence"}:
            return False
        if any(not isinstance(item[key], str) for key in required):
            return False
        if (len(item["rule"]) > 128 or len(item["message"]) > 1024 or len(item["remediation"]) > 1024
                or item["severity"] not in {"critical", "high", "medium", "low"}):
            return False
        if item["engine"] == "coverage":
            code = item["rule"].removeprefix("coverage.")
            if code not in FILE_ERROR_CODES or item != coverage_finding(code):
                return False
            coverage += 1
        elif item["engine"] not in {"clamav", "picklescan"}:
            return False
        if "evidence" in item and not isinstance(item["evidence"], dict):
            return False
    return coverage == (0 if value["complete"] else 1)


def valid_worker_result(value, artifacts, bundle, batch=False):
    if not batch:
        return valid_worker_analysis(value, bundle)
    if not isinstance(value, dict) or set(value) != {"results"} or not isinstance(value["results"], list):
        return False
    if len(value["results"]) != len(artifacts):
        return False
    return all(isinstance(item, dict) and set(item) == {"artifactId", "analysis"}
               and item["artifactId"] == artifact["artifactId"]
               and valid_worker_analysis(item["analysis"], bundle)
               for item, artifact in zip(value["results"], artifacts))


def bounded_copy(source, target, maximum):
    size = 0
    while True:
        block = source.read(min(128 << 10, maximum - size + 1))
        if not block:
            return size
        size += len(block)
        if size > maximum:
            raise Incomplete("expanded_bytes_limit")
        target.write(block)


class _WriteMap:
    """Private exact builtin-map token; never an artifact-created object."""
    __slots__ = ()


class _WriteGlobal:
    __slots__ = ("name",)

    def __init__(self, module, symbol):
        self.name = (module, symbol)


class ContainerWriteTypes:
    """Bounded map-write type proof, independent of threat classification.

    Only DICT/EMPTY_DICT and an exact collections.OrderedDict() with empty tuple
    arguments establish a map. Other constructor/reducer results stay unknown.
    SETITEM/S must target that proven map, including through memo aliases. No
    import, callable, object constructor, reducer or deserializer is invoked.
    This is not a proof of arbitrary loader semantics or model loadability.
    """
    MARK = object()
    UNKNOWN = object()
    NON_MAP = object()
    EMPTY_TUPLE = object()
    STRING_OPS = frozenset({"UNICODE", "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8"})
    PUT_OPS = frozenset({"PUT", "BINPUT", "LONG_BINPUT"})
    GET_OPS = frozenset({"GET", "BINGET", "LONG_BINGET"})

    def __init__(self, max_slots):
        self.max_slots = max_slots
        self.stack, self.marks, self.memo = [], [], {}

    def slot_count(self):
        return len(self.stack) + len(self.memo)

    def budget(self):
        if self.slot_count() > self.max_slots:
            raise Incomplete("pickle_symbol_budget")

    def need(self, count):
        if count < 1 or len(self.stack) < count or any(v is self.MARK for v in self.stack[-count:]):
            raise Incomplete("invalid_serialization")

    def push(self, value):
        if value is self.MARK:
            self.marks.append(len(self.stack))
        self.stack.append(value)
        self.budget()

    def drop(self, start):
        del self.stack[start:]
        while self.marks and self.marks[-1] >= start:
            self.marks.pop()

    def marked(self):
        if not self.marks:
            raise Incomplete("invalid_serialization")
        return self.marks[-1]

    def map_target(self, target):
        if type(target) is not _WriteMap:
            raise Incomplete("unsupported_container_or_serialization" if target is self.UNKNOWN
                             else "invalid_serialization")

    def next_stream(self):
        self.stack.clear()
        self.marks.clear()

    def apply(self, opcode, argument):
        name = opcode.name
        if name in self.STRING_OPS:
            if type(argument) is not str:
                raise Incomplete("invalid_serialization")
            self.push(argument)
        elif name == "MARK":
            self.push(self.MARK)
        elif name == "POP":
            if not self.stack:
                raise Incomplete("invalid_serialization")
            self.drop(len(self.stack) - 1)
        elif name == "POP_MARK":
            self.drop(self.marked())
        elif name == "DUP":
            self.need(1)
            self.push(self.stack[-1])
        elif name == "MEMOIZE" or name in self.PUT_OPS:
            self.need(1)
            key = len(self.memo) if name == "MEMOIZE" else argument
            if type(key) is not int or not 0 <= key <= self.max_slots:
                raise Incomplete("pickle_symbol_budget")
            self.memo[key] = self.stack[-1]
            self.budget()
        elif name in self.GET_OPS:
            if type(argument) is not int or argument not in self.memo:
                raise Incomplete("invalid_serialization")
            self.push(self.memo[argument])
        elif name == "EMPTY_DICT":
            self.push(_WriteMap())
        elif name == "DICT":
            mark = self.marked()
            if (len(self.stack) - mark - 1) % 2:
                raise Incomplete("invalid_serialization")
            self.drop(mark)
            self.push(_WriteMap())
        elif name == "SETITEM":
            self.need(3)
            self.map_target(self.stack[-3])
            self.drop(len(self.stack) - 2)
        elif name == "SETITEMS":
            mark = self.marked()
            if mark < 1 or (len(self.stack) - mark - 1) % 2:
                raise Incomplete("invalid_serialization")
            self.map_target(self.stack[mark - 1])
            self.drop(mark)
        elif name == "EMPTY_TUPLE":
            self.push(self.EMPTY_TUPLE)
        elif name == "TUPLE":
            mark = self.marked()
            value = self.EMPTY_TUPLE if len(self.stack) == mark + 1 else self.NON_MAP
            self.drop(mark)
            self.push(value)
        elif name == "GLOBAL":
            parts = argument.split(" ", 1)
            if len(parts) != 2:
                raise Incomplete("invalid_serialization")
            self.push(_WriteGlobal(*parts))
        elif name == "STACK_GLOBAL":
            self.need(2)
            module, symbol = self.stack[-2:]
            if type(module) is not str or type(symbol) is not str:
                raise Incomplete("invalid_serialization")
            self.drop(len(self.stack) - 2)
            self.push(_WriteGlobal(module, symbol))
        elif name == "REDUCE":
            self.need(2)
            target, args = self.stack[-2:]
            proven_map = (type(target) is _WriteGlobal and target.name == ("collections", "OrderedDict")
                          and args is self.EMPTY_TUPLE)
            self.drop(len(self.stack) - 2)
            self.push(_WriteMap() if proven_map else self.UNKNOWN)
        elif name == "BUILD":
            # Preserve the exact target identity through state application. The
            # existing threat/finite-profile checks still validate state. BUILD
            # never upgrades an unknown constructor to a proven builtin map.
            self.need(2)
            self.drop(len(self.stack) - 1)
        else:
            # Trusted opcode metadata supplies stack effects only. No inferred
            # dynamic result can establish a map. Primitive/collection results
            # are non-map; constructor/persistent results are unknown.
            before = opcode.stack_before
            if pickletools.markobject in before:
                mark = self.marked()
                if pickletools.stackslice not in before:
                    raise Incomplete("invalid_serialization")
                prefix = before.index(pickletools.markobject)
                minimum = before.index(pickletools.stackslice) - prefix - 1
                if mark < prefix or len(self.stack) - mark - 1 < minimum:
                    raise Incomplete("invalid_serialization")
                if any(v is self.MARK for v in self.stack[mark - prefix:mark]):
                    raise Incomplete("invalid_serialization")
                self.drop(mark - prefix)
            elif pickletools.stackslice in before:
                raise Incomplete("invalid_serialization")
            elif before:
                self.need(len(before))
                self.drop(len(self.stack) - len(before))
            value = self.UNKNOWN if name in {"NEWOBJ", "NEWOBJ_EX", "INST", "OBJ", "BINPERSID", "PERSID"} else self.NON_MAP
            for item in opcode.stack_after:
                if item is pickletools.markobject or item is pickletools.stackslice:
                    raise Incomplete("invalid_serialization")
                self.push(value)


class SymbolicReferences:
    """Bounded literal-string/memo analysis, never object construction.

    Stack values are literal Unicode strings, opaque values, or MARK. Containers
    and REDUCE/BUILD results are opaque; no callable is invoked. A STACK_GLOBAL
    that cannot be derived from literal strings is incomplete, never clean.
    """
    OPAQUE = object()
    MARK = object()
    STRING_OPS = frozenset({"UNICODE", "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8"})
    PUT_OPS = frozenset({"PUT", "BINPUT", "LONG_BINPUT"})
    GET_OPS = frozenset({"GET", "BINGET", "LONG_BINGET"})

    def __init__(self, max_slots):
        self.max_slots = max_slots
        self.stack = []
        self.marks = []
        self.memo = {}
        self.globals = set()

    def budget(self):
        if self.slot_count() > self.max_slots:
            raise Incomplete("pickle_symbol_budget")

    def slot_count(self):
        return len(self.stack) + len(self.memo) + len(self.globals)

    def push(self, value):
        if value is self.MARK:
            self.marks.append(len(self.stack))
        self.stack.append(value)
        self.budget()

    def require(self, count):
        if len(self.stack) < count or any(value is self.MARK for value in self.stack[-count:]):
            raise Incomplete("pickle_symbol_analysis_incomplete")

    def drop(self, start):
        del self.stack[start:]
        while self.marks and self.marks[-1] >= start:
            self.marks.pop()

    def next_stream(self):
        # This instance models one Unpickler performing multiple load() calls.
        # StaticInspector separately tracks a fresh-memo interpretation, since
        # artifact bytes cannot prove which consumer semantics will be used.
        self.stack.clear()
        self.marks.clear()

    def apply(self, opcode, argument):
        name = opcode.name
        matched = None
        if name in self.STRING_OPS:
            if type(argument) is not str:
                raise Incomplete("pickle_symbol_analysis_incomplete")
            self.push(argument)
        elif name == "MARK":
            self.push(self.MARK)
        elif name == "POP":
            if not self.stack:
                raise Incomplete("pickle_symbol_analysis_incomplete")
            self.drop(len(self.stack) - 1)
        elif name == "DUP":
            self.require(1)
            self.push(self.stack[-1])
        elif name == "MEMOIZE" or name in self.PUT_OPS:
            self.require(1)
            key = len(self.memo) if name == "MEMOIZE" else argument
            if type(key) is not int or key < 0:
                raise Incomplete("pickle_symbol_analysis_incomplete")
            self.memo[key] = self.stack[-1]
            self.budget()
        elif name in self.GET_OPS:
            if type(argument) is not int or argument < 0 or argument not in self.memo:
                raise Incomplete("pickle_symbol_analysis_incomplete")
            self.push(self.memo[argument])
        elif name == "STACK_GLOBAL":
            self.require(2)
            module, symbol = self.stack[-2:]
            if type(module) is not str or type(symbol) is not str:
                raise Incomplete("pickle_symbol_analysis_incomplete")
            matched = (module, symbol)
            self.drop(len(self.stack) - 2)
            self.push(self.OPAQUE)
        else:
            # Trusted pickletools metadata describes stack effects, not code
            # execution. Preserve no inferred result of a dynamic operation.
            before = opcode.stack_before
            if pickletools.markobject in before:
                if not self.marks or pickletools.stackslice not in before:
                    raise Incomplete("pickle_symbol_analysis_incomplete")
                mark_at = self.marks[-1]
                prefix = before.index(pickletools.markobject)
                minimum_tail = before.index(pickletools.stackslice) - prefix - 1
                if mark_at < prefix or len(self.stack) - mark_at - 1 < minimum_tail:
                    raise Incomplete("pickle_symbol_analysis_incomplete")
                if any(value is self.MARK for value in self.stack[mark_at - prefix:mark_at]):
                    raise Incomplete("pickle_symbol_analysis_incomplete")
                self.drop(mark_at - prefix)
            elif pickletools.stackslice in before:
                raise Incomplete("pickle_symbol_analysis_incomplete")
            elif before:
                self.require(len(before))
                self.drop(len(self.stack) - len(before))
            for value in opcode.stack_after:
                if value is pickletools.markobject or value is pickletools.stackslice:
                    raise Incomplete("pickle_symbol_analysis_incomplete")
                self.push(self.OPAQUE)
            if name in {"GLOBAL", "INST"}:
                pieces = argument.split(" ", 1)
                if len(pieces) != 2:
                    raise Incomplete("pickle_symbol_analysis_incomplete")
                matched = tuple(pieces)
        if matched is not None:
            self.globals.add(matched)
            self.budget()
        return matched


"""Prove a narrow torch.save ZIP typed-storage layout without deserialization.

This module never unpickles, imports torch, constructs tensors, or scans malware.
The caller MUST retain whole-file AV, held-FD pre/post SHA, worker budgets and
generation binding. Call only for a top-level ZIP. The callback must run the
existing complete pickletools/SymbolicReferences/Picklescan inspection.
"""
import io
import pickletools
import re
import stat
import struct
import zipfile
import zlib

FORMAT_REVISION = "torch-zip-typed-cpu-protocol2-parameter-layout-4"
MAX_METADATA_BYTES = 8 << 20
MAX_DIRECTORY_BYTES = 4 << 20
MAX_TRACKER_SLOTS = 65536
MAX_EXTRA_BYTES = 4096
CHUNK_BYTES = 128 << 10
STORAGE_WIDTHS = {
    "ByteStorage": 1, "CharStorage": 1, "BoolStorage": 1,
    "ShortStorage": 2, "HalfStorage": 2, "BFloat16Storage": 2,
    "IntStorage": 4, "FloatStorage": 4,
    "LongStorage": 8, "DoubleStorage": 8,
}
LAYOUT_GLOBALS = {("torch", name) for name in STORAGE_WIDTHS} | {
    ("collections", "OrderedDict"), ("torch._utils", "_rebuild_tensor_v2"),
}
KEY_RE = re.compile(r"(?:0|[1-9][0-9]{0,19})\Z")
ROOT_RE = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
METADATA = {"data.pkl", "version", "byteorder", ".data/serialization_id",
            ".format_version", ".storage_alignment"}


class LayoutError(Exception):
    """Only an existing fixed scanner code; no artifact-controlled text."""
    def __init__(self, code="invalid_serialization"):
        self.code = code
        super().__init__(code)


def require(value, code="invalid_serialization"):
    if not value:
        raise LayoutError(code)


def read_at(data, offset, count, size):
    require(type(offset) is int and type(count) is int and
            0 <= offset <= size and 0 <= count <= size - offset)
    data.seek(offset)
    value = data.read(count)
    require(len(value) == count)
    return value


def extras(raw, allowed):
    result, pos = {}, 0
    require(len(raw) <= MAX_EXTRA_BYTES)
    while pos < len(raw):
        require(len(raw) - pos >= 4)
        tag, count = struct.unpack_from("<HH", raw, pos)
        pos += 4
        require(tag in allowed and tag not in result and count <= len(raw) - pos)
        result[tag] = raw[pos:pos + count]
        pos += count
    return result


def directory_bytes(data, limits, exact_end):
    """Bound directory allocation before constructing Python ZipInfo objects."""
    data.seek(0, io.SEEK_END)
    size = data.tell()
    require(22 <= size <= limits["max_file_bytes"], "file_limit")
    tail_at = max(0, size - 65557)
    tail = read_at(data, tail_at, size - tail_at, size)
    relative = tail.rfind(b"PK\x05\x06")
    require(relative >= 0)
    eocd_at = tail_at + relative
    end = struct.unpack("<4s4H2IH", read_at(data, eocd_at, 22, size))
    require(end[0] == b"PK\x05\x06" and end[1] == end[2] == 0)
    if exact_end:
        require(eocd_at + 22 == size and end[7] == 0)
    count_disk, count, cd_size, cd_at = end[3:7]
    require(count_disk == count)
    after_cd = eocd_at
    if eocd_at >= 20 and read_at(data, eocd_at - 20, 4, size) == b"PK\x06\x07":
        locator = struct.unpack("<4sIQI", read_at(data, eocd_at - 20, 20, size))
        require(locator[1] == 0 and locator[3] == 1)
        zip64_at = locator[2]
        require(zip64_at + 56 == eocd_at - 20)
        record = struct.unpack("<4sQ2H2I4Q", read_at(data, zip64_at, 56, size))
        require(record[0] == b"PK\x06\x06" and record[1] == 44 and
                record[4] == record[5] == 0 and record[6] == record[7])
        count64, size64, at64 = record[7:10]
        require(count in {0xFFFF, count64} and count_disk in {0xFFFF, count64} and
                cd_size in {0xFFFFFFFF, size64} and cd_at in {0xFFFFFFFF, at64})
        count, cd_size, cd_at = count64, size64, at64
        after_cd = zip64_at
    else:
        require(count != 0xFFFF and cd_size != 0xFFFFFFFF and cd_at != 0xFFFFFFFF)
    require(0 <= count <= limits["max_members"], "archive_member_limit")
    require(cd_size <= MAX_DIRECTORY_BYTES, "expanded_bytes_limit")
    require(cd_at + cd_size == after_cd and cd_at >= 0)
    return read_at(data, cd_at, cd_size, size), cd_at, size, count


def bounded_zip_names(data, limits):
    """Validate every directory record before allocating ZipInfo objects.

    The EOCD count alone is untrusted: the directory must contain exactly that
    many complete records. This preflight is also used for nested archives,
    where the remaining global entry budget may be smaller than max_members.
    It is a resource fence, not proof of member content or a clean verdict.
    """
    directory, _, _, count = directory_bytes(data, limits, False)
    pos, names = 0, []
    for _ in range(count):
        require(len(directory) - pos >= 46)
        head = struct.unpack_from("<4s6H3I5H2I", directory, pos)
        require(head[0] == b"PK\x01\x02")
        nlen, xlen, clen = head[10:13]
        require(pos + 46 + nlen + xlen + clen <= len(directory))
        name = directory[pos + 46:pos + 46 + nlen]
        names.append(name)
        pos += 46 + nlen + xlen + clen
    require(pos == len(directory))
    return names


def selects_protocol2_framework(data, limits):
    """Recognition only; False always means inspect every member generically.

    A plain ZIP containing data.pkl is not a framework layout. Other pickle
    protocols retain the old full-member inspector and its expansion budget.
    No storage bytes can be exempted merely because this probe returns True.
    """
    names = bounded_zip_names(data, limits)
    unique_names = set(names)
    candidates = [name for name in names if len(name.split(b"/")) == 2 and
                  name.endswith(b"/data.pkl") and
                  name[:-8] + b"version" in unique_names]
    if not candidates:
        return False
    # An ambiguous candidate must enter the strict rejection path.
    if len(candidates) != 1 or len(names) != len(unique_names):
        return True
    try:
        candidate = candidates[0].decode("ascii")
    except UnicodeError:
        return True
    data.seek(0)
    with zipfile.ZipFile(data) as archive:
        info = archive.getinfo(candidate)
        require(not info.flag_bits & 1, "encrypted_archive")
        # Two-byte bounded selection is followed by either the full generic
        # path, or strict physical layout, full metadata CRC and threat scan.
        with archive.open(info) as stream:
            return stream.read(2) == b"\x80\x02"


def zip_directory(data, limits):
    """Classic-size members, with optional mandatory-consistent ZIP64 footer.

    The file ceiling is below 4 GiB, so per-entry ZIP64 size/offset extensions
    are outside this first subset. Real PyTorch ZIP64 *end records* are handled.
    No prefix, gaps, overlapping members, comments or bytes after EOCD.
    """
    directory, cd_at, size, count = directory_bytes(data, limits, True)
    require(count > 0)
    entries, names, offsets, pos = [], set(), set(), 0
    for index in range(count):
        require(len(directory) - pos >= 46)
        head = struct.unpack_from("<4s6H3I5H2I", directory, pos)
        require(head[0] == b"PK\x01\x02")
        made, needed, flags, method, mtime, mdate = head[1:7]
        crc, packed, unpacked = head[7:10]
        nlen, xlen, clen, disk, internal, external, offset = head[10:17]
        require(nlen > 0 and nlen <= 256 and xlen <= MAX_EXTRA_BYTES and clen == 0 and disk == 0)
        require(pos + 46 + nlen + xlen <= len(directory))
        name_raw = directory[pos + 46:pos + 46 + nlen]
        extra_raw = directory[pos + 46 + nlen:pos + 46 + nlen + xlen]
        pos += 46 + nlen + xlen
        # Under the <4 GiB envelope the supported writer needs no entry ZIP64.
        require(packed != 0xFFFFFFFF and unpacked != 0xFFFFFFFF and offset != 0xFFFFFFFF,
                "unsupported_container_or_serialization")
        require(not extra_raw, "unsupported_container_or_serialization")
        try:
            name = name_raw.decode("ascii")
        except UnicodeError:
            raise LayoutError("unsupported_container_or_serialization") from None
        require(name not in names, "duplicate_archive_member")
        require(offset not in offsets)
        names.add(name); offsets.add(offset)
        require(not flags & 1, "encrypted_archive")
        require(flags & ~0x0808 == 0 and method == zipfile.ZIP_STORED,
                "unsupported_container_or_serialization")
        require(packed == unpacked and unpacked <= limits["max_file_bytes"], "archive_member_size")
        mode = external >> 16
        require(not stat.S_ISLNK(mode), "archive_symlink")
        require(stat.S_IFMT(mode) in {0, stat.S_IFREG} and not name.endswith("/"),
                "archive_link_or_special_file")
        parts = name.split("/")
        require(all(part and part not in {".", ".."} for part in parts) and
                not any(ch in name for ch in "\\\x00:") and not name.startswith("/"))
        entries.append({"index": index, "name": name, "nameRaw": name_raw,
                        "offset": offset, "needed": needed, "flags": flags,
                        "method": method, "mtime": mtime, "mdate": mdate,
                        "crc": crc, "size": unpacked})
    require(pos == len(directory))
    ordered = sorted(entries, key=lambda item: item["offset"])
    require(ordered[0]["offset"] == 0)
    for index, entry in enumerate(ordered):
        boundary = ordered[index + 1]["offset"] if index + 1 < len(ordered) else cd_at
        head = struct.unpack("<4s5H3I2H", read_at(data, entry["offset"], 30, size))
        signature, needed, flags, method, mtime, mdate, crc, packed, unpacked, nlen, xlen = head
        require(signature == b"PK\x03\x04" and
                (needed, flags, method, mtime, mdate) ==
                tuple(entry[key] for key in ("needed", "flags", "method", "mtime", "mdate")))
        require(nlen == len(entry["nameRaw"]) and xlen <= MAX_EXTRA_BYTES)
        raw = read_at(data, entry["offset"] + 30, nlen + xlen, size)
        require(raw[:nlen] == entry["nameRaw"])
        local_extra = extras(raw[nlen:], {0x4246})
        if 0x4246 in local_extra:
            padding = local_extra[0x4246]
            require(len(padding) < 64 and padding == b"Z" * len(padding))
        payload_at = entry["offset"] + 30 + nlen + xlen
        if 0x4246 in local_extra:
            require(payload_at % 64 == 0)
        payload_end = payload_at + entry["size"]
        require(payload_end <= boundary)
        if flags & 8:
            require(crc in {0, entry["crc"]} and packed in {0, entry["size"]} and
                    unpacked in {0, entry["size"]})
            descriptor_size = boundary - payload_end
            require(descriptor_size in {12, 16, 20, 24})
            descriptor = read_at(data, payload_end, descriptor_size, size)
            if descriptor_size in {16, 24}:
                require(descriptor[:4] == b"PK\x07\x08")
                descriptor = descriptor[4:]
            if len(descriptor) == 12:
                observed = struct.unpack("<III", descriptor)
            else:
                require(needed >= 45)
                observed = struct.unpack("<IQQ", descriptor)
            require(observed == (entry["crc"], entry["size"], entry["size"]))
        else:
            require((crc, packed, unpacked) == (entry["crc"], entry["size"], entry["size"]) and
                    payload_end == boundary)
        entry["payloadOffset"] = payload_at
    return entries, size


class GlobalToken:
    __slots__ = ("module", "symbol")
    def __init__(self, module, symbol):
        self.module, self.symbol = module, symbol


class StorageReferences:
    """Literal-only PID tuple observer; not a replacement threat analyzer.

    REDUCE/BUILD and mutable containers stay opaque. Immutable tuple references
    are retained only at arity <=8. No recursively reconstructed object graph.
    """
    OPAQUE = object()
    MARK = object()

    def __init__(self, limits):
        self.limits = limits
        self.stack, self.marks, self.memo, self.storages = [], [], {}, {}
        self.max_slots = min(MAX_TRACKER_SLOTS, limits["max_pickle_opcodes"])

    def budget(self):
        require(len(self.stack) + len(self.memo) + len(self.storages) <= self.max_slots,
                "pickle_symbol_budget")

    def push(self, value):
        if value is self.MARK:
            self.marks.append(len(self.stack))
        self.stack.append(value); self.budget()

    def need(self, count):
        require(len(self.stack) >= count and all(v is not self.MARK for v in self.stack[-count:]))

    def drop(self, start):
        del self.stack[start:]
        while self.marks and self.marks[-1] >= start:
            self.marks.pop()

    def pid(self, value):
        require(type(value) is tuple and len(value) == 5)
        tag, kind, key, location, elements = value
        require(tag == "storage" and isinstance(kind, GlobalToken) and
                kind.module == "torch" and kind.symbol in STORAGE_WIDTHS and
                type(key) is str and KEY_RE.fullmatch(key) and location == "cpu",
                "unsupported_container_or_serialization")
        require(type(elements) is int and 0 <= elements <= (1 << 64) - 1)
        width = STORAGE_WIDTHS[kind.symbol]
        require(elements <= self.limits["max_file_bytes"] // width, "archive_member_size")
        spec = (kind.module, kind.symbol, location, elements, elements * width)
        require(key not in self.storages or self.storages[key] == spec)
        self.storages[key] = spec
        require(len(self.storages) <= self.limits["max_members"], "archive_member_limit")
        self.budget()

    def apply(self, opcode, argument):
        name = opcode.name
        if name in {"UNICODE", "BINUNICODE"}:
            self.push(argument if type(argument) is str and len(argument) <= 1024 else self.OPAQUE)
        elif name in {"INT", "BININT", "BININT1", "BININT2", "LONG", "LONG1", "LONG4"}:
            self.push(argument if type(argument) is int else self.OPAQUE)
        elif name == "NONE":
            self.push(None)
        elif name in {"NEWTRUE", "NEWFALSE"}:
            self.push(name == "NEWTRUE")
        elif name == "GLOBAL":
            parts = argument.split(" ", 1)
            require(len(parts) == 2)
            # Narrow layout support, never a threat-classifier allowlist. The
            # complete existing threat callback has already run before parse.
            require(tuple(parts) in LAYOUT_GLOBALS, "unsupported_container_or_serialization")
            self.push(GlobalToken(*parts))
        elif name == "MARK":
            self.push(self.MARK)
        elif name == "POP":
            require(self.stack); self.drop(len(self.stack) - 1)
        elif name == "DUP":
            self.need(1); self.push(self.stack[-1])
        elif name in {"PUT", "BINPUT", "LONG_BINPUT"}:
            self.need(1)
            require(type(argument) is int and 0 <= argument <= self.limits["max_pickle_opcodes"])
            self.memo[argument] = self.stack[-1]; self.budget()
        elif name in {"GET", "BINGET", "LONG_BINGET"}:
            require(type(argument) is int and argument in self.memo)
            self.push(self.memo[argument])
        elif name == "EMPTY_TUPLE":
            self.push(())
        elif name == "TUPLE":
            require(self.marks)
            start = self.marks[-1]
            values = tuple(self.stack[start + 1:]) if len(self.stack) - start <= 9 else self.OPAQUE
            self.drop(start); self.push(values)
        elif name in {"TUPLE1", "TUPLE2", "TUPLE3"}:
            count = int(name[-1]); self.need(count)
            values = tuple(self.stack[-count:])
            self.drop(len(self.stack) - count); self.push(values)
        elif name == "BINPERSID":
            self.need(1); self.pid(self.stack[-1])
            self.drop(len(self.stack) - 1); self.push(self.OPAQUE)
        elif name in {"PERSID", "EXT1", "EXT2", "EXT4"}:
            raise LayoutError("unsupported_container_or_serialization")
        else:
            before = opcode.stack_before
            if pickletools.markobject in before:
                require(self.marks and pickletools.stackslice in before)
                start = self.marks[-1]
                prefix = before.index(pickletools.markobject)
                tail = before.index(pickletools.stackslice) - prefix - 1
                require(start >= prefix and len(self.stack) - start - 1 >= tail and
                        all(v is not self.MARK for v in self.stack[start - prefix:start]))
                self.drop(start - prefix)
            elif pickletools.stackslice in before:
                raise LayoutError()
            elif before:
                self.need(len(before)); self.drop(len(self.stack) - len(before))
            for value in opcode.stack_after:
                require(value is not pickletools.markobject and value is not pickletools.stackslice)
                self.push(self.OPAQUE)

    def parse(self, raw):
        require(raw[:2] == b"\x80\x02", "unsupported_container_or_serialization")
        stream = io.BytesIO(raw)
        stopped = False
        for count, (opcode, argument, offset) in enumerate(pickletools.genops(stream), 1):
            require(count <= self.limits["max_pickle_opcodes"], "pickle_opcode_limit")
            require(opcode.proto <= 2, "unsupported_container_or_serialization")
            if opcode.name == "PROTO":
                require(offset == 0 and argument == 2)
            if isinstance(argument, (str, bytes)):
                require(len(argument) <= self.limits["max_pickle_argument"], "pickle_argument_limit")
            if opcode.name == "STOP":
                require(len(self.stack) == 1 and not self.marks)
                stopped = True
            self.apply(opcode, argument)
        require(stopped and stream.tell() == len(raw))
        return self.storages


def read_member(archive, info, maximum, retain):
    require(info.file_size <= maximum, "expanded_bytes_limit")
    count, crc, chunks = 0, 0, []
    with archive.open(info) as source:
        while True:
            block = source.read(min(CHUNK_BYTES, maximum - count + 1))
            if not block:
                break
            count += len(block)
            require(count <= maximum, "expanded_bytes_limit")
            crc = zlib.crc32(block, crc)
            if retain:
                chunks.append(block)
    require(count == info.file_size and crc & 0xFFFFFFFF == info.CRC, "archive_member_size")
    return b"".join(chunks) if retain else count


def verify_framework_zip(data, inspect_pickle_callback, limits):
    """Return counters on proof, None for the full generic path; otherwise raise.

    Callback signature: callback(BytesIO, original_member_index, full_name).
    It MUST invoke the existing metadata threat inspector; callback exceptions
    propagate and existing findings remain owned by the caller. Once a same-root
    protocol-2 data.pkl/version candidate is selected, proof failures
    MUST NOT fall back to generic success. Other protocols never skip storage.
    LayoutError codes are mapped to the existing scanner Incomplete.
    No claim is made about model accuracy, tensor shape validity or loadability.
    """
    # Preflight is bounded even if a hostile directory declares millions of
    # entries. Returning None retains full inspection; recognition is not acceptance.
    if not selects_protocol2_framework(data, limits):
        return None
    entries, size = zip_directory(data, limits)
    data.seek(0)
    with zipfile.ZipFile(data) as archive:
        infos = archive.infolist()
        candidates = [i for i in infos if i.filename.split("/")[-1] == "data.pkl"]
        require(len(infos) == len(entries))
        for info, entry in zip(infos, entries):
            require((info.filename, info.header_offset, info.file_size, info.compress_size,
                     info.CRC, info.flag_bits, info.compress_type) ==
                    (entry["name"], entry["offset"], entry["size"], entry["size"],
                     entry["crc"], entry["flags"], entry["method"]))
        require(len(candidates) == 1)
        parts = candidates[0].filename.split("/")
        require(len(parts) == 2 and ROOT_RE.fullmatch(parts[0]) and parts[0] not in {".", ".."})
        root = parts[0] + "/"
        relative = {}
        for index, info in enumerate(infos):
            require(info.filename.startswith(root))
            relative[info.filename[len(root):]] = (index, info)
        require({"data.pkl", "version"} <= set(relative),
                "unsupported_container_or_serialization")
        metadata_size = sum(info.file_size for name, (_, info) in relative.items() if name in METADATA)
        require(metadata_size <= min(MAX_METADATA_BYTES, limits["max_expanded_bytes"]), "expanded_bytes_limit")
        index, pickle_info = relative["data.pkl"]
        raw = read_member(archive, pickle_info, MAX_METADATA_BYTES, True)
        # Establish threat evidence before a later typed-layout failure.
        context = _ZipParameterContext(raw, index, pickle_info.filename, limits, _ZIP_PARAMETER_SEAL)
        metadata_stream = io.BytesIO(raw)
        context.stream = metadata_stream
        metadata_stream._zip_parameter_context = context
        inspect_pickle_callback(metadata_stream, index, pickle_info.filename)
        raw_members = {}
        for name, (index, info) in relative.items():
            if name in METADATA:
                continue
            require(name.startswith("data/") and KEY_RE.fullmatch(name[5:]),
                    "unsupported_container_or_serialization")
            raw_members[name[5:]] = info
        specs = context.specs if context.specs is not None else StorageReferences(limits).parse(raw)
        require(set(specs) == set(raw_members))
        # Older writers omit byteorder (added in PyTorch 2.1). Storage stays
        # opaque numeric bytes: all PID, exact-member, size and CRC proofs apply.
        # When present, byteorder must still be little; no value decoding or
        # cross-endian numeric equivalence is claimed for an absent marker.
        fixed = {"version": b"3\n", "byteorder": b"little", ".format_version": b"1",
                 ".storage_alignment": b"64"}
        require((".format_version" in relative) == (".storage_alignment" in relative),
                "unsupported_container_or_serialization")
        for name, (_, info) in relative.items():
            if name not in METADATA or name == "data.pkl":
                continue
            value = read_member(archive, info, 256, True)
            if name == ".data/serialization_id":
                require(re.fullmatch(b"[0-9]{40}", value), "unsupported_container_or_serialization")
            else:
                require(value == fixed[name], "unsupported_container_or_serialization")
        raw_bytes = sum(spec[-1] for spec in specs.values())
        require(raw_bytes <= min(limits["max_file_bytes"], limits["max_scan_bytes"]), "expanded_bytes_limit")
        for key, info in raw_members.items():
            expected = specs[key][-1]
            require(info.file_size == expected, "archive_member_size")
            read_member(archive, info, expected, False)
        return {"formatRevision": FORMAT_REVISION, "metadataBytes": metadata_size,
                "storageBytes": raw_bytes, "storageCount": len(specs),
                "memberCount": len(infos), "containerBytes": size,
                "allStorageCRCsVerified": True, "modelDeserialized": False}


def known_dangerous_reference(symbol):
    # Only concrete references covered by the pinned scanner's known rules.
    # Its unknown-placeholder heuristic is not an early evidence source.
    if not isinstance(symbol, tuple) or len(symbol) != 2 or not all(type(x) is str for x in symbol):
        return False
    from picklescan.scanner import _unsafe_globals, _build_scan_result_from_raw_globals, SafetyLevel
    module, name = symbol
    rule = _unsafe_globals.get(module)
    if rule is None and "." in module:
        parts = module.split(".")
        for i in range(1, len(parts)):
            if _unsafe_globals.get(".".join(parts[:i])) == "*":
                rule = "*"
                break
    if rule is None or not (rule == "*" or name in rule):
        return False
    classified = _build_scan_result_from_raw_globals({symbol}, "artifact", strict=False)
    return len(classified.globals) == 1 and classified.globals[0].safety == SafetyLevel.Dangerous


"""Uninstalled numeric-NPY proposal; never import numpy or deserialize objects.

The caller must keep whole-file AV, held-FD pre/post SHA, outer resource limits
and all ZIP/NPZ CRC, expansion, ratio and temporary-storage checks unchanged.
Object arrays deliberately remain unsupported. This module grants no direct
admission decision and must be source-bound into any new scanner generation.
"""
import ast
import io

NPY_FORMAT_REVISION = "numpy-numeric-literal-header-proposal-1"
NPY_HEADER_MAX = 10240
NPY_AST_MAX = 256
NPY_DIMS_MAX = 64
NPY_DIM_MAX = (1 << 63) - 1
NPY_DTYPES = {"|b1": 1, "|i1": 1, "|u1": 1}
for _order in ("<", ">", "="):
    for _kind, _widths in (("i", (2, 4, 8)), ("u", (2, 4, 8)),
                           ("f", (2, 4, 8)), ("c", (8, 16))):
        for _width in _widths:
            NPY_DTYPES[_order + _kind + str(_width)] = _width


class NumpyLayoutError(Exception):
    def __init__(self, code="invalid_serialization"):
        self.code = code
        super().__init__(code)


def npy_require(value, code="invalid_serialization"):
    if not value:
        raise NumpyLayoutError(code)


def npy_header_literals(raw):
    # One printable ASCII literal dictionary; UTF-8 v3 numeric headers use the
    # same subset. No comments, second expression, call, unpacking or evaluator.
    npy_require(raw.endswith(b"\n") and len(raw) <= NPY_HEADER_MAX)
    body = raw[:-1].rstrip(b" ")
    npy_require(body and body[:1] == b"{" and body[-1:] == b"}" and
                all(0x20 <= value <= 0x7E for value in body))
    try:
        expression = ast.parse(body.decode("ascii"), mode="eval")
    except (SyntaxError, ValueError, RecursionError):
        raise NumpyLayoutError() from None
    tree = expression.body
    npy_require(isinstance(tree, ast.Dict) and tree.lineno == tree.end_lineno == 1 and
                tree.col_offset == 0 and tree.end_col_offset == len(body))
    npy_require(sum(1 for _ in ast.walk(expression)) <= NPY_AST_MAX,
                "numpy_serialization_not_supported")
    npy_require(len(tree.keys) == len(tree.values) == 3)
    result = {}
    for key, value in zip(tree.keys, tree.values):
        npy_require(isinstance(key, ast.Constant) and type(key.value) is str and
                    key.value in {"descr", "fortran_order", "shape"} and key.value not in result)
        result[key.value] = value
    npy_require(set(result) == {"descr", "fortran_order", "shape"})
    descr, order, shape = (result[k] for k in ("descr", "fortran_order", "shape"))
    # Lists/dicts/subarray/structured/object descriptors cannot reach a raw
    # numeric exemption, even if the header itself is a valid Python literal.
    npy_require(isinstance(descr, ast.Constant) and type(descr.value) is str and
                descr.value in NPY_DTYPES, "numpy_serialization_not_supported")
    npy_require(isinstance(order, ast.Constant) and type(order.value) is bool)
    npy_require(isinstance(shape, ast.Tuple) and len(shape.elts) <= NPY_DIMS_MAX,
                "numpy_serialization_not_supported")
    dimensions = []
    for dimension in shape.elts:
        npy_require(isinstance(dimension, ast.Constant) and type(dimension.value) is int and
                    0 <= dimension.value <= NPY_DIM_MAX)
        dimensions.append(dimension.value)
    return descr.value, order.value, tuple(dimensions)


def verify_numeric_npy(data, limits):
    """Prove a simple fixed-width numeric NPY layout; otherwise fixed failure.

    Shape=() has one element, a zero dimension has no payload, and numeric raw
    bytes are never searched as pickle metadata. The exact physical file size
    is the payload bound. CRC of an NPZ member is still the outer ZIP reader's
    obligation. No numpy dtype constructor, load function or unpickler exists.
    """
    data.seek(0, io.SEEK_END)
    size = data.tell()
    npy_require(type(size) is int and 0 <= size <= limits["max_file_bytes"], "file_limit")
    npy_require(size >= 10)
    data.seek(0)
    prefix = data.read(8)
    npy_require(prefix[:6] == b"\x93NUMPY")
    version = tuple(prefix[6:8])
    npy_require(version in {(1, 0), (2, 0), (3, 0)}, "numpy_serialization_not_supported")
    length_bytes = 2 if version == (1, 0) else 4
    encoded_length = data.read(length_bytes)
    npy_require(len(encoded_length) == length_bytes)
    header_length = int.from_bytes(encoded_length, "little")
    npy_require(0 < header_length <= NPY_HEADER_MAX, "numpy_serialization_not_supported")
    payload_offset = 8 + length_bytes + header_length
    npy_require(payload_offset <= size and payload_offset % 64 == 0)
    raw = data.read(header_length)
    npy_require(len(raw) == header_length)
    dtype, fortran, shape = npy_header_literals(raw)
    width = NPY_DTYPES[dtype]
    elements = 0 if 0 in shape else 1
    maximum_elements = (size - payload_offset) // width
    if elements:
        for dimension in shape:
            # All dimensions are positive here, so integer division avoids a
            # huge intermediate multiplication and catches forged size claims.
            npy_require(elements <= maximum_elements // dimension)
            elements *= dimension
    payload_bytes = elements * width
    npy_require(payload_bytes == size - payload_offset)
    return {"formatRevision": NPY_FORMAT_REVISION, "version": list(version),
            "dtype": dtype, "shape": list(shape), "fortranOrder": fortran,
            "headerBytes": payload_offset, "numericPayloadBytes": payload_bytes,
            "objectArray": False, "modelDeserialized": False}


"""Bounded, non-executing legacy Torch CPU tensor profile.

Source contract: PyTorch v2.8.0/v2.9.1 serialization.py _legacy_save/_legacy_load,
_utils.py _rebuild_tensor_v2 and torch/csrc/serialization.cpp writeFileRaw.
Five independently memoized Pickles precede sorted storages, each encoded as
little-endian int64 element count followed by count * dtype-width raw bytes.
Only trusted Python primitives and the private tokens below are constructed.
No pickle loader, model module import, tensor constructor or reducer is called.

This is a format/parameter proof, not a model-behaviour or arbitrary-loader
safety claim. The caller must retain whole-file AV, held-FD SHA pre/post checks,
generation binding, sandbox budgets and the original metadata threat callback.
"""
import hashlib
import io
import pickletools
import re
import struct

LEGACY_PROFILE = "torch-legacy-cpu-tensor-p2-p4-parameters-v1"
LEGACY_MAGIC = 0x1950A86A20F9469CFC6C
LEGACY_META_MAX = 8 << 20
LEGACY_SLOTS_MAX = 65536
LEGACY_INT_MAX = (1 << 63) - 1
LEGACY_WIDTHS = {"ByteStorage": 1, "CharStorage": 1, "BoolStorage": 1,
                 "ShortStorage": 2, "HalfStorage": 2, "BFloat16Storage": 2,
                 "IntStorage": 4, "FloatStorage": 4, "LongStorage": 8,
                 "DoubleStorage": 8}
LEGACY_FLOATS = {"HalfStorage", "BFloat16Storage", "FloatStorage", "DoubleStorage"}
LEGACY_GLOBALS = ({("torch", name) for name in LEGACY_WIDTHS} |
                  {("torch._utils", "_rebuild_tensor_v2"), ("collections", "OrderedDict")})


class LegacyTorchError(Exception):
    def __init__(self, code="invalid_serialization"):
        self.code = code
        super().__init__(code)


def legacy_require(value, code="invalid_serialization"):
    if not value:
        raise LegacyTorchError(code)


class LegacyGlobal:
    __slots__ = ("name",)
    def __init__(self, module, symbol):
        self.name = (module, symbol)


class LegacyMap:
    __slots__ = ("ordered", "items", "state")
    def __init__(self, ordered=False):
        self.ordered, self.items, self.state = ordered, {}, None


class LegacyList:
    __slots__ = ("items",)
    def __init__(self):
        self.items = []


class LegacyStorage:
    __slots__ = ("key", "kind", "numel", "width")
    def __init__(self, key, kind, numel):
        self.key, self.kind, self.numel = key, kind, numel
        self.width = LEGACY_WIDTHS[kind]


class LegacyTensor:
    __slots__ = ("storage", "offset", "shape", "stride", "hooks", "metadata")
    def __init__(self, storage, offset, shape, stride, hooks, metadata):
        self.storage, self.offset, self.shape = storage, offset, shape
        self.stride, self.hooks, self.metadata = stride, hooks, metadata


class LegacyBoundedReader:
    """Reject oversized opcode operands before pickletools allocates them."""
    def __init__(self, data, end, max_operand):
        self.data, self.end, self.max_operand = data, end, max_operand

    def tell(self):
        return self.data.tell()

    def read(self, count):
        legacy_require(type(count) is int and 0 <= count <= min(self.max_operand, self.end - self.tell()),
                       "pickle_argument_limit")
        return self.data.read(count)

    def readline(self):
        remaining = min(self.max_operand, self.end - self.tell())
        legacy_require(remaining > 0, "pickle_argument_limit")
        raw = self.data.readline(remaining)
        legacy_require(raw.endswith(b"\n"), "pickle_argument_limit")
        return raw


def looks_like_legacy(data):
    """Narrow recognition only; a match never grants coverage or admission."""
    original = data.tell()
    try:
        data.seek(0)
        prefix = data.read(64)
        if prefix[:2] not in (b"\x80\x02", b"\x80\x04"):
            return False
        # The canonical magic stream contains no object/container construction.
        ops = list(pickletools.genops(io.BytesIO(prefix)))
        names = [op.name for op, _, _ in ops]
        if names and names[0] == "PROTO" and len(names) > 1 and names[1] == "FRAME":
            names = names[:1] + names[2:]
        return (len(names) == 3 and names[0] == "PROTO" and names[-1] == "STOP" and
                names[1] in {"LONG1", "LONG4", "LONG", "INT"} and
                type(ops[-2][1]) is int and ops[-2][1] == LEGACY_MAGIC)
    except (ValueError, UnicodeError, EOFError, OverflowError):
        return False
    finally:
        data.seek(original)


class LegacyMachine:
    """A finite abstract-value interpreter; reducers only produce tokens."""
    MARK = object()

    def __init__(self, limits):
        self.limits = limits
        self.max_slots = min(LEGACY_SLOTS_MAX, limits["max_pickle_opcodes"])
        self.stack, self.marks, self.memo = [], [], {}
        self.storages, self.tensors, self.maps = {}, [], []
        self.nodes, self.edges, self.opcodes = 0, 0, 0

    def budget(self, edges=0, nodes=0):
        self.edges += edges
        self.nodes += nodes
        legacy_require(self.nodes + self.edges + len(self.stack) + len(self.memo)
                       <= self.max_slots, "pickle_symbol_budget")

    def push(self, value):
        if value is self.MARK:
            self.marks.append(len(self.stack))
        self.stack.append(value)
        self.budget()

    def need(self, count):
        legacy_require(count > 0 and len(self.stack) >= count and
                       all(x is not self.MARK for x in self.stack[-count:]))

    def pop(self, count=1):
        self.need(count)
        values = self.stack[-count:]
        del self.stack[-count:]
        return values[0] if count == 1 else values

    def marked(self):
        legacy_require(bool(self.marks))
        index = self.marks.pop()
        values = self.stack[index + 1:]
        del self.stack[index:]
        return values

    def mapping(self, ordered=False):
        value = LegacyMap(ordered)
        self.maps.append(value)
        self.budget(nodes=1)
        return value

    def setitems(self, target, pairs):
        legacy_require(type(target) is LegacyMap and len(pairs) % 2 == 0)
        for index in range(0, len(pairs), 2):
            key, value = pairs[index:index + 2]
            legacy_require(type(key) is str and len(key) <= 1024 and
                           key not in target.items)
            self.budget(edges=2)
            target.items[key] = value

    def global_token(self, module, symbol):
        legacy_require(type(module) is str and type(symbol) is str and
                       (module, symbol) in LEGACY_GLOBALS,
                       "unsupported_container_or_serialization")
        self.budget(nodes=1)
        return LegacyGlobal(module, symbol)

    def persistent(self, value):
        legacy_require(type(value) is tuple and len(value) == 6)
        tag, kind, key, location, numel, view = value
        legacy_require(tag == "storage" and type(kind) is LegacyGlobal and
                       kind.name[0] == "torch" and kind.name[1] in LEGACY_WIDTHS and
                       type(key) is str and re.fullmatch(r"[0-9]{1,32}", key) and
                       location == "cpu" and view is None,
                       "unsupported_container_or_serialization")
        legacy_require(type(numel) is int and 0 <= numel <= LEGACY_INT_MAX)
        width = LEGACY_WIDTHS[kind.name[1]]
        legacy_require(numel <= min(self.limits["max_file_bytes"],
                                   self.limits["max_scan_bytes"]) // width,
                       "archive_member_size")
        if key in self.storages:
            old = self.storages[key]
            legacy_require((old.kind, old.numel) == (kind.name[1], numel))
            return old
        legacy_require(len(self.storages) < self.limits["max_members"], "archive_member_limit")
        value = LegacyStorage(key, kind.name[1], numel)
        self.storages[key] = value
        self.budget(nodes=1)
        return value

    def reduce(self, target, args):
        legacy_require(type(target) is LegacyGlobal and type(args) is tuple,
                       "unsupported_container_or_serialization")
        if target.name == ("collections", "OrderedDict"):
            legacy_require(not args, "unsupported_container_or_serialization")
            return self.mapping(True)
        legacy_require(target.name == ("torch._utils", "_rebuild_tensor_v2") and
                       len(args) in (6, 7), "unsupported_container_or_serialization")
        storage, offset, shape, stride, grad, hooks = args[:6]
        metadata = args[6] if len(args) == 7 else None
        legacy_require(type(storage) is LegacyStorage and type(offset) is int and
                       0 <= offset <= LEGACY_INT_MAX // storage.width)
        legacy_require(type(shape) is tuple and type(stride) is tuple and
                       len(shape) == len(stride) <= 64 and
                       all(type(x) is int and 0 <= x <= LEGACY_INT_MAX for x in shape + stride))
        legacy_require(type(grad) is bool and (not grad or storage.kind in LEGACY_FLOATS))
        legacy_require(type(hooks) is LegacyMap and hooks.ordered and not hooks.items and
                       hooks.state is None, "unsupported_container_or_serialization")
        legacy_require(metadata is None or (type(metadata) is LegacyMap and
                       not metadata.items and metadata.state is None),
                       "unsupported_container_or_serialization")
        # No element is addressed for an empty tensor; its offset may exceed
        # storage capacity. Scalar, zero-stride and ordinary shared views are valid.
        if 0 not in shape:
            product, maximum = 1, offset
            for size, step in zip(shape, stride):
                legacy_require(size > 0 and product <= LEGACY_INT_MAX // size)
                product *= size
                delta = (size - 1) * step
                legacy_require(delta <= LEGACY_INT_MAX - maximum)
                maximum += delta
            legacy_require(maximum < storage.numel, "archive_member_size")
        value = LegacyTensor(storage, offset, shape, stride, hooks, metadata)
        self.tensors.append(value)
        self.budget(nodes=1, edges=6)
        return value

    def apply(self, name, argument):
        if name in {"PROTO", "FRAME"}:
            return
        if name in {"BINUNICODE", "SHORT_BINUNICODE", "BINUNICODE8", "UNICODE"}:
            legacy_require(type(argument) is str and len(argument) <= 1024,
                           "pickle_argument_limit")
            self.push(argument)
        elif name in {"BININT", "BININT1", "BININT2", "LONG1", "LONG4", "INT", "LONG"}:
            legacy_require(type(argument) is int and -(1 << 127) <= argument < (1 << 127))
            self.push(argument)
        elif name == "NONE":
            self.push(None)
        elif name in {"NEWTRUE", "NEWFALSE"}:
            self.push(name == "NEWTRUE")
        elif name == "MARK":
            self.push(self.MARK)
        elif name == "EMPTY_TUPLE":
            self.push(())
        elif name == "TUPLE" or name in {"TUPLE1", "TUPLE2", "TUPLE3"}:
            if name == "TUPLE":
                values = self.marked()
            else:
                count = int(name[-1]); self.need(count)
                values = self.stack[-count:]; del self.stack[-count:]
            legacy_require(len(values) <= 64)
            self.budget(nodes=1, edges=len(values)); self.push(tuple(values))
        elif name == "EMPTY_DICT":
            self.push(self.mapping())
        elif name == "DICT":
            values = self.marked(); target = self.mapping()
            self.setitems(target, values); self.push(target)
        elif name in {"SETITEM", "SETITEMS"}:
            values = self.pop(2) if name == "SETITEM" else self.marked()
            self.need(1); self.setitems(self.stack[-1], values)
        elif name == "EMPTY_LIST":
            self.budget(nodes=1); self.push(LegacyList())
        elif name in {"APPEND", "APPENDS"}:
            values = [self.pop()] if name == "APPEND" else self.marked()
            self.need(1); target = self.stack[-1]
            legacy_require(type(target) is LegacyList and
                           len(target.items) + len(values) <= self.limits["max_members"],
                           "archive_member_limit")
            self.budget(edges=len(values)); target.items.extend(values)
        elif name in {"BINPUT", "LONG_BINPUT", "PUT", "MEMOIZE"}:
            self.need(1)
            key = len(self.memo) if name == "MEMOIZE" else argument
            legacy_require(type(key) is int and 0 <= key < self.max_slots and key not in self.memo)
            self.memo[key] = self.stack[-1]; self.budget()
        elif name in {"BINGET", "LONG_BINGET", "GET"}:
            legacy_require(type(argument) is int and argument in self.memo)
            self.push(self.memo[argument])
        elif name == "GLOBAL":
            parts = argument.split(" ", 1)
            legacy_require(len(parts) == 2)
            self.push(self.global_token(*parts))
        elif name == "STACK_GLOBAL":
            module, symbol = self.pop(2)
            self.push(self.global_token(module, symbol))
        elif name == "BINPERSID":
            self.push(self.persistent(self.pop()))
        elif name == "REDUCE":
            target, args = self.pop(2)
            self.push(self.reduce(target, args))
        elif name == "BUILD":
            state = self.pop(); self.need(1); target = self.stack[-1]
            legacy_require(type(target) is LegacyMap and target.ordered and
                           target.state is None and type(state) is LegacyMap and
                           not state.ordered and set(state.items) == {"_metadata"},
                           "unsupported_container_or_serialization")
            target.state = state; self.budget(edges=1)
        elif name == "STOP":
            legacy_require(len(self.stack) == 1 and not self.marks)
        else:
            # POP/OBJ/INST/NEWOBJ/EXT/PERSID/etc are deliberately outside the
            # finite tensor profile, even if a general Pickle VM knows them.
            raise LegacyTorchError("unsupported_container_or_serialization")

    def parse(self, raw, protocol):
        self.stack, self.marks, self.memo = [], [], {}
        stream = io.BytesIO(raw)
        for opcode, argument, _ in pickletools.genops(stream):
            self.opcodes += 1
            legacy_require(self.opcodes <= self.limits["max_pickle_opcodes"], "pickle_opcode_limit")
            legacy_require(opcode.proto <= protocol, "unsupported_container_or_serialization")
            self.apply(opcode.name, argument)
        legacy_require(stream.tell() == len(raw) and len(self.stack) == 1 and not self.marks)
        return self.stack[0]

    def final_state(self, root):
        legacy_require(type(root) is LegacyTensor or
                       (type(root) is LegacyMap and
                        all(type(v) is LegacyTensor for v in root.items.values())),
                       "unsupported_container_or_serialization")
        self.final_tokens(root)

    def final_tokens(self, root):
        # Alias mutation after a reducer/BUILD must not turn a previously empty
        # hooks/metadata token into executable or unsupported state.
        for tensor in self.tensors:
            legacy_require(not tensor.hooks.items and tensor.hooks.state is None and
                           (tensor.metadata is None or (not tensor.metadata.items and
                            tensor.metadata.state is None)), "unsupported_container_or_serialization")
        for value in self.maps:
            if value.state is None:
                continue
            legacy_require(value is root and value.ordered and
                           type(value.state) is LegacyMap and value.state.state is None and
                           set(value.state.items) == {"_metadata"},
                           "unsupported_container_or_serialization")
            metadata = value.state.items["_metadata"]
            legacy_require(type(metadata) is LegacyMap and metadata.state is None,
                           "unsupported_container_or_serialization")
            for item in metadata.items.values():
                legacy_require(type(item) is LegacyMap and not item.ordered and
                               item.state is None and set(item.items) == {"version"} and
                               type(item.items["version"]) is int and
                               0 <= item.items["version"] <= (1 << 31) - 1,
                               "unsupported_container_or_serialization")


_PARAMETER_SYMBOL = ("torch._utils", "_rebuild_parameter")
_ZIP_PARAMETER_SEAL = object()


class _ZipParameter:
    __slots__ = ("data", "grad", "hooks")

    def __init__(self, data, grad, hooks):
        self.data, self.grad, self.hooks = data, grad, hooks


class _ZipParameterMachine(LegacyMachine):
    """Only the selected P2 ZIP state_dict profile; no constructors are called."""
    def __init__(self, limits):
        super().__init__(limits)
        self.parameters = []
        self.layout = StorageReferences(limits)

    def global_token(self, module, symbol):
        if (module, symbol) == _PARAMETER_SYMBOL:
            self.budget(nodes=1)
            return LegacyGlobal(module, symbol)
        return super().global_token(module, symbol)

    def persistent(self, value):
        legacy_require(type(value) is tuple and len(value) == 5)
        tag, kind, key, location, numel = value
        legacy_require(type(kind) is LegacyGlobal, "unsupported_container_or_serialization")
        # Reuse exactly the existing typed CPU ZIP PID rules and storage closure.
        try:
            self.layout.pid((tag, GlobalToken(*kind.name), key, location, numel))
        except LayoutError as error:
            raise LegacyTorchError(error.code) from None
        if key in self.storages:
            return self.storages[key]
        value = LegacyStorage(key, kind.name[1], numel)
        self.storages[key] = value
        self.budget(nodes=1)
        return value

    def reduce(self, target, args):
        if type(target) is not LegacyGlobal or target.name != _PARAMETER_SYMBOL:
            return super().reduce(target, args)
        legacy_require(type(args) is tuple and len(args) == 3,
                       "unsupported_container_or_serialization")
        data, grad, hooks = args
        legacy_require(type(data) is LegacyTensor and type(grad) is bool and
                       (not grad or data.storage.kind in LEGACY_FLOATS) and
                       type(hooks) is LegacyMap and hooks.ordered and
                       not hooks.items and hooks.state is None,
                       "unsupported_container_or_serialization")
        value = _ZipParameter(data, grad, hooks)
        self.parameters.append(value)
        self.budget(nodes=1, edges=3)
        return value

    def parse(self, raw):
        try:
            return self._parse_metadata(raw)
        except (ValueError, UnicodeError, EOFError, OverflowError):
            raise LegacyTorchError("invalid_serialization") from None

    def _parse_metadata(self, raw):
        legacy_require(self.opcodes == 0 and raw[:2] == b"\x80\x02",
                       "unsupported_container_or_serialization")
        stream = io.BytesIO(raw)
        reader = LegacyBoundedReader(stream, len(raw), self.limits["max_pickle_argument"])
        stopped = False
        for opcode, argument, offset in pickletools.genops(reader):
            self.opcodes += 1
            legacy_require(self.opcodes <= self.limits["max_pickle_opcodes"], "pickle_opcode_limit")
            legacy_require(opcode.proto <= 2, "unsupported_container_or_serialization")
            if opcode.name == "PROTO":
                legacy_require(offset == 0 and argument == 2)
            self.apply(opcode.name, argument)
            if opcode.name == "STOP":
                stopped = True
        legacy_require(stopped and stream.tell() == len(raw) and len(self.stack) == 1 and not self.marks)
        root = self.stack[0]
        self.final_state(root)
        return root

    def final_state(self, root):
        legacy_require(type(root) is LegacyMap and root.ordered and bool(root.items) and
                       all(type(key) is str and key and type(value) in (LegacyTensor, _ZipParameter)
                           for key, value in root.items.items()), "unsupported_container_or_serialization")
        direct = {id(value) for value in root.items.values() if type(value) is _ZipParameter}
        legacy_require(bool(self.parameters) and
                       all(id(value) in direct for value in self.parameters),
                       "unsupported_container_or_serialization")
        self.final_tokens(root)
        for parameter in self.parameters:
            legacy_require(type(parameter.data) is LegacyTensor and type(parameter.grad) is bool and
                           (not parameter.grad or parameter.data.storage.kind in LEGACY_FLOATS) and
                           type(parameter.hooks) is LegacyMap and parameter.hooks.ordered and
                           not parameter.hooks.items and parameter.hooks.state is None,
                           "unsupported_container_or_serialization")


class _ZipParameterContext:
    """Single-callback capability, bound to the exact bytes, member and VM graph."""
    __slots__ = ("raw", "digest", "chain", "limits", "stream", "specs", "machine", "seal")

    def __init__(self, raw, index, name, limits, seal):
        require(seal is _ZIP_PARAMETER_SEAL, "unsupported_container_or_serialization")
        self.raw, self.digest = raw, hashlib.sha256(raw).digest()
        self.chain = ((index, hashlib.sha256(name.encode("utf-8", "surrogatepass")).hexdigest()),)
        self.limits, self.stream, self.specs, self.machine, self.seal = dict(limits), None, None, None, seal

    def prove(self, stream, chain, limits):
        legacy_require(self.seal is _ZIP_PARAMETER_SEAL and type(stream) is io.BytesIO and
                       stream is self.stream and chain == self.chain and limits == self.limits,
                       "unsupported_container_or_serialization")
        view = stream.getbuffer()
        try:
            legacy_require(len(view) == len(self.raw) and hashlib.sha256(view).digest() == self.digest,
                           "unsupported_container_or_serialization")
        finally:
            view.release()
        legacy_require(self.machine is None, "unsupported_container_or_serialization")
        machine = _ZipParameterMachine(limits)
        machine.parse(self.raw)
        self.machine = machine
        self.specs = dict(machine.layout.storages)
        return {_PARAMETER_SYMBOL}


def legacy_read_segment(data, metadata_end, max_argument, max_opcodes):
    """Find an exact STOP, validating protocol-4 FRAME boundaries as well."""
    start, frame_end, protocol, count = data.tell(), None, None, 0
    reader = LegacyBoundedReader(data, metadata_end, max_argument)
    for opcode, argument, offset in pickletools.genops(reader):
        count += 1
        legacy_require(count <= max_opcodes, "pickle_opcode_limit")
        after = data.tell()
        if frame_end is not None and offset == frame_end:
            frame_end = None
        legacy_require(frame_end is None or (offset < frame_end and after <= frame_end))
        if count == 1:
            legacy_require(opcode.name == "PROTO" and argument in (2, 4),
                           "unsupported_container_or_serialization")
            protocol = argument
        elif opcode.name == "PROTO":
            raise LegacyTorchError()
        legacy_require(opcode.proto <= protocol, "unsupported_container_or_serialization")
        if opcode.name == "FRAME":
            legacy_require(protocol == 4 and frame_end is None and type(argument) is int and
                           0 < argument <= metadata_end - after)
            frame_end = after + argument
        if isinstance(argument, (str, bytes)):
            legacy_require(len(argument) <= max_argument, "pickle_argument_limit")
        if opcode.name == "STOP":
            legacy_require(frame_end is None or after == frame_end)
    end = data.tell()
    data.seek(start); raw = data.read(end - start); data.seek(end)
    legacy_require(raw.endswith(b".") and count > 1)
    return raw, protocol, count


def parse_legacy_metadata(data, size, inspect_pickle_callback, limits):
    """Shared finite metadata semantics; never examines or approves storage bytes."""
    metadata_end = min(size, LEGACY_META_MAX, limits["max_expanded_bytes"])
    machine, values, segments, protocol, opcodes = LegacyMachine(limits), [], [], None, 0
    for index in range(5):
        start = data.tell()
        try:
            raw, segment_protocol, count = legacy_read_segment(
                data, metadata_end, limits["max_pickle_argument"], limits["max_pickle_opcodes"] - opcodes)
        except (LegacyTorchError, ValueError, UnicodeError, EOFError, OverflowError) as error:
            failure = error if isinstance(error, LegacyTorchError) else LegacyTorchError()
            if failure.code in {"invalid_serialization", "unsupported_container_or_serialization"}:
                # Already rejected. Preserve any dangerous references seen
                # before a malformed frame/STOP without overriding this
                # failure or doing more work after a resource-budget failure.
                end = min(data.tell(), metadata_end)
                data.seek(start); partial = data.read(max(0, end - start)); data.seek(end)
                try:
                    inspect_pickle_callback(io.BytesIO(partial), index)
                except Exception:
                    pass  # This path always raises the original fixed failure.
            raise failure from None
        end = data.tell(); opcodes += count
        # Threat evidence is retained even when the narrower semantic
        # profile subsequently rejects a global/constructor/state.
        inspect_pickle_callback(io.BytesIO(raw), index)
        if protocol is None:
            protocol = segment_protocol
        legacy_require(segment_protocol == protocol, "unsupported_container_or_serialization")
        values.append(machine.parse(raw, protocol))
        segments.append({"index": index, "offset": start, "bytes": end - start,
                         "sha256": hashlib.sha256(raw).hexdigest()})
    magic, version, system, root, keys = values
    legacy_require(type(magic) is int and magic == LEGACY_MAGIC and
                   type(version) is int and version == 1001)
    legacy_require(type(system) is LegacyMap and not system.ordered and system.state is None and
                   set(system.items) == {"protocol_version", "little_endian", "type_sizes"})
    legacy_require(type(system.items["protocol_version"]) is int and
                   system.items["protocol_version"] == 1001 and system.items["little_endian"] is True,
                   "unsupported_container_or_serialization")
    widths = system.items["type_sizes"]
    legacy_require(type(widths) is LegacyMap and not widths.ordered and widths.state is None and
                   set(widths.items) == {"short", "int", "long"} and
                   all(type(v) is int for v in widths.items.values()) and
                   widths.items["short"] == 2 and widths.items["int"] == 4 and
                   widths.items["long"] in (4, 8), "unsupported_container_or_serialization")
    machine.final_state(root)
    legacy_require(type(keys) is LegacyList and all(type(key) is str for key in keys.items) and
                   keys.items == sorted(machine.storages), "archive_member_size")
    return machine, keys, segments, protocol


def verify_legacy_torch(data, inspect_pickle_callback, limits, *, hash_storage_payloads=True):
    """Return a public layout proof, None for non-legacy, or fail closed.

    callback(BytesIO, stream_index) must run the unchanged threat inspector.
    Storage bytes are exempted from Pickle parsing only after all five segments,
    constructor constraints and every storage boundary have been verified.

    The default proof includes each storage payload digest. Layout-only callers
    must independently scan and bind the whole artifact; this function does not
    certify payload content. Both modes prove an exact partition through EOF.
    """
    if type(hash_storage_payloads) is not bool:
        raise ValueError("hash_storage_payloads must be bool")
    if not looks_like_legacy(data):
        return None
    data.seek(0, io.SEEK_END); size = data.tell(); data.seek(0)
    legacy_require(size <= min(limits["max_file_bytes"], limits["max_scan_bytes"]), "file_limit")
    try:
        machine, keys, segments, protocol = parse_legacy_metadata(
            data, size, inspect_pickle_callback, limits)
        metadata_bytes, storage_bytes, ranges = data.tell(), 0, []
        for key in keys.items:
            storage = machine.storages[key]
            offset = data.tell(); header = data.read(8)
            legacy_require(len(header) == 8 and struct.unpack("<q", header)[0] == storage.numel,
                           "archive_member_size")
            count = storage.numel * storage.width
            legacy_require(count <= size - data.tell(), "archive_member_size")
            payload_sha = None
            if hash_storage_payloads:
                sha = hashlib.sha256(); remaining = count
                while remaining:
                    block = data.read(min(128 << 10, remaining))
                    legacy_require(bool(block), "archive_member_size")
                    sha.update(block); remaining -= len(block)
                payload_sha = sha.hexdigest()
            else:
                # Only the proven numeric payload is skipped. Its next header
                # (or exact EOF) is still checked; no payload digest is claimed.
                payload_end = data.tell() + count
                data.seek(payload_end)
                legacy_require(data.tell() == payload_end, "archive_member_size")
            storage_bytes += count
            ranges.append({"keySha256": hashlib.sha256(key.encode("ascii")).hexdigest(),
                           "headerOffset": offset, "payloadOffset": offset + 8,
                           "payloadBytes": count, "payloadSHA256": payload_sha,
                           "elementBytes": storage.width, "elements": storage.numel})
        legacy_require(data.tell() == size, "archive_member_size")
        proof = {"formatRevision": LEGACY_PROFILE, "pickleProtocol": protocol,
                "metadataBytes": metadata_bytes, "storageBytes": storage_bytes,
                "storageHeaderBytes": len(ranges) * 8, "containerBytes": size,
                "pickleSegments": segments, "storageRanges": ranges,
                "storageCount": len(ranges), "tensorCount": len(machine.tensors),
                "completeByteCoverage": True, "constructorParametersVerified": True,
                "unknownConstructorsAllowed": False, "modelDeserialized": False}
        if not hash_storage_payloads:
            proof["storageDigestMode"] = "layout-only"
        return proof
    except (ValueError, UnicodeError, EOFError, OverflowError, struct.error):
        raise LegacyTorchError("invalid_serialization") from None



def probe_legacy_prefix(descriptor, limits, generation):
    """Fail-only preflight: no result from this function approves any bytes.

    First locate five complete metadata segments. Any shortage or malformed
    segment remains pending: the mandatory whole-file scan owns those errors.
    Only then apply the same metadata semantics and threat inspector as the
    final scan. Storage bytes, storage headers and EOF are never certified.
    """
    validate_prefix(descriptor, limits)
    raw = base64.b64decode(descriptor["prefixBase64"], validate=True)
    result = {"generation": generation, "prefixSha256": descriptor["prefixSha256"],
              "prefixBytes": descriptor["prefixBytes"], "status": "pending", "reason": ""}
    data = io.BytesIO(raw)
    if not looks_like_legacy(data):
        return result
    end = min(descriptor["sourceSize"], LEGACY_META_MAX, limits["max_expanded_bytes"])
    opcodes = 0
    try:
        for _ in range(5):
            _, _, count = legacy_read_segment(data, end, limits["max_pickle_argument"],
                                               limits["max_pickle_opcodes"] - opcodes)
            opcodes += count
    except (LegacyTorchError, ValueError, UnicodeError, EOFError, OverflowError):
        return result
    metadata = io.BytesIO(raw[:data.tell()])
    inspector = StaticInspector(limits)
    def inspect_segment(member, index):
        inspector.inspect_pickle(member, stream_index_base=index)
    try:
        parse_legacy_metadata(metadata, descriptor["sourceSize"], inspect_segment, limits)
    except (LegacyTorchError, Incomplete) as error:
        code = error.code if isinstance(error, LegacyTorchError) else (error.args[0] if error.args else None)
        if code not in FILE_ERROR_CODES:
            raise Incomplete(code if code in ERROR_CODES else "worker_failed_or_incomplete") from None
        result.update(status="reject", reason=code)
    except (ValueError, UnicodeError, EOFError, OverflowError, struct.error):
        result.update(status="reject", reason="invalid_serialization")
    return result


def prefix_worker(request, rules):
    logging.disable(logging.CRITICAL)
    limits = prefix_limits(request["limits"])
    child_limits(limits)
    check_rules_expiry(limits)
    descriptor = validate_prefix(request["prefix"], limits)
    if rule_inventory(rules) != request["evidence"]["rules"]:
        raise Incomplete("rules_changed")
    result = probe_legacy_prefix(descriptor, limits, request["bundle"]["generation"])
    if rule_inventory(rules) != request["evidence"]["rules"]:
        raise Incomplete("rules_changed")
    check_rules_expiry(limits)
    return result


def validate_zip_directory_member(data, archive, member):
    """Prove that a directory entry has no hidden decompressed payload.

    ZipExtFile may consider a declared zero-size entry finished without
    consuming its compressed bytes, so read(1) alone cannot establish this.
    Only physically empty stored entries and bounded exact empty DEFLATE
    streams are supported; this does not authorize any non-directory content.
    """
    if member.file_size != 0 or member.CRC != 0:
        raise Incomplete("archive_member_size")
    # Retain ZipFile's local-name and overlapping-entry validation before
    # inspecting the small physical compressed fragment ourselves.
    with archive.open(member):
        pass
    data.seek(member.header_offset)
    raw = data.read(30)
    if len(raw) != 30:
        raise Incomplete("invalid_serialization")
    head = struct.unpack("<4s5H3I2H", raw)
    if head[0] != b"PK\x03\x04" or head[2] != member.flag_bits or head[3] != member.compress_type:
        raise Incomplete("invalid_serialization")
    if member.flag_bits & 8:
        consistent = (head[6] in {0, member.CRC} and head[7] in {0, member.compress_size}
                      and head[8] in {0, member.file_size})
    else:
        consistent = (head[6], head[7], head[8]) == (member.CRC, member.compress_size, member.file_size)
    if not consistent:
        raise Incomplete("invalid_serialization")
    payload_at = member.header_offset + 30 + head[9] + head[10]
    if payload_at < 0 or payload_at > archive.start_dir or member.compress_size > archive.start_dir - payload_at:
        raise Incomplete("archive_member_size")
    if member.compress_type == zipfile.ZIP_STORED:
        if member.compress_size != 0:
            raise Incomplete("archive_member_size")
        return
    if member.compress_type != zipfile.ZIP_DEFLATED:
        raise Incomplete("unsupported_container_or_serialization")
    if not 0 < member.compress_size <= 32:
        raise Incomplete("archive_member_size")
    data.seek(payload_at)
    compressed = data.read(member.compress_size)
    if len(compressed) != member.compress_size:
        raise Incomplete("archive_member_size")
    try:
        decoder = zlib.decompressobj(-15)
        output = decoder.decompress(compressed, 1)
    except zlib.error:
        raise Incomplete("invalid_serialization") from None
    if output or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise Incomplete("archive_member_size")


def validate_pax_records(raw):
    """Bound a PAX extension without constructing TarFile's metadata map.

    Layout-changing PAX attributes are outside the supported TAR profile. Path,
    timestamps and other ordinary bounded metadata remain supported. No value
    is evaluated, loaded or used as a filesystem path by this preflight.
    """
    position, fields = 0, 0
    while position < len(raw):
        fields += 1
        if fields > TAR_MAX_PAX_FIELDS:
            raise Incomplete("archive_member_limit")
        space = raw.find(b" ", position, min(len(raw), position + 22))
        if space < 0:
            raise Incomplete("invalid_serialization")
        encoded_length = raw[position:space]
        if not encoded_length or not encoded_length.isdigit():
            raise Incomplete("invalid_serialization")
        length = int(encoded_length)
        if length <= space - position + 2 or length > len(raw) - position:
            raise Incomplete("invalid_serialization")
        end = position + length
        equal = raw.find(b"=", space + 1, end - 1)
        if equal <= space + 1 or raw[end - 1:end] != b"\n":
            raise Incomplete("invalid_serialization")
        key = raw[space + 1:equal]
        if (key == b"size" or key.startswith(b"GNU.sparse")
                or key in {b"SCHILY.realsize", b"SCHILY.filetype"}):
            raise Incomplete("unsupported_container_or_serialization")
        position = end


def bounded_tar_headers(data, remaining_members, remaining_expanded, max_file_bytes):
    """Fence physical TAR records before TarFile can recurse or allocate.

    Supports uncompressed V7/USTAR, bounded ordinary PAX metadata and GNU long
    names. Sparse/layout-changing extensions, special files and nonzero tails
    are deliberately incomplete. A complete supported archive ends with two
    zero blocks, followed only by zero record padding.
    """
    data.seek(0, io.SEEK_END)
    size = data.tell()
    data.seek(0)
    if not 1024 <= size <= max_file_bytes or size % 512:
        raise Incomplete("invalid_serialization")
    position, physical_count, extension_count, extension_bytes = 0, 0, 0, 0
    pending_extension = False
    extension_types = {tarfile.XHDTYPE, tarfile.XGLTYPE,
                       tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK}
    while position <= size - 512:
        data.seek(position)
        raw = data.read(512)
        if len(raw) != 512:
            raise Incomplete("invalid_serialization")
        if raw == b"\x00" * 512:
            # A single zero marker or concatenated/nonzero second archive is
            # not complete coverage under the fixed supported TAR profile.
            if pending_extension or size - position < 1024 or data.read(512) != b"\x00" * 512:
                raise Incomplete("invalid_serialization")
            for block in iter(lambda: data.read(CHUNK_BYTES), b""):
                if block.strip(b"\x00"):
                    raise Incomplete("invalid_serialization")
            data.seek(0)
            return extension_count, extension_bytes
        physical_count += 1
        if physical_count > remaining_members:
            raise Incomplete("archive_member_limit")
        try:
            # frombuf handles this fixed header and checksum only. In
            # particular it never follows a PAX/GNU extension to the next one.
            info = tarfile.TarInfo.frombuf(raw, "utf-8", "surrogateescape")
        except (tarfile.HeaderError, ValueError, UnicodeError):
            raise Incomplete("invalid_serialization") from None
        if info.size < 0:
            raise Incomplete("archive_member_size")
        payload_remaining = size - position - 512
        padded_size = ((info.size + 511) // 512) * 512
        if info.size > payload_remaining or padded_size > payload_remaining:
            raise Incomplete("archive_member_size")
        if info.type in extension_types:
            if (info.size > TAR_MAX_EXTENSION_BYTES
                    or info.size > min(MAX_METADATA_BYTES, remaining_expanded) - extension_bytes):
                raise Incomplete("expanded_bytes_limit")
            extension_count += 1
            extension_bytes += info.size
            pending_extension = True
            extension = data.read(info.size)
            if len(extension) != info.size:
                raise Incomplete("archive_member_size")
            if info.type in {tarfile.XHDTYPE, tarfile.XGLTYPE}:
                validate_pax_records(extension)
        elif info.isdir():
            if info.size != 0:
                raise Incomplete("archive_member_size")
            pending_extension = False
        elif not info.isfile():
            raise Incomplete("archive_link_or_special_file")
        elif info.type == tarfile.GNUTYPE_SPARSE:
            raise Incomplete("unsupported_container_or_serialization")
        else:
            pending_extension = False
        position += 512 + padded_size
    raise Incomplete("invalid_serialization")


class PickleOpcodeReader:
    """Fence raw opcode operands before either static parser allocates them.

    The argument budget applies to encoded bytes, including a protocol-0
    line's newline, as well as the existing decoded-value checks. UTF-8 or
    escaped text whose raw encoding exceeds the budget is now incomplete even
    when its decoded value would fit. This is a per-read allocation fence,
    not a claim that total parser memory is bounded by one argument.
    """
    __slots__ = ("max_operand", "_read", "_readline", "tell", "seek", "limit_exceeded", "unconfirmed_probe")

    def __init__(self, data, max_operand, *, unconfirmed_probe=False):
        self.max_operand = max_operand
        self._read, self._readline = data.read, data.readline
        self.tell, self.seek = data.tell, data.seek
        self.limit_exceeded = False
        self.unconfirmed_probe = unconfirmed_probe

    def reject(self):
        self.limit_exceeded = True
        raise Incomplete("pickle_argument_limit")

    def read(self, count=-1):
        if type(count) is not int or count < 0:
            self.reject()
        if count > self.max_operand:
            if self.unconfirmed_probe:
                # An unknown text file may start with a length-bearing opcode
                # by coincidence. Prove a missing operand with bounded reads,
                # never forwarding its untrusted allocation request. A short
                # read is not EOF; only an actual empty read proves truncation.
                remaining = self.max_operand
                while remaining:
                    amount = min(remaining, 64 << 10)
                    try:
                        raw = self._read(amount)
                    except Exception:
                        self.reject()
                    if type(raw) is not bytes or len(raw) > amount:
                        self.reject()
                    if not raw:
                        raise ValueError("truncated unconfirmed pickle operand")
                    remaining -= len(raw)
            self.reject()
        return self._read(count)

    def readline(self):
        raw = self._readline(self.max_operand + 1)
        if len(raw) > self.max_operand:
            self.reject()
        return raw

    def check_budget(self):
        # Picklescan catches parser exceptions internally and can turn a parse
        # error without globals into an empty result. Never let that swallow a
        # resource-budget failure during its mandatory independent full pass.
        if self.limit_exceeded:
            raise Incomplete("pickle_argument_limit")


class StaticInspector:
    """Budgeted container traversal around the mature Picklescan analyzer.

    Pickletools provides structural completeness and bounded symbolic locations.
    Picklescan supplies threat categories for the actually observed globals.
    Neither establishes invocation or malicious execution.
    """
    def __init__(self, limits, *, hash_storage_payloads=True):
        if type(hash_storage_payloads) is not bool:
            raise ValueError("hash_storage_payloads must be bool")
        self.limits = limits
        self.hash_storage_payloads = hash_storage_payloads
        self.expanded = 0
        self.members = 0
        self.opcodes = 0
        self.findings = []
        self.pickle_files = 0

    def inspect(self, data, name, depth=0, archive_chain=()):
        if depth > self.limits["max_depth"] or len(archive_chain) > MAX_EVIDENCE_CHAIN:
            raise Incomplete("archive_depth_limit")
        data.seek(0)
        prefix = data.read(512)
        data.seek(0)
        ext = PurePosixPath(name).suffix.lower()
        if prefix.startswith(b"7z\xbc\xaf\x27\x1c") or prefix.startswith(b"Rar!\x1a\x07") or (ext in UNSUPPORTED_EXT and ext not in {".npy", ".npz"}):
            raise Incomplete("unsupported_container_or_serialization")
        if prefix.startswith(b"PK") or ext in {".zip", ".npz"}:
            self.inspect_zip(data, depth, archive_chain)
        elif prefix.startswith(b"\x1f\x8b"):
            with gzip.GzipFile(fileobj=data) as member:
                # Gzip has one anonymous traversal child. No outer filename
                # or optional untrusted gzip header is exposed as evidence.
                chain = self.member_chain(archive_chain, 0, "")
                self.inspect_member(member, name[:-3] if name.endswith(".gz") else "member", depth + 1,
                                    archive_chain=chain)
        elif (len(prefix) >= 265 and prefix[257:262] == b"ustar") or ext in {".tar", ".tgz"}:
            self.inspect_tar(data, depth, archive_chain)
        elif ext == ".safetensors":
            # The little-endian length of a valid 128-byte header starts with
            # 80 00, also a Pickle PROTO prefix. Validate the entire declared
            # format before generic Pickle probing; this is not an extension
            # allowlist. Renamed Pickles fail, and archive magic still wins.
            self.validate_safetensors(data)
        elif prefix.startswith(b"\x93NUMPY"):
            # NPY's 0x93 magic byte is also a Pickle opcode. Prove the exact
            # numeric format before generic probing, without constructing an
            # array or granting any direct admission decision. NPZ still uses
            # the existing bounded ZIP member read and CRC verification.
            try:
                self.verified_numeric_npy = verify_numeric_npy(data, self.limits)
            except NumpyLayoutError as error:
                raise Incomplete(error.code) from None
        elif looks_like_legacy(data):
            hash_storage_payloads = self.hash_storage_payloads or depth != 0 or bool(archive_chain)
            if not hash_storage_payloads:
                # The worker opts in only after open_verified has bound this
                # held regular FD. Nested and standalone-default paths retain
                # their existing payload digest proof.
                try:
                    regular = stat.S_ISREG(os.fstat(data.fileno()).st_mode)
                except (OSError, ValueError):
                    raise Incomplete("invalid_analysis_context") from None
                if not regular:
                    raise Incomplete("invalid_analysis_context")
            self.inspect_legacy_torch(data, archive_chain, hash_storage_payloads=hash_storage_payloads)
        elif ext in PICKLE_EXT or (len(prefix) > 1 and prefix[0] == 0x80 and prefix[1] <= 5) or self.pickle_candidate(data):
            self.inspect_pickle(data, archive_chain)
        elif ext == ".npy":
            # A file extension alone cannot establish numeric-only storage.
            # Concrete Pickle references above still retain their evidence.
            raise Incomplete("invalid_serialization")
        # Other files have no recognized pickle serialization context. ClamAV
        # still scans every whole artifact. No arbitrary framework whitelist.

    def inspect_legacy_torch(self, data, archive_chain, *, hash_storage_payloads=True):
        def metadata_inspection(member, stream_index):
            self.inspect_pickle(member, archive_chain, stream_index_base=stream_index)
        try:
            proof = verify_legacy_torch(data, metadata_inspection, self.limits,
                                        hash_storage_payloads=hash_storage_payloads)
        except LegacyTorchError as error:
            raise Incomplete(error.code) from None
        if proof is None:
            raise Incomplete("invalid_serialization")
        if proof["storageCount"] > self.limits["max_members"] - self.members:
            raise Incomplete("archive_member_limit")
        if proof["metadataBytes"] > self.limits["max_expanded_bytes"] - self.expanded:
            raise Incomplete("expanded_bytes_limit")
        self.members += proof["storageCount"]
        self.expanded += proof["metadataBytes"]
        self.verified_legacy_torch = proof

    def pickle_candidate(self, data):
        # Extensions are attacker-controlled. Disassemble unknown content to
        # identify valid protocol-0/1 pickles and any executable opcode before
        # a later parse error. A prefix such as EMPTY_LIST/POP must not hide a
        # following GLOBAL in a .txt file. This never executes those opcodes.
        data = PickleOpcodeReader(data, self.limits["max_pickle_argument"], unconfirmed_probe=True)
        data.seek(0)
        try:
            for count, (opcode, argument, position) in enumerate(pickletools.genops(data), 1):
                if count > self.limits["max_pickle_opcodes"]:
                    raise Incomplete("pickle_opcode_limit")
                if opcode.name == "PROTO":
                    # An explicit protocol declaration establishes the format;
                    # retain the strict operand fence even if called directly.
                    data.unconfirmed_probe = False
                    if not 0 <= argument <= 5:
                        raise Incomplete("unsupported_container_or_serialization")
                if isinstance(argument, (bytes, str)) and len(argument) > self.limits["max_pickle_argument"]:
                    raise Incomplete("pickle_argument_limit")
                # OBJ consumes a previously populated MARK/callable stack. At
                # byte zero it cannot instantiate anything, and the ordinary
                # letter 'o' alone does not establish a Pickle context. Keep
                # disassembling: later references, STOP and explicit protocols
                # retain all existing strict routing and allocation fences.
                # Known Pickle extensions bypass this unconfirmed probe.
                if count == 1 and position == 0 and opcode.name == "OBJ":
                    continue
                if opcode.name in {"STOP", "GLOBAL", "STACK_GLOBAL", "INST", "OBJ", "REDUCE", "BUILD", "NEWOBJ", "NEWOBJ_EX", "EXT1", "EXT2", "EXT4", "PERSID", "BINPERSID"}:
                    return True
        except (ValueError, UnicodeError, EOFError):
            return False
        finally:
            data.seek(0)
        return False

    def member_chain(self, archive_chain, member_index, name):
        if len(archive_chain) >= MAX_EVIDENCE_CHAIN:
            raise Incomplete("archive_depth_limit")
        # Only an index and digest leave this parser. Do not expose raw names,
        # repository paths, artifact IDs, or opcode arguments in the report.
        name_sha = hashlib.sha256(name.encode("utf-8", "surrogatepass")).hexdigest()
        return archive_chain + ((member_index, name_sha),)

    def inspect_member(self, source, name, depth, expected=None, archive_chain=()):
        self.members += 1
        if self.members > self.limits["max_members"]:
            raise Incomplete("archive_member_limit")
        remaining = self.limits["max_expanded_bytes"] - self.expanded
        with tempfile.SpooledTemporaryFile(max_size=1 << 20, mode="w+b") as out:
            n = bounded_copy(source, out, remaining)
            if expected is not None and n != expected:
                raise Incomplete("archive_member_size")
            self.expanded += n
            out.seek(0)
            self.inspect(out, name, depth, archive_chain)

    def inspect_zip(self, data, depth, archive_chain=()):
        if depth == 0 and not archive_chain:
            def metadata_inspection(member, index, name):
                chain = self.member_chain(archive_chain, index, name)
                self.inspect_pickle(member, chain,
                                    _parameter_context=getattr(member, "_zip_parameter_context", None))
            try:
                proof = verify_framework_zip(data, metadata_inspection, self.limits)
            except LayoutError as error:
                raise Incomplete(error.code) from None
            if proof is not None:
                if proof["memberCount"] > self.limits["max_members"] - self.members:
                    raise Incomplete("archive_member_limit")
                if proof["metadataBytes"] > self.limits["max_expanded_bytes"] - self.expanded:
                    raise Incomplete("expanded_bytes_limit")
                self.members += proof["memberCount"]
                self.expanded += proof["metadataBytes"]
                self.verified_raw_storage_bytes = proof["storageBytes"]
                self.verified_framework_zip = proof
                return
            # Unrelated ZIPs and unoptimized protocols retain complete generic
            # traversal, with exactly the existing expansion and temp limits.
            data.seek(0)
        # ZipFile eagerly materializes its full central directory. Bound it
        # before construction at EVERY depth, not only in the top-level
        # framework selector. Directory entries consume the same global
        # member budget as files and cannot be used as uncounted filler.
        remaining = dict(self.limits, max_members=self.limits["max_members"] - self.members)
        try:
            bounded_zip_names(data, remaining)
        except LayoutError as error:
            raise Incomplete(error.code) from None
        data.seek(0)
        with zipfile.ZipFile(data) as archive:
            names = set()
            for member_index, member in enumerate(archive.infolist()):
                if member.flag_bits & 1:
                    raise Incomplete("encrypted_archive")
                kind = stat.S_IFMT(member.external_attr >> 16)
                if kind == stat.S_IFLNK:
                    raise Incomplete("archive_symlink")
                if member.is_dir():
                    if kind not in {0, stat.S_IFDIR}:
                        raise Incomplete("archive_link_or_special_file")
                    validate_zip_directory_member(data, archive, member)
                    self.members += 1
                    if self.members > self.limits["max_members"]:
                        raise Incomplete("archive_member_limit")
                    continue
                if kind not in {0, stat.S_IFREG}:
                    raise Incomplete("archive_link_or_special_file")
                if member.filename in names:
                    raise Incomplete("duplicate_archive_member")
                names.add(member.filename)
                if member.file_size > self.limits["max_expanded_bytes"] - self.expanded:
                    raise Incomplete("expanded_bytes_limit")
                if member.file_size > max(1, member.compress_size) * self.limits["max_ratio"]:
                    raise Incomplete("archive_ratio_limit")
                with archive.open(member) as source:
                    chain = self.member_chain(archive_chain, member_index, member.filename)
                    self.inspect_member(source, member.filename, depth + 1, member.file_size, chain)

    def inspect_tar(self, data, depth, archive_chain=()):
        # TarFile consumes PAX/GNU extension records internally, before it
        # yields a logical TarInfo. Fence physical headers and extension bytes
        # first so neither recursion nor hidden metadata escapes our budget.
        extension_count, extension_bytes = bounded_tar_headers(
            data, self.limits["max_members"] - self.members,
            self.limits["max_expanded_bytes"] - self.expanded,
            self.limits["max_file_bytes"],
        )
        self.members += extension_count
        self.expanded += extension_bytes
        data.seek(0)
        with tarfile.open(fileobj=data, mode="r|*") as archive:
            for member_index, member in enumerate(archive):
                if member.isdir():
                    self.members += 1
                    if self.members > self.limits["max_members"]:
                        raise Incomplete("archive_member_limit")
                    continue
                if not member.isfile():
                    raise Incomplete("archive_link_or_special_file")
                if member.size > self.limits["max_expanded_bytes"] - self.expanded:
                    raise Incomplete("expanded_bytes_limit")
                with archive.extractfile(member) as source:
                    chain = self.member_chain(archive_chain, member_index, member.name)
                    self.inspect_member(source, member.name, depth + 1, member.size, chain)

    def inspect_pickle(self, data, archive_chain=(), stream_index_base=0, *, _parameter_context=None):
        # genops disassembles only. Never instantiate an Unpickler or import a
        # module referenced by an opcode. Parse ALL bytes/concatenated streams.
        original_stream = data
        data = PickleOpcodeReader(data, self.limits["max_pickle_argument"])
        data.seek(0)
        streams = 0
        reference_location = None
        dangerous_recorded = False
        reference_categories = {}
        symbols = SymbolicReferences(self.limits["max_pickle_opcodes"])
        fresh_symbols = None
        write_types = ContainerWriteTypes(self.limits["max_pickle_opcodes"])
        fresh_write_types = None
        while data.read(1):
            data.seek(-1, io.SEEK_CUR)
            stopped = False
            for opcode, argument, offset in pickletools.genops(data):
                self.opcodes += 1
                if self.opcodes > self.limits["max_pickle_opcodes"]:
                    raise Incomplete("pickle_opcode_limit")
                # genops accepts a byte-valued declaration even when no
                # supported Pickle loader understands that protocol.
                if opcode.name == "PROTO" and not 0 <= argument <= 5:
                    raise Incomplete("unsupported_container_or_serialization")
                if isinstance(argument, (bytes, str)) and len(argument) > self.limits["max_pickle_argument"]:
                    raise Incomplete("pickle_argument_limit")
                if opcode.name in {"EXT1", "EXT2", "EXT4"}:
                    raise Incomplete("pickle_extension_registry_unsupported")
                matched = symbols.apply(opcode, argument)
                if fresh_symbols is not None:
                    fresh_matched = fresh_symbols.apply(opcode, argument)
                    if fresh_matched != matched:
                        raise Incomplete("pickle_symbol_analysis_incomplete")
                    if symbols.slot_count() + fresh_symbols.slot_count() > self.limits["max_pickle_opcodes"]:
                        raise Incomplete("pickle_symbol_budget")
                dangerous_reference = False
                if not dangerous_recorded and matched is not None:
                    # Classification is pure under the pinned rules for this
                    # invocation. Repeated symbols need not rebuild the same
                    # Picklescan classification; the existing symbolic/global
                    # budget bounds the number of memoized keys.
                    dangerous_reference = reference_categories.get(matched)
                    if dangerous_reference is None:
                        dangerous_reference = known_dangerous_reference(matched)
                        reference_categories[matched] = dangerous_reference
                if dangerous_reference:
                    self.findings.append(finding("picklescan", "pickle.dangerous-global", "critical",
                                                 "Static analysis found a dangerous callable reference."))
                    dangerous_recorded = True
                    if len(self.findings) > 4096:
                        raise Incomplete("finding_limit")
                if reference_location is None and matched == NESTED_DESERIALIZATION_SYMBOL:
                    reference_location = (streams, offset)
                    # Preserve an established reference even if later bytes fail
                    # complete analysis. This is observed evidence, not a claim
                    # that a truncated/unsupported Pickle is completely covered.
                    evidence = {"knownSymbolId": NESTED_DESERIALIZATION_SYMBOL_ID,
                                "observation": "reference", "source": "pickletools",
                                "archiveMemberChain": [{"memberIndex": index, "nameSha256": digest}
                                                       for index, digest in archive_chain] or None,
                                "streamIndex": stream_index_base + streams, "opcodeOffset": offset}
                    self.findings.append(finding(
                        "picklescan", "pickle.nested-deserialization-reference", "high",
                        "Static analysis found a reference to a restricted nested-deserialization capability; "
                        "this does not prove invocation or malicious execution.", evidence))
                    if len(self.findings) > 4096:
                        raise Incomplete("finding_limit")
                # Keep established dangerous/nested-reference evidence even
                # when a later container write fails its independent type proof.
                write_types.apply(opcode, argument)
                if fresh_write_types is not None:
                    fresh_write_types.apply(opcode, argument)
                # Each abstract domain has its own bounded state budget. Do
                # not halve the established symbol budget by double-counting
                # the independent type observer (e.g. N followed by STOP).
                slots = symbols.slot_count()
                write_slots = write_types.slot_count()
                if fresh_symbols is not None:
                    slots += fresh_symbols.slot_count()
                    write_slots += fresh_write_types.slot_count()
                if max(slots, write_slots) > self.limits["max_pickle_opcodes"]:
                    raise Incomplete("pickle_symbol_budget")
                if opcode.name == "STOP":
                    stopped = True
            if not stopped:
                raise Incomplete("malformed_pickle")
            streams += 1
            symbols.next_stream()
            write_types.next_stream()
            # Later streams must be unambiguous under both retained-memo and
            # fresh-Unpickler interpretations. Unsupported/ambiguous operands
            # fail closed; neither interpretation may silently win.
            fresh_symbols = SymbolicReferences(self.limits["max_pickle_opcodes"])
            fresh_write_types = ContainerWriteTypes(self.limits["max_pickle_opcodes"])
        if not streams:
            raise Incomplete("empty_pickle")
        data.seek(0)
        from picklescan.scanner import scan_pickle_bytes, SafetyLevel
        try:
            result = scan_pickle_bytes(data, "artifact", multiple_pickles=True, strict=False)
        finally:
            data.check_budget()
        if result.scan_err or result.scanned_files < 1:
            raise Incomplete("pickle_analysis_incomplete")
        reported_globals = {(g.module, g.name) for g in result.globals}
        if symbols.globals - reported_globals - {NESTED_DESERIALIZATION_SYMBOL}:
            # Do not advertise other analyzer disagreements (including memo
            # obscured dangerous globals) as complete medium/safe results.
            raise Incomplete("pickle_symbol_analysis_disagreement")
        self.pickle_files += 1
        actual_globals = [g for g in result.globals if (g.module, g.name) in symbols.globals]
        dangerous = any(g.safety == SafetyLevel.Dangerous for g in actual_globals)
        suspicious_pairs = {(g.module, g.name) for g in actual_globals
                            if g.safety == SafetyLevel.Suspicious and
                            (g.module, g.name) != NESTED_DESERIALIZATION_SYMBOL}
        proof_error = None
        if _PARAMETER_SYMBOL in suspicious_pairs and type(_parameter_context) is _ZipParameterContext:
            try:
                suspicious_pairs -= _parameter_context.prove(original_stream, archive_chain, self.limits)
            except LegacyTorchError as error:
                proof_error = error.code
        suspicious = bool(suspicious_pairs)
        if dangerous and not dangerous_recorded:
            self.findings.append(finding("picklescan", "pickle.dangerous-global", "critical", "Static analysis found a dangerous callable reference."))
        if suspicious:
            self.findings.append(finding("picklescan", "pickle.unknown-global", "medium", "Static analysis found a callable reference requiring review."))
            # Strict v11 capability profile: a risk threshold cannot
            # turn unknown callable semantics into complete coverage.
            raise Incomplete(proof_error or "unsupported_container_or_serialization")
        if len(self.findings) > 4096:
            raise Incomplete("finding_limit")

    def validate_safetensors(self, data):
        data.seek(0, io.SEEK_END)
        size = data.tell()
        data.seek(0)
        header_length = int.from_bytes(data.read(8), "little")
        if not 2 <= header_length <= min(8 << 20, max(0, size - 8)):
            raise Incomplete("invalid_safetensors_header")
        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise Incomplete("invalid_safetensors_header")
                result[key] = value
            return result

        raw = data.read(header_length)
        if not raw.startswith(b"{"):
            raise Incomplete("invalid_safetensors_header")
        try:
            header = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
        except (ValueError, UnicodeError, RecursionError):
            # A hostile deeply nested header is an unsupported artifact, not
            # an unhandled interpreter recursion failure for the whole batch.
            raise Incomplete("invalid_safetensors_header") from None
        if not isinstance(header, dict):
            raise Incomplete("invalid_safetensors_header")
        # These are fixed supported-profile limits, bound into generation by
        # scanner source identity. They do not classify oversized input as
        # malware and must never authorize a partially inspected header.
        if len(header) - int("__metadata__" in header) > SAFETENSORS_MAX_TENSORS:
            raise Incomplete("invalid_safetensors_header")
        payload_size = size - 8 - header_length
        spans = []
        for key, value in header.items():
            if key == "__metadata__":
                if not isinstance(value, dict) or any(not isinstance(v, str) for v in value.values()):
                    raise Incomplete("invalid_safetensors_header")
                continue
            if not isinstance(value, dict) or set(value) != {"dtype", "shape", "data_offsets"}:
                raise Incomplete("invalid_safetensors_header")
            dtype, shape = value["dtype"], value["shape"]
            if (not isinstance(dtype, str) or dtype not in SAFETENSORS_BITS
                    or not isinstance(shape, list) or len(shape) > SAFETENSORS_MAX_RANK):
                raise Incomplete("invalid_safetensors_header")
            elements = 1
            for dimension in shape:
                if type(dimension) is not int or not 0 <= dimension <= (1 << 64) - 1:
                    raise Incomplete("invalid_safetensors_header")
                elements *= dimension
                if elements > (1 << 64) - 1:
                    raise Incomplete("invalid_safetensors_offsets")
            bits = elements * SAFETENSORS_BITS[dtype]
            if bits > (1 << 64) - 1 or bits % 8:
                raise Incomplete("invalid_safetensors_offsets")
            if not isinstance(value.get("data_offsets"), list) or len(value["data_offsets"]) != 2:
                raise Incomplete("invalid_safetensors_offsets")
            lo, hi = value["data_offsets"]
            if type(lo) is not int or type(hi) is not int or not 0 <= lo <= hi <= payload_size or hi - lo != bits // 8:
                raise Incomplete("invalid_safetensors_offsets")
            spans.append((lo, hi))
        covered = 0
        for lo, hi in sorted(spans):
            if lo != covered:
                raise Incomplete("invalid_safetensors_offsets")
            covered = hi
        if covered != payload_size:
            raise Incomplete("invalid_safetensors_offsets")


def scan_clamav(data, rules, limits):
    data.seek(0)
    argv = ["/usr/local/bin/clamscan", "--database=" + rules, "--stdout", "--no-summary", "--infected",
            "--max-filesize=" + str(limits["max_file_bytes"]),
            "--max-scansize=" + str(limits["max_scan_bytes"]),
            "--pcre-max-filesize=" + str(limits["max_file_bytes"]), "--disable-cache=yes",
            "--max-files=" + str(limits["max_members"]),
            "--max-recursion=" + str(limits["max_depth"] + 2),
            "--max-scantime=" + str(limits["wall_seconds"] * 1000),
            "--alert-exceeds-max=yes", "--alert-encrypted=yes", "--alert-broken=yes", "-"]
    # Output goes into bounded tmpfs files, never unbounded communicate() RAM.
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        proc = subprocess.run(argv, stdin=data, stdout=out, stderr=err, timeout=limits["wall_seconds"],
                              preexec_fn=lambda: native_limits(limits))
        if out.tell() > (1 << 20) or err.tell() > (1 << 20):
            raise Incomplete("clamav_output_limit")
        out.seek(0); raw = out.read(1 << 20)
        err.seek(0); errors = err.read(1 << 20)
    if proc.returncode not in (0, 1):
        raise Incomplete("clamav_unavailable_or_failed")
    # A limit alert must never be advertised as a complete malicious-content
    # classification. Engine warnings/errors likewise cannot silently pass.
    if any(marker in raw for marker in (b"Heuristics.Limits.Exceeded", b"Heuristics.Encrypted", b"Heuristics.Broken")) or errors:
        raise Incomplete("clamav_coverage_incomplete")
    if proc.returncode == 1:
        if b" FOUND" not in raw:
            raise Incomplete("clamav_invalid_result")
        return [finding("clamav", "malware.signature-match", "critical", "ClamAV matched a malware or dangerous-content signature.")]
    if raw.strip():
        raise Incomplete("clamav_unexpected_output")
    return []


def parse_batch_clamav_output(raw, errors, returncode, paths, sizes):
    if returncode not in (0, 1):
        raise Incomplete("clamav_unavailable_or_failed")
    if errors or any(marker in raw for marker in (b"Heuristics.Limits.Exceeded", b"Heuristics.Encrypted", b"Heuristics.Broken")):
        raise Incomplete("clamav_coverage_incomplete")
    expected = {p.encode(): i for i, p in enumerate(paths)}
    results = [None] * len(paths)
    found = False
    for line in raw.splitlines():
        if not line:
            continue
        name, separator, status = line.partition(b": ")
        if separator != b": " or name not in expected:
            raise Incomplete("clamav_unknown_result")
        i = expected[name]
        if results[i] is not None:
            raise Incomplete("clamav_unknown_result")
        if status == b"OK" or (status == b"Empty file" and sizes[i] == 0):
            results[i] = []
        elif re.fullmatch(rb"[A-Za-z0-9_.:+-]{1,120} FOUND", status):
            found = True
            rule = "clamav." + status[:-6].decode("ascii")
            results[i] = [finding("clamav", rule, "critical", "ClamAV matched a malware or dangerous-content signature.")]
        else:
            # Skipped links, errors, unknown output and limits cannot be clean.
            raise Incomplete("clamav_coverage_incomplete")
    if any(result is None for result in results):
        raise Incomplete("clamav_missing_result")
    if (returncode == 1) != found:
        raise Incomplete("clamav_invalid_result")
    return results


def scan_clamav_batch(files, rules, limits):
    # Each FD was opened without symlinks and verified against its descriptor.
    # /proc/self/fd aliases preserve the held inode rather than reopening a
    # mutable repository path. Explicit OK/FOUND for EVERY FD is mandatory;
    # a platform/engine that skips proc aliases fails this entire batch.
    fds = [data.fileno() for data in files]
    paths = ["/proc/self/fd/" + str(fd) for fd in fds]
    sizes = [os.fstat(fd).st_size for fd in fds]
    for data in files:
        data.seek(0)
    argv = ["/usr/local/bin/clamscan", "--database=" + rules, "--stdout", "--no-summary",
            "--follow-file-symlinks=2", "--max-filesize=" + str(limits["max_file_bytes"]),
            "--max-scansize=" + str(limits["max_scan_bytes"]),
            "--pcre-max-filesize=" + str(limits["max_file_bytes"]), "--disable-cache=yes",
            "--max-files=" + str(limits["max_members"]),
            "--max-recursion=" + str(limits["max_depth"] + 2),
            "--max-scantime=" + str(limits["wall_seconds"] * 1000),
            "--alert-exceeds-max=yes", "--alert-encrypted=yes", "--alert-broken=yes", *paths]
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        proc = subprocess.run(argv, pass_fds=fds, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                              timeout=limits["wall_seconds"], preexec_fn=lambda: native_limits(limits))
        if out.tell() > (1 << 20) or err.tell() > (1 << 20):
            raise Incomplete("clamav_output_limit")
        out.seek(0); raw = out.read(1 << 20)
        err.seek(0); errors = err.read(1 << 20)
    return parse_batch_clamav_output(raw, errors, proc.returncode, paths, sizes)


def process_usage(pid, expected_start=None):
    try:
        fields = Path("/proc/" + str(pid) + "/stat").read_text().rsplit(") ", 1)[1].split()
        start = int(fields[19])
        if expected_start is not None and start != expected_start:
            raise Incomplete("clamav_unavailable_or_failed")
        ticks = sum(int(fields[index]) for index in [11, 12, 13, 14])
        return start, ticks / os.sysconf("SC_CLK_TCK")
    except (OSError, ValueError, IndexError):
        raise Incomplete("clamav_unavailable_or_failed") from None


def process_tree_cpu(pid):
    _, cpu = process_usage(pid)
    try:
        children = Path("/proc/" + str(pid) + "/task/" + str(pid) + "/children").read_text().split()
    except OSError:
        return cpu
    for child in children:
        with contextlib.suppress(Incomplete):
            cpu += process_tree_cpu(int(child))
    return cpu


def kill_and_reap(process):
    if process is None:
        return
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    with contextlib.suppress(ChildProcessError):
        process.wait(timeout=5)


def native_limits(limits):
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (limits["daemon_memory_bytes"], limits["daemon_memory_bytes"]))
    resource.setrlimit(resource.RLIMIT_FSIZE, (limits["native_write_file_bytes"], limits["native_write_file_bytes"]))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    # Lifetime RLIMIT_CPU is unsuitable for a persistent process. The supervisor
    # charges native CPU deltas against each request's aggregate deadline.


def check_engine_peer(connection, engine):
    try:
        pid, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if pid != engine["pid"] or uid != os.getuid():
            raise Incomplete("clamav_unavailable_or_failed")
        process_usage(pid, engine["startTime"])
    except (OSError, KeyError, struct.error):
        raise Incomplete("clamav_unavailable_or_failed") from None


def receive_clamd_reply(connection, maximum=4096):
    raw = bytearray()
    while True:
        try:
            block = connection.recv(min(1024, maximum + 1 - len(raw)))
        except socket.timeout:
            raise Incomplete("scan_timeout") from None
        if not block:
            raise Incomplete("clamav_missing_result")
        raw.extend(block)
        if len(raw) > maximum:
            raise Incomplete("clamav_output_limit")
        if b"\x00" in block:
            body, _, trailing = bytes(raw).partition(b"\x00")
            if trailing:
                raise Incomplete("clamav_unknown_result")
            try:
                if connection.recv(1):
                    raise Incomplete("clamav_unknown_result")
            except socket.timeout:
                raise Incomplete("clamav_unknown_result") from None
            return body


def parse_fildes_reply(raw, size):
    match = re.fullmatch(rb"fd\[[0-9]{1,10}\]: (.+)", raw)
    if not match:
        raise Incomplete("clamav_unknown_result")
    status = match[1]
    if status == b"OK" or (status == b"Empty file" and size == 0):
        return []
    if any(marker in status for marker in (b"Heuristics.Limits.Exceeded", b"Heuristics.Encrypted", b"Heuristics.Broken")):
        raise Incomplete("clamav_coverage_incomplete")
    if not re.fullmatch(rb"[A-Za-z0-9_.:+-]{1,120} FOUND", status):
        raise Incomplete("clamav_coverage_incomplete")
    return [finding("clamav", "clamav." + status[:-6].decode("ascii"), "critical",
                    "ClamAV matched a malware or dangerous-content signature.")]


def native_file_waves(files, limits):
    """Plan original-order waves from held, previously verified regular FDs."""
    waves, wave, total = [], [], 0
    for data in files:
        info = os.fstat(data.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 <= info.st_size <= NATIVE_WAVE_BYTES:
            raise Incomplete("snapshot_size")
        if wave and (len(wave) >= limits["native_threads"] or total + info.st_size > NATIVE_WAVE_BYTES):
            waves.append(wave)
            wave, total = [], 0
        wave.append((data, info.st_size))
        total += info.st_size
    if wave:
        waves.append(wave)
    return waves


def scan_clamd_wave(wave, scan_one, stop_connections):
    """Join one bounded wave completely before another wave can start."""
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=len(wave), thread_name_prefix="native-av")
    futures, complete = [], False
    try:
        futures = [executor.submit(scan_one, data, size) for data, size in wave]
        done, _ = concurrent.futures.wait(futures, return_when=concurrent.futures.FIRST_EXCEPTION)
        failed = next((future for future in futures if future in done and future.exception() is not None), None)
        if failed is not None:
            stop_connections()
            failed.result()
        results = [future.result() for future in futures]
        complete = True
        return results
    finally:
        if not complete:
            stop_connections()
        for future in futures:
            future.cancel()
        executor.shutdown(wait=True, cancel_futures=True)


def scan_clamd_files(files, engine, limits):
    # Only files in this single admitted request share the daemon. Each file
    # has its own held FD and socket; static inspection starts after every AV
    # operation has joined. A failed operation invalidates the whole batch.
    deadline = time.monotonic() + limits["wall_seconds"]
    cancelled, connections_lock, connections = threading.Event(), threading.Lock(), set()

    def stop_connections():
        with connections_lock:
            cancelled.set()
            for connection in connections:
                with contextlib.suppress(OSError):
                    connection.shutdown(socket.SHUT_RDWR)

    def scan_one(data, expected_size=None):
        data.seek(0)
        size = os.fstat(data.fileno()).st_size
        if expected_size is not None and size != expected_size:
            raise Incomplete("snapshot_size")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                with connections_lock:
                    if cancelled.is_set():
                        raise Incomplete("clamav_unavailable_or_failed")
                    connections.add(connection)
                try:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise Incomplete("scan_timeout")
                    connection.settimeout(remaining)
                    connection.connect(engine["socket"])
                    check_engine_peer(connection, engine)
                    connection.sendall(b"zFILDES\x00")
                    rights = array.array("i", [data.fileno()])
                    if connection.sendmsg([b"\x00"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)]) != 1:
                        raise Incomplete("clamav_unavailable_or_failed")
                    result = parse_fildes_reply(receive_clamd_reply(connection), size)
                    process_usage(engine["pid"], engine["startTime"])
                    return result
                finally:
                    with connections_lock:
                        connections.discard(connection)
        except socket.timeout:
            raise Incomplete("scan_timeout") from None
        except (OSError, KeyError):
            raise Incomplete("clamav_unavailable_or_failed") from None

    concurrency = min(limits.get("native_threads", 1), len(files))
    if concurrency <= 1:
        return [scan_one(data) for data in files]
    # At most 32 descriptors and four active sockets exist. The fixed 2 GiB
    # byte ceiling uses verified held-FD sizes and preserves original order.
    # This limits pressure, but is not a mathematical memory-use guarantee.
    # Shutdown interrupts
    # sibling receives before joining, so no thread can keep using an FD after
    # the caller releases its snapshot. The supervisor still owns CPU/wall,
    # peer cancellation and whole-process-group termination for this request.
    results = []
    try:
        for wave in native_file_waves(files, limits):
            # One deadline and cancellation domain span all waves. The outer
            # supervisor charges aggregate CPU throughout, without resetting.
            results.extend(scan_clamd_wave(wave, scan_one, stop_connections))
        return results
    finally:
        stop_connections()


def verify_held_snapshot(data, artifact, original):
    info = os.fstat(data.fileno())
    if info.st_size != artifact["size"]:
        raise Incomplete("snapshot_size")
    if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) != original:
        raise Incomplete("snapshot_digest")
    data.seek(0)
    actual = stream_sha256(data)
    info = os.fstat(data.fileno())
    if ((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) != original
            or actual != artifact["sha256"]):
        raise Incomplete("snapshot_digest")
    data.seek(0)



class PersistentClamAV:
    """Own a single fixed native daemon; an aborted attempt is never retried."""
    LOG_LIMIT = 1 << 20

    def __init__(self, rules, limits, evidence, directory):
        self.rules, self.limits, self.evidence = rules, limits, evidence
        self.directory = Path(directory)
        self.config_path = self.directory / "engine.conf"
        self.config = clamd_configuration(rules, limits, self.directory)
        self.runtime_config_sha = hashlib.sha256(self.config).hexdigest()
        self.lock = threading.RLock()
        self.ready, self.closed, self.recovering = False, False, False
        self.process, self.start_time, self.epoch = None, None, 0
        self.logs = [tempfile.TemporaryFile(), tempfile.TemporaryFile()]
        self.offsets = [0, 0]
        self.directory.mkdir(mode=0o700)
        self.config_path.write_bytes(self.config)
        self.config_path.chmod(0o400)
        self._verify_fixed()

    def _verify_fixed(self):
        if rule_inventory(self.rules) != self.evidence["rules"]:
            raise Incomplete("rules_changed")
        info = self.config_path.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o400:
            raise Incomplete("clamav_unavailable_or_failed")
        if (self.config_path.read_bytes() != self.config
                or hashlib.sha256(self.config_path.read_bytes()).hexdigest() != self.runtime_config_sha
                or hashlib.sha256(self.config).hexdigest() != self.evidence["engine_config_sha256"]
                or file_sha("/usr/local/sbin/clamd") != self.evidence["engine_binary_sha256"]):
            raise Incomplete("clamav_unavailable_or_failed")
        info = self.directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise Incomplete("clamav_unavailable_or_failed")

    def _descriptor(self):
        if self.process is None or self.process.poll() is not None:
            raise Incomplete("clamav_unavailable_or_failed")
        process_usage(self.process.pid, self.start_time)
        return {"socket": str(self.directory / "engine.sock"), "pid": self.process.pid,
                "startTime": self.start_time, "epoch": self.epoch,
                "configSha256": self.runtime_config_sha}

    def _check_logs(self):
        # pread does not disturb the daemon's shared write offset. Retention is
        # bounded over the daemon lifetime, so repeated requests cannot fill tmpfs.
        for index, output in enumerate(self.logs):
            size = os.fstat(output.fileno()).st_size
            if size < self.offsets[index] or size > self.LOG_LIMIT:
                raise Incomplete("clamav_output_limit")
            raw = os.pread(output.fileno(), size, 0)
            if len(raw) != size:
                raise Incomplete("clamav_output_limit")
            if (index == 1 and raw.strip()) or re.search(rb"(?i)(?:^|[\s:])(warning|error|fatal)(?:[\s:!]|$)", raw):
                raise Incomplete("clamav_coverage_incomplete")
            self.offsets[index] = size

    def _control(self, command, descriptor):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(2)
                connection.connect(descriptor["socket"])
                check_engine_peer(connection, descriptor)
                connection.sendall(b"z" + command + b"\x00")
                return receive_clamd_reply(connection, 4096)
        except (OSError, KeyError):
            raise Incomplete("clamav_unavailable_or_failed") from None

    def start(self):
        with self.lock:
            if self.closed:
                raise Incomplete("clamav_unavailable_or_failed")
            self.ready = False
            self._verify_fixed()
            socket_path = self.directory / "engine.sock"
            if socket_path.exists() or socket_path.is_symlink():
                info = socket_path.lstat()
                if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
                    raise Incomplete("clamav_unavailable_or_failed")
                socket_path.unlink()
            # Reset only after the previous owned daemon has been reaped.
            for output in self.logs:
                output.seek(0); output.truncate(0)
            self.offsets = [0, 0]
            self.process = subprocess.Popen(["/usr/local/sbin/clamd", "--foreground",
                                            "--config-file=" + str(self.config_path)],
                                           stdin=subprocess.DEVNULL, stdout=self.logs[0], stderr=self.logs[1],
                                           start_new_session=True,
                                           env={"PATH": "/usr/bin:/bin", "TMPDIR": "/tmp"},
                                           preexec_fn=lambda: native_limits(self.limits))
            self.start_time, initial_cpu = process_usage(self.process.pid)
            self.epoch += 1
            descriptor = self._descriptor()
        deadline = time.monotonic() + self.limits["startup_seconds"]
        try:
            while True:
                with self.lock:
                    if self.closed:
                        raise Incomplete("clamav_unavailable_or_failed")
                    self._descriptor()
                    self._check_logs()
                    cpu = process_usage(descriptor["pid"], descriptor["startTime"])[1] - initial_cpu
                    if cpu > self.limits["startup_seconds"] or time.monotonic() >= deadline:
                        raise Incomplete("scan_timeout")
                if socket_path.exists():
                    info = socket_path.lstat()
                    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                        raise Incomplete("clamav_unavailable_or_failed")
                    if self._control(b"PING", descriptor) != b"PONG":
                        raise Incomplete("clamav_invalid_result")
                    version = self._control(b"VERSIONCOMMANDS", descriptor)
                    if not version.startswith(b"ClamAV 1.4.6") or b"FILDES" not in version:
                        raise Incomplete("clamav_invalid_result")
                    with self.lock:
                        self._verify_fixed()
                        self._check_logs()
                        self._descriptor()
                        self.ready = True
                    return
                time.sleep(0.05)
        except BaseException:
            with self.lock:
                self.ready = False
                kill_and_reap(self.process)
                self.process = None
            raise

    def healthy(self):
        with self.lock:
            if not self.ready or self.closed:
                return False
            try:
                self._descriptor()
                self._check_logs()
                return True
            except Incomplete:
                return False

    def begin(self):
        with self.lock:
            if not self.ready or self.closed:
                raise Incomplete("clamav_unavailable_or_failed")
            self._verify_fixed()
            descriptor = self._descriptor()
            self._check_logs()
            return descriptor, process_usage(descriptor["pid"], descriptor["startTime"])[1]

    def check_request(self, descriptor):
        with self.lock:
            if not self.ready or self.closed or descriptor != self._descriptor():
                raise Incomplete("clamav_unavailable_or_failed")
            self._check_logs()
            return process_usage(descriptor["pid"], descriptor["startTime"])[1]

    def finish(self, descriptor):
        with self.lock:
            self.check_request(descriptor)
            self._verify_fixed()

    def abort(self, expected_epoch=None, only_if_unhealthy=False):
        with self.lock:
            if self.recovering or (expected_epoch is not None and expected_epoch != self.epoch):
                return
            if only_if_unhealthy and self.healthy():
                return
            self.ready = False
            try:
                kill_and_reap(self.process)
            except BaseException:
                self.closed = True  # no replacement without proven reap
                raise
            self.process = None
            if self.closed:
                return
            self.recovering = True
        def recover():
            try:
                self.start()
            except BaseException:
                # Immutable rules/config changes cannot be blessed by a restart.
                pass
            finally:
                with self.lock:
                    self.recovering = False
        threading.Thread(target=recover, name="native-engine-recovery", daemon=True).start()

    def close(self):
        with self.lock:
            self.closed, self.ready = True, False
            kill_and_reap(self.process)
            self.process = None
            for output in self.logs:
                output.close()
            for path in [self.directory / "engine.sock", self.config_path]:
                with contextlib.suppress(FileNotFoundError):
                    path.unlink()
            with contextlib.suppress(FileNotFoundError, OSError):
                self.directory.rmdir()


# LAB-only opt-in archive capacity support. Inlined after PersistentClamAV.
# All names used below come from the scanner's existing stdlib imports.
ARCHIVE_TEMP_ROOT = "/native-tmp"
ARCHIVE_TEMP_BYTES = 1536 << 20


def native_scratch_path(directory):
    name = Path(directory).name
    if not re.fullmatch(r"matrix-clamd-[a-f0-9]{16}", name):
        raise Incomplete("clamav_unavailable_or_failed")
    return Path(ARCHIVE_TEMP_ROOT) / name


def process_group_absent(pid):
    try:
        os.killpg(pid, 0)
    except ProcessLookupError:
        return True
    except OSError:
        return False
    return False


class ArchiveScratch:
    """A held, private tmpfs directory; never removes the mount or other roots."""
    def __init__(self, directory):
        self.root_fd = self.child_fd = None
        self.path = native_scratch_path(directory)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            self.root_fd = os.open(ARCHIVE_TEMP_ROOT, flags)
            self.root_identity = self.identity(os.fstat(self.root_fd))
            self.verify_root()
            if os.listdir(self.root_fd):
                raise Incomplete("clamav_unavailable_or_failed")
            os.mkdir(self.path.name, 0o700, dir_fd=self.root_fd)
            self.child_fd = os.open(self.path.name, flags, dir_fd=self.root_fd)
            self.child_identity = self.identity(os.fstat(self.child_fd))
            self.verify()
        except BaseException:
            self.close_fds()
            raise

    @staticmethod
    def identity(info):
        return info.st_dev, info.st_ino

    @staticmethod
    def private_directory(info):
        return (stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                and info.st_gid == os.getgid() and stat.S_IMODE(info.st_mode) == 0o700)

    def verify_root(self):
        held = os.fstat(self.root_fd)
        named = os.stat(ARCHIVE_TEMP_ROOT, follow_symlinks=False)
        if (self.identity(held) != self.root_identity or self.identity(named) != self.root_identity
                or not self.private_directory(held) or not self.private_directory(named)):
            raise Incomplete("clamav_unavailable_or_failed")
        with open("/proc/self/mountinfo", "rb") as stream:
            raw = stream.read((1 << 20) + 1)
        if len(raw) > (1 << 20):
            raise Incomplete("clamav_unavailable_or_failed")
        rows = [line.split() for line in raw.splitlines() if len(line.split()) > 6
                and line.split()[4] == b"/native-tmp"]
        if len(rows) != 1:
            raise Incomplete("clamav_unavailable_or_failed")
        row = rows[0]
        split = row.index(b"-") if b"-" in row else len(row)
        if (split + 3 >= len(row) or row[split + 1] != b"tmpfs"
                or not {b"rw", b"noexec", b"nosuid", b"nodev"} <= set(row[5].split(b","))):
            raise Incomplete("clamav_unavailable_or_failed")
        space = os.fstatvfs(self.root_fd)
        if space.f_blocks * space.f_frsize != ARCHIVE_TEMP_BYTES:
            raise Incomplete("clamav_unavailable_or_failed")

    def verify(self):
        self.verify_root()
        held = os.fstat(self.child_fd)
        named = os.stat(self.path.name, dir_fd=self.root_fd, follow_symlinks=False)
        if (self.identity(held) != self.child_identity or self.identity(named) != self.child_identity
                or held.st_dev != self.root_identity[0] or not self.private_directory(held)
                or not self.private_directory(named)):
            raise Incomplete("clamav_unavailable_or_failed")
        # One supervisor owns this fresh mount. Unexpected siblings are retained.
        if os.listdir(self.root_fd) != [self.path.name]:
            raise Incomplete("clamav_unavailable_or_failed")

    def clear(self):
        self.verify()
        remaining = [4096]
        self._clear_directory(self.child_fd, self.root_identity[0], remaining, 0)
        self.verify()
        if os.listdir(self.child_fd):
            raise Incomplete("clamav_unavailable_or_failed")

    @classmethod
    def _clear_directory(cls, directory_fd, device, remaining, depth):
        if depth > 16:
            raise Incomplete("clamav_unavailable_or_failed")
        # Bounded iteration, not a recursively materialized list of paths.
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                remaining[0] -= 1
                if remaining[0] < 0 or entry.name in {".", ".."} or "/" in entry.name:
                    raise Incomplete("clamav_unavailable_or_failed")
                info = os.stat(entry.name, dir_fd=directory_fd, follow_symlinks=False)
                if info.st_dev != device or info.st_uid != os.getuid():
                    raise Incomplete("clamav_unavailable_or_failed")
                if stat.S_ISDIR(info.st_mode):
                    child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                    dir_fd=directory_fd)
                    try:
                        if cls.identity(os.fstat(child)) != cls.identity(info):
                            raise Incomplete("clamav_unavailable_or_failed")
                        cls._clear_directory(child, device, remaining, depth + 1)
                        if cls.identity(os.stat(entry.name, dir_fd=directory_fd, follow_symlinks=False)) != cls.identity(info):
                            raise Incomplete("clamav_unavailable_or_failed")
                    finally:
                        os.close(child)
                    os.rmdir(entry.name, dir_fd=directory_fd)
                elif stat.S_ISLNK(info.st_mode) or (stat.S_ISREG(info.st_mode) and info.st_nlink == 1):
                    # Unlinking a symlink removes only the owned link, never its target.
                    os.unlink(entry.name, dir_fd=directory_fd)
                else:
                    raise Incomplete("clamav_unavailable_or_failed")

    def remove(self):
        self.clear()
        os.rmdir(self.path.name, dir_fd=self.root_fd)
        self.close_fds()

    def close_fds(self):
        for attribute in ("child_fd", "root_fd"):
            descriptor = getattr(self, attribute, None)
            if descriptor is not None:
                os.close(descriptor)
                setattr(self, attribute, None)


class ArchivePersistentClamAV(PersistentClamAV):
    """Archive-only capacity: restart cleanup follows proven process quiescence."""
    def __init__(self, rules, limits, evidence, directory):
        self.worker_state = None
        self.native_groups = set()
        self.scratch = None
        super().__init__(rules, limits, evidence, directory)
        self.scratch = ArchiveScratch(directory)

    def _descriptor(self):
        if self.process is not None:
            self.native_groups.add(self.process.pid)
        return super()._descriptor()

    def _quiescent(self):
        state = self.worker_state
        if state is None or state.get("unsafe"):
            return False
        with state["workers_lock"]:
            if any(process.poll() is None or not process_group_absent(process.pid)
                   for process in state["workers"]):
                return False
        return all(process_group_absent(pid) for pid in self.native_groups)

    def start(self):
        state = self.worker_state
        if state is None or not state["semaphore"].acquire(timeout=5):
            raise Incomplete("clamav_unavailable_or_failed")
        try:
            # The API semaphore covers requests before spawn through worker reap.
            # Holding it prevents a descriptor obtained before abort from spawning
            # a worker after the quiescence check.
            with self.lock:
                if self.closed or state.get("closing") or not self._quiescent():
                    raise Incomplete("clamav_unavailable_or_failed")
                self.ready = False
                self.scratch.clear()
                self.native_groups.clear()
            try:
                super().start()
            except BaseException:
                with self.lock:
                    self.ready = False
                    if self.process is not None:
                        self.native_groups.add(self.process.pid)
                        kill_and_reap(self.process)
                        self.process = None
                raise
        finally:
            state["semaphore"].release()

    def close(self):
        with self.lock:
            if self.process is not None:
                self.native_groups.add(self.process.pid)
            try:
                super().close()
                if self.scratch is not None:
                    if not self._quiescent():
                        raise Incomplete("clamav_unavailable_or_failed")
                    self.scratch.remove()
                    self.scratch = None
            finally:
                if self.scratch is not None:
                    # Retain uncertain scratch. The owned container teardown is
                    # the final boundary; no cleanup of a possibly active tree.
                    self.scratch.close_fds()


def child_limits(limits):
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (limits["cpu_seconds"], limits["cpu_seconds"]))
    resource.setrlimit(resource.RLIMIT_AS, (limits["memory_bytes"], limits["daemon_memory_bytes"]))
    # Keep the static worker soft limit. Its hard ceiling permits only the
    # trusted native child to adopt the fixed derived native write-file cap.
    resource.setrlimit(resource.RLIMIT_FSIZE, (limits["temp_bytes"], limits["native_write_file_bytes"]))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))


def worker(request, input_root, rules):
    logging.disable(logging.CRITICAL)  # scanner logs may contain untrusted operands
    limits = request["limits"]
    child_limits(limits)
    check_rules_expiry(limits)
    batch = request.get("batch", False)
    artifacts = validate_batch({"artifacts": request["artifacts"]}, limits) if batch else [validate_artifact(request["artifact"], limits)]
    started = time.monotonic()
    # The worker independently verifies rules both sides of analysis. Rules
    # mutation makes this attempt incomplete; it cannot reuse old generation.
    if rule_inventory(rules) != request["evidence"]["rules"]:
        raise Incomplete("rules_changed")
    with contextlib.ExitStack() as opened:
        # Verify every descriptor before any analysis. Binding failures are not
        # artifact format failures and must invalidate the entire request.
        files = [opened.enter_context(open_verified(input_root, artifact)) for artifact in artifacts]
        identities = [(info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                      for info in [os.fstat(data.fileno()) for data in files]]
        if request.get("backend", "clamscan") == "clamd":
            antivirus_findings = scan_clamd_files(files, request["engine"], limits)
        elif request.get("backend", "clamscan") == "clamscan":
            antivirus_findings = scan_clamav_batch(files, rules, limits) if batch else [scan_clamav(files[0], rules, limits)]
        else:
            raise Incomplete("clamav_unavailable_or_failed")
        pickle_results = []
        for artifact, data in zip(artifacts, files):
            # This held FD has already passed the complete pre-scan SHA. AV
            # scans the entire artifact, and the mandatory post-scan SHA below
            # still covers every byte after static inspection. Only redundant
            # top-level legacy storage digests may be omitted here.
            inspector = StaticInspector(limits, hash_storage_payloads=False)
            ext = artifact["type"].split(";ext=", 1)[1]
            code = None
            try:
                inspector.inspect(data, "artifact" + ext)
            except Incomplete as error:
                code = error.args[0] if error.args else None
                if code not in FILE_ERROR_CODES:
                    raise
            except FORMAT_EXCEPTIONS:
                code = "invalid_serialization"
            if code is not None:
                inspector.findings.append(coverage_finding(code))
            if len(inspector.findings) > 4096:
                raise Incomplete("finding_limit")
            pickle_results.append((code is None, inspector.findings))
        # Full SHA after both native and static inspection binds the returned
        # evidence to the same held snapshot, including a same-size mutation.
        for artifact, data, identity in zip(artifacts, files, identities):
            verify_held_snapshot(data, artifact, identity)
    if rule_inventory(rules) != request["evidence"]["rules"]:
        raise Incomplete("rules_changed")
    check_rules_expiry(limits)
    elapsed = round((time.monotonic() - started) * 1000)
    analyses = [{"generation": request["bundle"]["generation"], "complete": complete,
                 "engines": request["bundle"]["engines"], "findings": av + pickles,
                 "durationMs": elapsed} for av, (complete, pickles) in zip(antivirus_findings, pickle_results)]
    if any(len(analysis["findings"]) > 4096 for analysis in analyses):
        raise Incomplete("finding_limit")
    if batch:
        return {"results": [{"artifactId": a["artifactId"], "analysis": result} for a, result in zip(artifacts, analyses)]}
    return analyses[0]


def run_worker(artifact, state, peer=None, batch=False, probe=False):
    backend = "prefix" if probe else state.get("backend", "clamscan")
    run_limits = prefix_limits(state["limits"]) if probe else state["limits"]
    engine = state.get("engine") if backend == "clamd" else None
    descriptor, native_initial = None, 0
    payload = {"limits": run_limits, "bundle": state["bundle"], "evidence": state["evidence"],
               "batch": batch, "backend": backend, "probe": probe}
    payload["prefix" if probe else "artifacts" if batch else "artifact"] = artifact
    command = [sys.executable, "-I", str(Path(__file__).resolve()), "--worker", "--input", state["input"], "--rules", state["rules"]]
    p = None
    started = time.monotonic()
    child_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    baseline_cpu = child_before.ru_utime + child_before.ru_stime
    try:
        if backend == "clamd":
            if engine is None:
                raise Incomplete("clamav_unavailable_or_failed")
            descriptor, native_initial = engine.begin()
            payload["engine"] = descriptor
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            def spawn():
                return subprocess.Popen(command, stdin=subprocess.PIPE, stdout=out, stderr=err, start_new_session=True,
                                        env={"PATH": "/usr/bin:/bin", "TMPDIR": "/tmp", "PYTHONDONTWRITEBYTECODE": "1"})
            if "workers" in state:
                # Shutdown and spawn registration share a fence: no unowned
                # worker can appear after main takes its cleanup snapshot.
                with state["workers_lock"]:
                    if state.get("closing") or state.get("unsafe"):
                        raise Incomplete("clamav_unavailable_or_failed")
                    p = spawn()
                    state["workers"].add(p)
            else:
                p = spawn()
            p.stdin.write(canonical(payload))
            p.stdin.close()
            worker_cpu = 0
            while True:
                with contextlib.suppress(Incomplete):
                    worker_cpu = max(worker_cpu, process_tree_cpu(p.pid))
                native_cpu = engine.check_request(descriptor) - native_initial if engine else 0
                if time.monotonic() - started >= run_limits["wall_seconds"] or worker_cpu + native_cpu > run_limits["cpu_seconds"]:
                    raise Incomplete("scan_timeout")
                if out.tell() > MAX_RESPONSE or err.tell() > MAX_RESPONSE:
                    raise Incomplete("worker_output_limit")
                if peer is not None and select.select([peer], [], [], 0)[0]:
                    if not peer.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT):
                        raise Incomplete("scan_cancelled")
                if p.poll() is not None:
                    break
                time.sleep(0.05)
            child_after = resource.getrusage(resource.RUSAGE_CHILDREN)
            final_cpu = child_after.ru_utime + child_after.ru_stime - baseline_cpu + native_cpu
            if final_cpu > run_limits["cpu_seconds"]:
                raise Incomplete("scan_timeout")
            out.seek(0)
            try:
                value = json.loads(out.read(MAX_RESPONSE))
            except (ValueError, UnicodeError):
                value = None
            valid = (valid_prefix_result(value, artifact, state["bundle"]) if probe else
                     valid_worker_result(value, artifact, state["bundle"], batch))
            if p.returncode != 0 or err.tell() or not valid:
                code = value.get("error") if isinstance(value, dict) else None
                raise Incomplete(code if code in ERROR_CODES else "worker_failed_or_incomplete")
            if engine:
                engine.finish(descriptor)
            if time.monotonic() - started >= run_limits["wall_seconds"]:
                raise Incomplete("scan_timeout")
            check_rules_expiry(run_limits)
            return value
    except BaseException:
        try:
            kill_and_reap(p)
        except BaseException:
            state["unsafe"] = True
            raise
        finally:
            if engine:
                try:
                    if state.get("unsafe"):
                        engine.close()
                    else:
                        engine.abort(expected_epoch=descriptor.get("epoch") if descriptor else None)
                except BaseException:
                    state["unsafe"] = True
                    raise
        raise
    finally:
        if p is not None and "workers" in state:
            with state["workers_lock"]:
                state["workers"].discard(p)
            if (probe or state["limits"].get("native_temp_bytes")) and not process_group_absent(p.pid):
                if probe:
                    kill_and_reap(p)
                state["unsafe"] = True
                if engine:
                    engine.close()
                raise Incomplete("clamav_unavailable_or_failed")


class UnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    request_queue_size = 8


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *args):
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def answer(self, code, value):
        raw = canonical(value)
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        with contextlib.suppress(BrokenPipeError, ConnectionResetError):
            self.wfile.write(raw)

    def do_GET(self):
        if self.path != "/v1/bundle":
            return self.answer(404, {"error": "not_found"})
        # Fixed rules directory is mounted read-only and not updated in place.
        # Full hashes are verified inside every child before and after scanning.
        state = self.server.state
        if state.get("closing") or state.get("unsafe"):
            return self.answer(503, {"error": "clamav_unavailable_or_failed"})
        try:
            check_rules_expiry(state["limits"])
            if rule_stamp(state["rules"]) != state["rule_stamp"]:
                raise Incomplete("rules_changed")
        except Incomplete as error:
            return self.answer(503, {"error": "rules_expired" if error.args == ("rules_expired",) else "rules_changed_restart_required"})
        except Exception:
            return self.answer(503, {"error": "rules_changed_restart_required"})
        if state.get("engine") and not state["engine"].healthy():
            state["engine"].abort(only_if_unhealthy=True)
            return self.answer(503, {"error": "clamav_unavailable_or_failed"})
        self.answer(200, state["bundle"])

    def do_POST(self):
        state = self.server.state
        if self.path not in {"/v1/analyze", "/v1/analyze-batch", "/v1/probe-legacy-prefix"}:
            return self.answer(404, {"error": "not_found"})
        if state.get("closing") or state.get("unsafe"):
            return self.answer(503, {"error": "clamav_unavailable_or_failed"})
        try:
            check_rules_expiry(state["limits"])
            if rule_stamp(state["rules"]) != state["rule_stamp"]:
                raise Incomplete("rules_changed")
        except Incomplete as error:
            return self.answer(503, {"error": "rules_expired" if error.args == ("rules_expired",) else "rules_changed_restart_required"})
        except Exception:
            return self.answer(503, {"error": "rules_changed_restart_required"})
        if state.get("engine") and not state["engine"].healthy():
            state["engine"].abort(only_if_unhealthy=True)
            return self.answer(503, {"error": "clamav_unavailable_or_failed"})
        if self.headers.get("X-Expected-Generation") != state["bundle"]["generation"]:
            return self.answer(409, {"error": "generation_changed"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            probe = self.path == "/v1/probe-legacy-prefix"
            maximum = MAX_PREFIX_REQUEST if probe else MAX_REQUEST
            if not 0 < length <= maximum or self.headers.get("Transfer-Encoding"):
                raise Incomplete("request_limit")
            value = json.loads(self.rfile.read(length))
            batch = self.path == "/v1/analyze-batch"
            artifact = (validate_prefix(value, state["limits"]) if probe else
                        validate_batch(value, state["limits"]) if batch else validate_artifact(value, state["limits"]))
        except (ValueError, Incomplete):
            return self.answer(400, {"error": "invalid_request"})
        if not state["semaphore"].acquire(blocking=False):
            return self.answer(503, {"error": "scanner_busy"})
        try:
            self.answer(200, run_worker(artifact, state, self.connection, batch=batch, probe=probe))
        except Incomplete as error:
            code = error.args[0] if error.args else "scan_incomplete"
            self.answer(422, {"error": code if code in ERROR_CODES else "scan_incomplete"})
        except (Exception, MemoryError):
            self.answer(422, {"error": "scan_incomplete"})
        finally:
            state["semaphore"].release()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--input", default="/input")
    parser.add_argument("--rules", default="/rules")
    parser.add_argument("--socket", default="/run/matrix-security/scanner.sock")
    args = parser.parse_args()
    if args.worker:
        try:
            request = json.loads(sys.stdin.buffer.read(1 << 20))
            result = (prefix_worker(request, args.rules) if request.get("probe") else
                      worker(request, args.input, args.rules))
            sys.stdout.buffer.write(canonical(result))
            return 0
        except Incomplete as error:
            code = error.args[0] if error.args else "worker_failed_or_incomplete"
            sys.stdout.buffer.write(canonical({"complete": False, "error": code if code in ERROR_CODES else "worker_failed_or_incomplete"}))
            return 2
        except (ValueError, UnicodeError, EOFError, zipfile.BadZipFile, tarfile.TarError):
            sys.stdout.buffer.write(b'{"complete":false,"error":"invalid_serialization"}')
            return 2
        except BaseException:
            # Never serialize exception messages or tracebacks from parsers.
            sys.stdout.buffer.write(b'{"complete":false}')
            return 2
    limits = limits_from_env()
    backend = backend_from_env()
    directory = engine_directory(args.socket)
    bundle, evidence = create_bundle(args.rules, limits, backend, directory)
    engine_class = ArchivePersistentClamAV if limits.get("native_temp_bytes") else PersistentClamAV
    engine = engine_class(args.rules, limits, evidence, directory) if backend == "clamd" else None
    state = {"bundle": bundle, "evidence": evidence, "limits": limits, "backend": backend, "engine": engine,
             "input": args.input, "rules": args.rules, "rule_stamp": rule_stamp(args.rules),
             "semaphore": threading.BoundedSemaphore(1), "workers": set(), "workers_lock": threading.Lock(),
             "closing": False, "unsafe": False}
    if isinstance(engine, ArchivePersistentClamAV):
        engine.worker_state = state
    server = None
    def stop(_signal, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        if engine:
            engine.start()
        api_socket = Path(args.socket)
        if api_socket.exists() or api_socket.is_symlink():
            if not stat.S_ISSOCK(api_socket.lstat().st_mode):
                raise RuntimeError("refusing non-socket path")
            api_socket.unlink()
        server = UnixHTTPServer(str(api_socket), Handler)
        os.chmod(api_socket, 0o660)
        server.state = state
        print(json.dumps({"event": "scanner_ready", "generation": bundle["generation"], "engines": bundle["engines"],
                          "backend": backend, "profile": os.getenv("SCAN_PROFILE", "default"),
                          "daemonPid": engine.process.pid if engine else None,
                          "daemonEpoch": engine.epoch if engine else None,
                          "runtimeEngineConfigSha256": engine.runtime_config_sha if engine else None,
                          "workerAddressSpaceSoftBytes": limits["memory_bytes"],
                          "workerAddressSpaceHardBytes": limits["daemon_memory_bytes"],
                          "nativeAddressSpaceBytes": limits["daemon_memory_bytes"],
                          "nativeThreads": limits["native_threads"],
                          "maxBatchBytes": limits["max_batch_bytes"],
                          "rulesExpiresAt": limits["rules_expires_at"],
                          "workerWriteFileSoftBytes": limits["temp_bytes"],
                          "workerWriteFileHardBytes": limits["native_write_file_bytes"],
                          "nativeWriteFileLimitBytes": limits["native_write_file_bytes"]}), flush=True)
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        with state["workers_lock"]:
            state["closing"] = True
            processes = list(state["workers"])
        try:
            for process in processes:
                try:
                    kill_and_reap(process)
                except BaseException:
                    state["unsafe"] = True
        finally:
            if engine:
                engine.close()
        if server:
            server.server_close()
        with contextlib.suppress(FileNotFoundError):
            Path(args.socket).unlink()
    return 0


if __name__ == "__main__":
    sys.exit(main())
