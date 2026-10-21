#!/usr/bin/env python3
# Copyright The MatrixHub Authors. Licensed under the Apache License, Version 2.0.
"""Bounded v13 native acceptance through the actual scanner Unix protocol.

Run only in an isolated Linux scanner test container with complete read-only
/rules, /baseline/scanner.py, and /public-models. This harness never loads a
model, runs uploaded code, downloads anything, or controls Docker. It creates
at most 32 MiB of manifest-bound public test weights plus small inert fixtures
in its private /tmp directory. Public tiny-random weights establish format
compatibility, not trained-production-model or GiB-capacity acceptance.

Baseline outcomes are observations. Candidate outcomes must match each fixed
expectation. Native coverage rejection may precede static inspection for
explicitly listed malformed/over-budget archives; such cases are recorded
separately and never presented as proof that a static branch executed.
"""
import argparse
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import tempfile
import time
import zipfile

MAX_PUBLIC_BYTES = 32 << 20
MAX_FIXTURE_BYTES = 4 << 20
MAX_RESPONSE_BYTES = 2 << 20
RULE_EXT = {".cvd", ".cld", ".hdb", ".hsb", ".ndb", ".ldb", ".cdb",
            ".cbc", ".ign", ".ign2"}
SHA_RE = re.compile(r"[a-f0-9]{64}\Z")
PUBLIC_IDS = {"gpt2-public-test", "vit-public-test"}
NATIVE_COVERAGE_CODE = "clamav_coverage_incomplete"


def sha_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def rules_identity(root):
    entries = []
    for path in sorted(root.iterdir()):
        if path.suffix.lower() not in RULE_EXT:
            continue
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError("rules_not_regular")
        entries.append({"name": path.name, "bytes": info.st_size,
                        "sha256": sha_file(path)})
    if not entries:
        raise RuntimeError("complete_rules_required")
    return entries


def load_transport():
    path = Path(__file__).with_name("legacy_io_native.py")
    spec = importlib.util.spec_from_file_location("v13_native_transport", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_evidence(path, evidence):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n",
                         encoding="utf-8")
    os.replace(temporary, path)


def call(transport, socket_path, method, endpoint, descriptor=None,
         generation=None, timeout=330):
    connection = transport.UnixConnection(str(socket_path), timeout=timeout)
    headers = {"Content-Type": "application/json"}
    if generation is not None:
        headers["X-Expected-Generation"] = generation
    started = time.perf_counter()
    record = {"method": method, "endpoint": endpoint}
    try:
        body = None if descriptor is None else json.dumps(descriptor)
        connection.request(method, endpoint, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        record.update(httpStatus=response.status,
                      responseHeaders=dict(response.getheaders()),
                      requestSeconds=time.perf_counter() - started)
        if len(raw) > MAX_RESPONSE_BYTES:
            record["protocolError"] = "response_too_large"
            return record
        try:
            record["rawBody"] = raw.decode("utf-8", "strict")
            record["response"] = json.loads(record["rawBody"])
        except (ValueError, UnicodeError):
            record["rawBodyBase64"] = base64.b64encode(raw).decode("ascii")
            record["protocolError"] = "invalid_response_json"
    except (OSError, TimeoutError) as error:
        record.update(requestSeconds=time.perf_counter() - started,
                      transportError=type(error).__name__)
    finally:
        connection.close()
    return record


def wait_healthy(transport, server, generation):
    deadline = time.monotonic() + 150
    polls = []
    while time.monotonic() < deadline:
        if server.process.poll() is not None:
            return {"ready": False, "reason": "scanner_process_exited",
                    "polls": polls}
        record = call(transport, server.socket, "GET", "/v1/bundle", timeout=5)
        value = record.get("response")
        if (record.get("httpStatus") == 200 and isinstance(value, dict)
                and value.get("generation") == generation
                and value.get("engines") == server.bundle.get("engines")):
            polls.append(record)
            return {"ready": True, "polls": polls}
        if record.get("httpStatus") == 200:
            polls.append(record)
            return {"ready": False, "reason": "bundle_identity_changed",
                    "polls": polls}
        polls.append(record)
        # Recovery is expected after a failed request; never retry analysis.
        time.sleep(0.5)
    return {"ready": False, "reason": "bundle_recovery_timeout", "polls": polls}


def zip_bytes(entries, compression=zipfile.ZIP_STORED):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression) as archive:
        for name, content in entries:
            archive.writestr(name, content)
    return output.getvalue()


def tar_bytes(entries, archive_format=tarfile.USTAR_FORMAT):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=archive_format) as archive:
        for name, content, directory in entries:
            info = tarfile.TarInfo(name)
            info.mtime = 0
            info.size = len(content)
            if directory:
                info.type = tarfile.DIRTYPE
            archive.addfile(info, io.BytesIO(content))
    return output.getvalue()


def safetensors_bytes(header, payload=b""):
    raw = header if isinstance(header, bytes) else json.dumps(
        header, separators=(",", ":")).encode()
    return len(raw).to_bytes(8, "little") + raw + payload


def expected(mode, code=None, native_coverage=False):
    result = {"mode": mode}
    if code is not None:
        result["code"] = code
    if native_coverage:
        result["allowedNativeCoverageError"] = NATIVE_COVERAGE_CODE
    return result


def generated_cases():
    if sys.platform != "linux":
        raise RuntimeError("fixtures_must_be_constructed_inside_linux_container")
    note = b'{"format":"MatrixHub inert native acceptance","version":13}'
    dangerous = b"cos\nsystem\n."  # Static reference only; never unpickled.
    symlink = zipfile.ZipInfo("hidden/")
    symlink.create_system = 3
    symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
    dirs = [(f"directory-{index}/", b"") for index in range(257)]
    nested_dirs = zip_bytes([("nested.zip", zip_bytes(dirs))])
    deep = b'{"__metadata__":{"key":' + b"[" * 1500 + b"0" + b"]" * 1500 + b"}}"
    normal_tar = tar_bytes([("readme.json", note, False)])
    rows = [
        ("clean-json", note, ".json", expected("clean")),
        ("normal-zip", zip_bytes([("readme.json", note)]), ".zip", expected("clean")),
        ("zip-stored-directory", zip_bytes([("folder/", b""), ("folder/readme.json", note)]),
         ".zip", expected("clean")),
        ("zip-deflated-directory", zip_bytes([("folder/", b""), ("folder/readme.json", note)],
                                             zipfile.ZIP_DEFLATED), ".zip", expected("clean")),
        ("normal-tar", normal_tar, ".tar", expected("clean")),
        ("tar-directory", tar_bytes([("folder/", b"", True), ("folder/readme.json", note, False)]),
         ".tar", expected("clean")),
        ("pax-long-name", tar_bytes([("folder/" + "n" * 150 + ".json", note, False)],
                                    tarfile.PAX_FORMAT), ".tar", expected("clean")),
        ("dangerous-global", dangerous, ".pkl", expected("risk")),
        # Tiny, inert length declarations exercise the real worker's generic
        # allocation fence. No large operand payload is stored or executed.
        ("pickle-binbytes8-huge-declaration", b"\x80\x04\x8e" + (1 << 30).to_bytes(8, "little"),
         ".pkl", expected("error", "pickle_argument_limit")),
        ("pickle-long4-huge-declaration", b"\x80\x02\x8b" + (1 << 30).to_bytes(4, "little"),
         ".pkl", expected("error", "pickle_argument_limit")),
        ("dangerous-nested-zip", zip_bytes([("inner.zip", zip_bytes([("model.pkl", dangerous)]))]),
         ".zip", expected("risk")),
        ("zip-directory-payload", zip_bytes([("hidden/", dangerous)]), ".zip",
         expected("incomplete", "archive_member_size", True)),
        ("zip-directory-symlink", zip_bytes([(symlink, b"target")]), ".zip",
         expected("incomplete", "archive_symlink", True)),
        ("tar-directory-payload", tar_bytes([("hidden/", dangerous, True)]), ".tar",
         expected("incomplete", "archive_member_size", True)),
        ("zip-257-directories", zip_bytes(dirs), ".zip",
         expected("error", "archive_member_limit", True)),
        ("nested-zip-257-directories", nested_dirs, ".zip",
         expected("error", "archive_member_limit", True)),
        ("tar-257-directories", tar_bytes([(name, b"", True) for name, _ in dirs]), ".tar",
         expected("error", "archive_member_limit", True)),
        ("tar-nonzero-tail", normal_tar + b"not-a-covered-member".ljust(512, b"\x00"), ".tar",
         expected("incomplete", "invalid_serialization", True)),
        ("deep-safetensors", safetensors_bytes(deep), ".safetensors",
         expected("incomplete", "invalid_safetensors_header")),
        ("damaged-safetensors-offsets",
         safetensors_bytes({"weight": {"dtype": "U8", "shape": [2], "data_offsets": [0, 2]}}, b"\x00"),
         ".safetensors", expected("incomplete", "invalid_safetensors_offsets")),
    ]
    # Standard harmless AV test bytes are constructed only inside this Linux
    # test-container function. They are never downloaded or executed.
    antivirus_parts = [b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$",
                       b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"]
    antivirus_test = b"".join(antivirus_parts)
    rows.append(("antivirus-positive-control", antivirus_test, ".com",
                 expected("antivirus")))
    # Exercise archive inspection with compressed harmless AV test controls.
    # These expectations require a complete, critical ClamAV EICAR finding;
    # coverage rejection is never an acceptable substitute. Actual support is
    # established only by the later isolated native run, for both variants.
    antivirus_zip = zip_bytes([("control.com", antivirus_test)], zipfile.ZIP_DEFLATED)
    rows.append(("antivirus-zip-positive-control", antivirus_zip, ".zip",
                 expected("antivirus")))
    rows.append(("antivirus-nested-zip-positive-control",
                 zip_bytes([("inner.zip", antivirus_zip)], zipfile.ZIP_DEFLATED), ".zip",
                 expected("antivirus")))
    if sum(len(raw) for _, raw, _, _ in rows) > MAX_FIXTURE_BYTES:
        raise RuntimeError("generated_fixture_budget")
    return rows


def publish_bytes(root, index, content, extension):
    artifact_id = "task-1-1-" + "a" * 16 + "/" + format(index, "032x") + ".blob"
    target = root / artifact_id
    target.parent.mkdir(mode=0o700, exist_ok=True)
    target.write_bytes(content)
    target.chmod(0o440)
    return {"artifactId": artifact_id, "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content), "type": "opaque;ext=" + extension}


def public_cases(root, public_root, index):
    manifest_path = public_root / "manifest.json"
    if manifest_path.is_symlink() or manifest_path.stat().st_size > 64 << 10:
        raise RuntimeError("invalid_public_manifest")
    raw_manifest = manifest_path.read_bytes()
    manifest = json.loads(raw_manifest)
    entries = manifest.get("files")
    if (manifest.get("status") != "PASS" or manifest.get("modelLoaded") is not False
            or not isinstance(entries, list) or len(entries) != 2
            or {item.get("id") for item in entries} != PUBLIC_IDS):
        raise RuntimeError("public_manifest_contract_mismatch")
    total = 0
    result = []
    for entry in entries:
        name, size, digest = entry.get("filename"), entry.get("bytes"), entry.get("sha256")
        if (not isinstance(name, str) or Path(name).name != name
                or not name.endswith(".safetensors")
                or type(size) is not int or not 0 < size <= MAX_PUBLIC_BYTES
                or not isinstance(digest, str) or not SHA_RE.fullmatch(digest)
                or entry.get("trainedProductionModel") is not False
                or entry.get("modelLoaded") is not False):
            raise RuntimeError("invalid_public_model_descriptor")
        total += size
        if total > MAX_PUBLIC_BYTES:
            raise RuntimeError("public_model_total_budget")
        source = public_root / name
        info = source.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size != size or sha_file(source) != digest:
            raise RuntimeError("public_model_identity_mismatch")
        # The read-only public mount is copied to the same private sealed input
        # root used for generated cases, then independently hashed again.
        content = source.read_bytes()
        descriptor = publish_bytes(root, index, content, ".safetensors")
        del content
        if descriptor["size"] != size or descriptor["sha256"] != digest:
            raise RuntimeError("public_model_copy_identity_mismatch")
        result.append({"id": entry["id"], "descriptor": descriptor,
                       "expected": expected("clean"), "provenance": entry})
        index += 1
    return result, {"manifestSHA256": hashlib.sha256(raw_manifest).hexdigest(),
                    "manifest": manifest, "totalBytes": total}


def judge(record, expectation, bundle):
    status, body = record.get("httpStatus"), record.get("response")
    if record.get("protocolError") or record.get("transportError"):
        return {"matched": False, "reason": "transport_or_protocol_failure"}
    if (status == 422 and type(body) is dict and set(body) == {"error"}
            and expectation.get("allowedNativeCoverageError") == NATIVE_COVERAGE_CODE
            and body["error"] == NATIVE_COVERAGE_CODE):
        return {"matched": True, "reason": "explicit_native_coverage_rejection",
                "staticExpectedCodeObserved": False}
    if expectation["mode"] == "error":
        valid = (status == 422 and type(body) is dict
                 and body == {"error": expectation["code"]})
        return {"matched": valid, "reason": "fixed_global_error" if valid else "wrong_global_error",
                "staticExpectedCodeObserved": valid}
    if (status != 200 or type(body) is not dict
            or body.get("generation") != bundle["generation"]
            or body.get("engines") != bundle["engines"]
            or type(body.get("complete")) is not bool
            or type(body.get("findings")) is not list
            or type(body.get("durationMs")) is not int or body["durationMs"] < 0
            or any(type(item) is not dict for item in body["findings"])):
        return {"matched": False, "reason": "wrong_http_or_analysis_identity"}
    findings = body["findings"]
    coverage = [item for item in findings if item.get("engine") == "coverage"]
    mode = expectation["mode"]
    if mode == "clean":
        valid = body["complete"] and not findings
    elif mode == "risk":
        valid = body["complete"] and not coverage and any(
            item.get("engine") == "picklescan" and item.get("rule") == "pickle.dangerous-global"
            and item.get("severity") == "critical" for item in findings)
    elif mode == "antivirus":
        valid = body["complete"] and not coverage and any(
            item.get("engine") == "clamav" and item.get("severity") == "critical"
            and str(item.get("rule", "")).startswith("clamav.")
            and "eicar" in str(item.get("rule", "")).lower() for item in findings)
    elif mode == "incomplete":
        valid = (not body["complete"] and len(coverage) == 1
                 and coverage[0].get("rule") == "coverage." + expectation["code"])
    else:
        valid = False
    return {"matched": bool(valid), "reason": "expected_" + mode if valid else "unexpected_" + mode,
            "staticExpectedCodeObserved": bool(valid) if mode == "incomplete" else None}


def run_variant(name, source, inputs, rules, cases, transport, evidence, output):
    item = {"status": "RUNNING", "sourceSHA256": sha_file(source), "cases": []}
    evidence["variants"][name] = item
    write_evidence(output, evidence)
    with transport.Server(source, inputs, rules) as server:
        item["bundle"] = server.bundle
        generation = server.bundle["generation"]
        try:
            for case in cases:
                readiness = wait_healthy(transport, server, generation)
                row = {"id": case["id"], "descriptor": case["descriptor"],
                       "expectedCandidate": case["expected"], "readiness": readiness,
                       "requiredForCandidate": name == "candidate"}
                item["cases"].append(row)
                if not readiness["ready"]:
                    row["judgment"] = {"matched": False, "reason": readiness["reason"]}
                    write_evidence(output, evidence)
                    raise RuntimeError(name + "_bundle_not_ready")
                record = call(transport, server.socket, "POST", "/v1/analyze",
                              case["descriptor"], generation)
                row.update(record)
                if (record.get("transportError") or record.get("protocolError")
                        or record.get("httpStatus") not in {200, 422}):
                    # Baseline semantic differences are observations, but an
                    # unavailable engine or broken transport is not evidence.
                    evidence["operationalFailures"].append({
                        "variant": name, "case": case["id"],
                        "type": "NativeProtocolFailure",
                        "httpStatus": record.get("httpStatus"),
                        "detail": record.get("transportError") or record.get("protocolError")
                                  or "unexpected_http_status"})
                row["judgment"] = judge(record, case["expected"], server.bundle)
                row["status"] = ("PASS" if row["judgment"]["matched"] else "FAIL") if name == "candidate" else "OBSERVED"
                write_evidence(output, evidence)
                print(json.dumps({"event": "native_case", "variant": name,
                                  "id": case["id"], "status": row["status"],
                                  "httpStatus": record.get("httpStatus"),
                                  "judgment": row["judgment"],
                                  "requestSeconds": record.get("requestSeconds")}), flush=True)
            item["finalReadiness"] = wait_healthy(transport, server, generation)
            if not item["finalReadiness"]["ready"]:
                raise RuntimeError(name + "_final_bundle_not_ready")
        finally:
            server.log.flush()
            log_size = os.fstat(server.log.fileno()).st_size
            item["supervisorLogBytes"] = log_size
            item["supervisorLogTruncated"] = log_size > 1 << 20
            item["supervisorLog"] = os.pread(server.log.fileno(), min(log_size, 1 << 20), 0).decode("utf-8", "replace")
            write_evidence(output, evidence)
    item["status"] = ("PASS" if all(row["status"] == "PASS" for row in item["cases"])
                      else "FAIL") if name == "candidate" else "OBSERVED"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, default=Path("/baseline/scanner.py"))
    parser.add_argument("--candidate", type=Path, default=Path(__file__).with_name("scanner.py"))
    parser.add_argument("--rules", type=Path, default=Path("/rules"))
    parser.add_argument("--public-models", type=Path, default=Path("/public-models"))
    parser.add_argument("--output", type=Path, default=Path("/evidence/native.json"))
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("run only inside the isolated Linux scanner test container")
    sources = {"baseline": args.baseline, "candidate": args.candidate}
    evidence = {"status": "RUNNING", "startedUnix": time.time(), "python": sys.version,
                "scope": "actual ClamAV/Picklescan Unix API; private test snapshots; no model execution, MatrixHub E2E, GiB performance, or independent container-isolation certification",
                "staticSuite": "not executed by this harness", "variants": {},
                "operationalFailures": [], "harnessSHA256": sha_file(Path(__file__))}
    try:
        evidence["sourceSHA256"] = {name: sha_file(source) for name, source in sources.items()}
        evidence["rules"] = rules_identity(args.rules)
        transport = load_transport()
        evidence["transportSHA256"] = sha_file(Path(__file__).with_name("legacy_io_native.py"))
        with tempfile.TemporaryDirectory(prefix="v13-native-acceptance-") as directory:
            inputs = Path(directory)
            cases = [{"id": name, "descriptor": publish_bytes(inputs, index, raw, extension),
                      "expected": expectation}
                     for index, (name, raw, extension, expectation) in enumerate(generated_cases(), 1)]
            models, evidence["publicModels"] = public_cases(inputs, args.public_models, len(cases) + 1)
            cases.extend(models)
            evidence["cases"] = cases
            write_evidence(args.output, evidence)
            for name, source in sources.items():
                try:
                    run_variant(name, source, inputs, args.rules, cases, transport, evidence, args.output)
                except Exception as error:
                    evidence["operationalFailures"].append(
                        {"variant": name, "type": type(error).__name__, "detail": str(error)[:240]})
                    evidence["variants"].setdefault(name, {})["status"] = "ERROR"
                    write_evidence(args.output, evidence)
            evidence["finalSourceSHA256"] = {name: sha_file(source) for name, source in sources.items()}
            evidence["finalRules"] = rules_identity(args.rules)
            if (evidence["sourceSHA256"] != evidence["finalSourceSHA256"]
                    or evidence["rules"] != evidence["finalRules"]):
                raise RuntimeError("source_or_rules_identity_changed")
        candidate = evidence["variants"].get("candidate", {})
        evidence["nativeCoverageShortCircuits"] = [
            row["id"] for row in candidate.get("cases", [])
            if row.get("judgment", {}).get("reason") == "explicit_native_coverage_rejection"]
        evidence["status"] = ("PASS" if candidate.get("status") == "PASS"
                              and not evidence["operationalFailures"] else "FAIL")
    except Exception as error:
        evidence["status"] = "FAIL"
        evidence["operationalFailures"].append(
            {"type": type(error).__name__, "detail": str(error)[:240]})
    finally:
        peak = Path("/sys/fs/cgroup/memory.peak")
        if peak.exists():
            evidence["wholeContainerPeakBytes"] = int(peak.read_text())
        evidence["finishedUnix"] = time.time()
        write_evidence(args.output, evidence)
        print("RESULT " + json.dumps({"status": evidence["status"], "output": str(args.output),
                                     "operationalFailures": evidence["operationalFailures"],
                                     "nativeCoverageShortCircuits": evidence.get("nativeCoverageShortCircuits", [])}),
              flush=True)
    return 0 if evidence["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

