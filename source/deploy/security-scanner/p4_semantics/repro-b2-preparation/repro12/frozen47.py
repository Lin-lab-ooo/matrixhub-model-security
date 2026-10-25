"""Separate Linux-only inert missing-storage component regression.

Default Describe performs no source/artifact IO. Executing requires the frozen
guard, exact source pins and private Linux noexec RAM. Never calls an unpickler,
Torch, a model constructor, network, Docker, AV, or the unchanged 84-test suite.
"""
import argparse
import ast
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import pickletools
import struct
import sys
import tempfile
import time
import warnings
import zipfile

BASELINE_SHA256 = "7cd1be1e44b007f57a643bfbb195f4495fd97ec92df872a7cbf91dbb2e4d6e01"
CANDIDATE_SHA256 = "8bffc514fa56b14b506c57629f4970a3197133f7a7d0b0a62348d392a125e05f"
HELPER_SHA256 = "7d4b785dce92d5962c6b5f57202a20aefae49f63272949f895449c676e330a1b"
TRANSCODER_SOURCE_SHA256 = "f44a31539b719fa76b9aeFE7eff5ac17d89675103318fc33038e964cb8f1f209".lower()
MAX_TOTAL = 1 << 20
LIMITS = {"max_file_bytes": 1 << 20, "max_scan_bytes": 1 << 20,
          "max_expanded_bytes": 1 << 20, "max_members": 64, "max_depth": 3,
          "max_ratio": 100, "max_pickle_opcodes": 10000, "max_pickle_argument": 8192}


def need(value, code):
    if not value:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load(path, wanted, name, H):
    raw = H.bounded_sha(path, wanted)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def outcome(module, path, limits):
    inspector = module.StaticInspector(dict(limits))
    code = operation = None
    try:
        with path.open("rb") as stream:
            inspector.inspect(stream, path.name)
        complete = True
    except module.Incomplete as error:
        complete = False
        code = error.args[0] if len(error.args) == 1 and error.args[0] in module.ERROR_CODES else "UNCLASSIFIED_INCOMPLETE"
    except module.FORMAT_EXCEPTIONS as error:
        complete, code = False, "invalid_serialization"
        names = {"ValueError", "UnicodeError", "UnicodeDecodeError", "UnicodeEncodeError", "EOFError",
                 "BadZipFile", "TarError", "ReadError", "CompressionError", "BadGzipFile", "error"}
        operation = type(error).__name__ if type(error).__name__ in names else "KNOWN_FORMAT_SUBCLASS_OTHER"
    except Exception:
        complete, code, operation = False, "UNEXPECTED_OPERATION", "OTHER"
    return {"complete": complete, "code": code, "operation": operation,
            "highCriticalFindings": sum(item.get("severity") in {"high", "critical"} for item in inspector.findings),
            "dangerousGlobalFound": any(item.get("rule") == "pickle.dangerous-global" for item in inspector.findings),
            "typedZIP": hasattr(inspector, "verified_framework_zip")}


def run(args, H, cap):
    B = load(args.baseline, BASELINE_SHA256, "missing_frozen_7cd", H)
    C = load(args.candidate, CANDIDATE_SHA256, "missing_candidate", H)
    records, generated = [], 0

    class P4Builder(H.Builder):
        pass

    def modern_wire(body):
        raw=b'\x80\x02'+body;stream=io.BytesIO(raw)
        ops=list(pickletools.genops(stream))
        need(len(ops)<=10000 and stream.tell()==len(raw) and ops[-1][0].name=='STOP','wire-single-stop-eof')
        refs=B.SymbolicReferences(10000);mapping={};out=[]
        for i,(op,arg,pos) in enumerate(ops):
            end=ops[i+1][2] if i+1<len(ops) else len(raw)
            need(op.proto<=2,'wire-source-protocol2')
            if op.name=='PROTO':
                need(i==0 and arg==2,'wire-source-header');continue
            if op.name in refs.PUT_OPS:
                refs.require(1)
                need(type(arg)is int and arg>=0 and arg not in mapping,'fixture-memo-key')
                mapping[arg]=len(mapping);piece=b'\x94'
            elif op.name in refs.GET_OPS:
                need(type(arg)is int and arg in mapping,'fixture-memo-get-before-put')
                index=mapping[arg];piece=(b'h'+bytes([index])) if index<256 else b'j'+struct.pack('<I',index)
            elif op.name=='GLOBAL':
                module,symbol=arg.split(' ',1)
                def literal(value):
                    encoded=value.encode('ascii');need(0<len(encoded)<256,'wire-global-literal');return b'\x8c'+bytes([len(encoded)])+encoded
                piece=literal(module)+literal(symbol)+b'\x93'
            else:piece=raw[pos:end]
            # This bounded stack/memo observer rejects undefined references and
            # invalid marks. It is not an alias/effect or model-safety proof.
            refs.apply(op,arg);out.append(piece)
        need(not refs.stack and not refs.marks and set(refs.memo)==set(mapping),'wire-final-stack-memo')
        result=b''.join(out)
        # Check the transformed stack/memo in wire order, using the explicit
        # key bijection. OPAQUE values cannot prove semantic alias safety.
        modern=B.SymbolicReferences(10000)
        for op,arg,pos in pickletools.genops(b'\x80\x04'+result):modern.apply(op,arg)
        need(not modern.stack and not modern.marks and modern.globals==refs.globals and set(modern.memo)==set(mapping.values()),'wire-reference-shape')
        return result,mapping

    class SpecBuilder(P4Builder):
        def __init__(self, token):
            super().__init__(token)
            self.next_memo = 0

        def fresh_put(self):
            index = self.next_memo
            self.next_memo += 1
            return self.put(index)

        def tensor_spec(self, key="0", kind="FloatStorage", numel=1, shape=1,
                        location="cpu", offset=0):
            # Same trusted Builder primitives, explicit P2 source memo keys;
            # only modern_wire assigns P4 MEMOIZE indices in actual wire order.
            pid = (b"(" + self.text("storage") + self.global_ref("torch", kind)
                   + self.text(key) + self.text(location) + self.integer(numel) + b"tQ")
            return (self.global_ref("torch._utils", "_rebuild_tensor_v2") + b"(" + pid
                    + self.integer(offset) + self.integer(shape) + b"\x85"
                    + self.integer(1) + b"\x85\x89" + self.ordered() + self.fresh_put() + b"NtR")

        def tensor_map(self, specs):
            body = self.ordered() + self.fresh_put() + b"("
            for index, spec in enumerate(specs):
                body += self.text("weight" + str(index)) + self.tensor_spec(**spec)
            return body + b"u."

    def metadata(specs, *, modern=True, frame=True):
        need(sys.platform == "linux" and cap is not None, "linux-generation-required")
        builder = SpecBuilder(cap)
        body = builder.tensor_map(specs)
        if not modern:
            return b"\x80\x02" + body
        body, _mapping = modern_wire(body)
        return b"\x80\x04" + (b"\x95" + struct.pack("<Q", len(body)) if frame else b"") + body

    def package(raw, members=(), *, metadata_name="archive/data.pkl", extra=()):
        need(sys.platform == "linux" and cap is not None, "linux-generation-required")
        output = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
                for name, content in [(metadata_name, raw), ("archive/version", b"3\n"), *members, *extra]:
                    entry = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                    entry.external_attr = 0o100600 << 16
                    archive.writestr(entry, content)
        return output.getvalue()

    def record(name, passed, **fields):
        records.append({"id": name, "passed": bool(passed), **fields})

    with tempfile.TemporaryDirectory(prefix="missing-finite-", dir="/tmp") as temporary:
        directory = Path(temporary)

        def write(name, blob):
            nonlocal generated
            need(time.time() < args.deadline, "test-deadline")
            generated += len(blob)
            need(generated <= MAX_TOTAL, "aggregate-fixture-budget")
            path = directory / (name + ".pt")
            path.write_bytes(blob)
            return path

        def witness(module, path, limits):
            with path.open("rb") as stream:
                value = module.observe_protocol4_storage_mismatch(stream, limits)
            return None if value is None else type(value).__name__

        def compare(name, raw, members=(), *, expected="same", limits=LIMITS, extra=(), metadata_name="archive/data.pkl"):
            blob = package(raw, members, extra=extra, metadata_name=metadata_name)
            path = write(name, blob)
            old, new = outcome(B, path, limits), outcome(C, path, limits)
            old_witness, new_witness = witness(B, path, limits), witness(C, path, limits)
            known = new["code"] not in {"UNCLASSIFIED_INCOMPLETE", "UNEXPECTED_OPERATION"}
            if expected == "missing":
                passed = (known and old_witness is None and old["complete"] and old["code"] is None
                          and old["highCriticalFindings"] == 0 and new_witness == "_MissingStorageRecord"
                          and not new["complete"] and new["code"] == "invalid_serialization")
            elif expected == "size":
                passed = known and old_witness == new_witness == "_StorageLengthMismatch" and old == new and new["code"] == "archive_member_size"
            elif expected == "unproven":
                passed = known and old_witness is None and new_witness is None and old == new
            elif expected == "same":
                passed = known and old == new and old_witness == new_witness
            else:
                raise ValueError("fixed-test-expectation")
            record(name, passed, fixtureBytes=len(blob), fixtureSHA256=sha(blob), baseline=old,
                   candidate=new, baselineWitness=old_witness, candidateWitness=new_witness)
            return path, raw, blob

        one = metadata([{}])
        missing, _, _ = compare("missing-float-key0", one, expected="missing")
        compare("missing-double-key7", metadata([{"key": "7", "kind": "DoubleStorage"}]), expected="missing")
        compare("missing-shared-pid", metadata([{}, {}]), expected="missing")
        two = metadata([{}, {"key": "7", "kind": "DoubleStorage"}])
        compare("missing-two-keys-both", two, expected="missing")
        compare("missing-two-keys-first", two, [("archive/data/7", bytes(8))], expected="missing")
        compare("missing-two-keys-second", two, [("archive/data/0", bytes(4))], expected="missing")
        compare("missing-zero-view-positive-backing", metadata([{"shape": 0}]), expected="missing")
        compare("true-zero-storage-missing-unproven", metadata([{"numel": 0, "shape": 0}]), expected="unproven")
        mixed = metadata([{"numel": 0, "shape": 0}, {"key": "7"}])
        compare("mixed-zero-positive-both-missing-unproven", mixed, expected="unproven")
        compare("mixed-zero-present-positive-missing", mixed, [("archive/data/0", b"")], expected="missing")
        compare("mixed-positive-present-zero-missing-unproven", mixed, [("archive/data/7", bytes(4))], expected="unproven")
        compare("matched-float-record-unchanged", one, [("archive/data/0", bytes(4))])
        compare("matched-shared-record-unchanged", metadata([{}, {}]), [("archive/data/0", bytes(4))])
        compare("matched-two-records-unchanged", two, [("archive/data/0", bytes(4)), ("archive/data/7", bytes(8))])
        compare("exact-set-short-existing-size-guard", one, [("archive/data/0", bytes(3))], expected="size")
        compare("exact-set-long-existing-size-guard", one, [("archive/data/0", bytes(5))], expected="size")
        compare("missing-plus-extra-record-unproven", one, [("archive/data/7", bytes(4))], expected="unproven")
        compare("conflicting-pid-missing-unproven", metadata([{}, {"kind": "DoubleStorage"}]), expected="unproven")
        compare("cuda-missing-unproven", metadata([{"location": "cuda:0"}]), expected="unproven")
        compare("geometry-outside-storage-unproven", metadata([{"shape": 2}]), expected="unproven")
        builder = P4Builder(cap)
        unknown_body = builder.global_ref("argparse", "Namespace") + b"."
        unknown = b"\x80\x04" + modern_wire(unknown_body)[0]
        compare("unknown-global-missing-unproven", unknown, expected="unproven")
        compare("fake-metadata-name-unproven", one, metadata_name="archive/not-data.pkl", expected="unproven")
        compare("two-root-metadata-unproven", one, extra=[("other/data.pkl", one)], expected="unproven")
        compare("ambiguous-storage-path-unproven", one, [("archive/data/../0", bytes(4))], expected="unproven")
        compare("duplicate-storage-path-unproven", one, [("archive/data/0", bytes(4)), ("archive/data/0", bytes(4))], expected="unproven")
        compare("protocol2-missing-unchanged", metadata([{}], modern=False), expected="same")
        body = one[11:]
        bad_frame = b"\x80\x04\x95" + struct.pack("<Q", len(body) + 1) + body
        compare("bad-frame-missing-unproven", bad_frame, expected="unproven")
        compare("trailing-stream-missing-unproven", one + b"\x80\x04N.", expected="unproven")
        tight = dict(LIMITS, max_pickle_opcodes=5)
        compare("opcode-budget-missing-unproven", one, limits=tight, expected="unproven")
        old_cap = C._P4_SELECTOR_BYTES
        try:
            C._P4_SELECTOR_BYTES = 32
            compare("selector-budget-missing-unproven", one, expected="unproven")
        finally:
            C._P4_SELECTOR_BYTES = old_cap
        # A concrete known unsafe global reference is never invoked. Its POP
        # makes the finite proof ineligible, so generic findings must survive.
        dangerous = P4Builder(cap).global_ref("os", "system") + b"0" + SpecBuilder(cap).tensor_map([{}])
        danger_raw = b"\x80\x04" + modern_wire(dangerous)[0]
        risk, _, _ = compare("risk-reference-remains-generic", danger_raw, expected="unproven")
        risk_observation = outcome(C, risk, LIMITS)
        record("risk-finding-retained", risk_observation["dangerousGlobalFound"] and risk_observation["highCriticalFindings"] > 0)

        # The real caller must establish threat callback evidence BEFORE the
        # fixed missing-record deny, and must never turn callback failure into
        # either a witness or a successful generic fallback.
        seen = []
        def callback(stream, member_index, member_name):
            seen.append((type(stream) is io.BytesIO, type(member_index) is int, type(member_name) is str))
        try:
            with missing.open("rb") as stream:
                C.verify_framework_zip(stream, callback, LIMITS)
            denied = False
        except C.LayoutError as error:
            denied = error.code == "invalid_serialization"
        record("caller-callback-before-fixed-deny", denied and seen == [(True, True, True)])
        for label, kind in [("value", ValueError), ("runtime", RuntimeError), ("memory", MemoryError),
                            ("io", OSError), ("timeout", TimeoutError), ("interrupt", KeyboardInterrupt), ("exit", SystemExit)]:
            def fail_callback(*_args, exception=kind):
                raise exception()
            try:
                with missing.open("rb") as stream:
                    C.verify_framework_zip(stream, fail_callback, LIMITS)
                propagated = False
            except kind:
                propagated = True
            record("caller-propagates-" + label, propagated)
        for label, exception in [("incomplete-instance", C.Incomplete("pickle_opcode_limit")),
                                 ("layout-instance", C.LayoutError("unsupported_container_or_serialization"))]:
            def fail_exact_callback(*_args, original=exception):
                raise original
            try:
                with missing.open("rb") as stream:
                    C.verify_framework_zip(stream, fail_exact_callback, LIMITS)
                propagated = False
            except BaseException as actual:
                propagated = actual is exception
            record("caller-preserves-" + label, propagated)
        original_parse = C._P4ZipMachine.parse
        try:
            for label, kind in [("memory", MemoryError), ("io", OSError), ("timeout", TimeoutError),
                                ("interrupt", KeyboardInterrupt), ("exit", SystemExit)]:
                def fail_parse(self, raw, exception=kind):
                    raise exception()
                C._P4ZipMachine.parse = fail_parse
                try:
                    with missing.open("rb") as stream:
                        C.observe_protocol4_storage_mismatch(stream, LIMITS)
                    propagated = False
                except kind:
                    propagated = True
                record("observer-propagates-" + label, propagated)
        finally:
            C._P4ZipMachine.parse = original_parse

    H.bounded_sha(args.baseline, BASELINE_SHA256)
    H.bounded_sha(args.candidate, CANDIDATE_SHA256)
    need(len(records) == 47, "fixed-case-inventory")
    result = {"schema": 1, "scope": "MISSING_NONEMPTY_STATIC_COMPONENT_ONLY_NOT_AV_OR_ADOPTION",
              "status": "PASS" if all(row["passed"] for row in records) else "FAIL",
              "tests": len(records), "passed": sum(row["passed"] for row in records),
              "fixtureBytesGenerated": generated, "baselineSHA256": BASELINE_SHA256,
              "candidateSHA256": CANDIDATE_SHA256, "modelDeserialized": False, "AVRun": False,
              "unchanged84SuiteRun": False, "old84ExpectedDifference": "deny-guard-missing-record-unproven -> invalid_serialization",
              "records": records}
    encoded = json.dumps(result, sort_keys=True, ensure_ascii=True)
    need(len(encoded.encode("ascii")) <= 128 << 10, "bounded-output")
    print(encoded)
    return 0 if result["status"] == "PASS" else 2


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--deadline", type=int)
    parser.add_argument("--root-idle-confirmed", action="store_true")
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"mode": "DESCRIBE", "artifactInputsRead": False, "fixturesGenerated": 0,
                          "testsExecuted": 0, "candidatePinned": CANDIDATE_SHA256 is not None}))
        return 0
    need(sys.platform == "linux" and os.geteuid() == 65532, "linux-low-uid-before-fixtures")
    need(type(CANDIDATE_SHA256) is str and len(CANDIDATE_SHA256) == 64
         and all(c in "0123456789abcdef" for c in CANDIDATE_SHA256), "candidate-not-sealed")
    need(args.baseline is not None and args.candidate is not None, "explicit-source-inputs")
    path = Path(__file__).with_name("fixture_helpers.py")
    need(path.is_file() and not path.is_symlink() and path.stat().st_size <= 64 << 10, "fixed-own-helper")
    raw = path.read_bytes()
    need(sha(raw) == HELPER_SHA256, "fixed-helper-sha")
    spec = importlib.util.spec_from_file_location("missing_fixture_guard", path)
    H = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), "exec"), H.__dict__)
    cap = H.environment(args.deadline, args.root_idle_confirmed)
    H.bounded_sha(args.baseline, BASELINE_SHA256)
    H.bounded_sha(args.candidate, CANDIDATE_SHA256)
    return run(args, H, cap)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as error:
        allowed = {"ValueError", "OSError", "TimeoutError", "MemoryError"}
        print(json.dumps({"status": "REFUSED", "errorType": type(error).__name__ if type(error).__name__ in allowed else "OTHER",
                          "fixturesExecutedSuccessfully": False}))
        raise SystemExit(2)
