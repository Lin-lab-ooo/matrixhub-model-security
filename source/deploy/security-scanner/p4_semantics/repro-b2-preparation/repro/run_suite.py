"""Pinned sequential static-component suite adapter; default Describe has no IO.

Run one group per fresh Linux process. Root alone supplies the isolated
container and <=120s external deadline. This script never contacts Docker.
"""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import time

CANDIDATE = "b2e80d9544f0c5dd313d3758107ea6069b0c0a742cd7f78030901aabea7ffda6"
OLD_ASCII_CANDIDATE = "7cd1be1e44b007f57a643bfbb195f4495fd97ec92df872a7cbf91dbb2e4d6e01"
SUITES = {
    "missing47": {"file": "suite47/linux_missing_tests.py", "sha256": "5c96427e19ca4373233242e2297770ffd1ec7b1fc6bb9d4abe8c0b380646cc34", "count": 47,
                  "baseline": "scanner-7cd.py", "baselineSHA256": OLD_ASCII_CANDIDATE},
    "p4_84_delta": {"file": "suite84/linux_p4_tests.py", "sha256": "bacc75b2741f7f95b80b39308cd86edf2b4441ed386cd732db07965145914c9f", "count": 84,
                    "baseline": "scanner-5fa.py", "baselineSHA256": "5fa1c563389f6b70ce16d9a7c3e60fc7c5a452ede2871a231b7e386147500c57"},
    "ascii34": {"file": "suite34/linux_ascii_tests.py", "sha256": "092f556bee4290f72a62f29c107c7f64832ef29109203d98114936b1eff49e40", "count": 34,
                "baseline": "scanner-19aee.py", "baselineSHA256": "19aee967a7d5c8e3857b4d962423af3a036f5f72af721a98372f419804b6c5ad"},
}
MAX_RESULT = 128 << 10


def need(value, code):
    if not value:
        raise ValueError(code)


def source(path, wanted):
    need(path.is_file() and not path.is_symlink() and all(not p.is_symlink() for p in path.parents), "source-path")
    before = path.stat()
    with path.open("rb") as stream:
        held = os.fstat(stream.fileno())
        raw = stream.read(512001)
        after = os.fstat(stream.fileno())
    stamp = lambda row: (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns, row.st_ctime_ns)
    need(0 < len(raw) <= 512000 and held.st_nlink == 1 and stamp(before) == stamp(held) == stamp(after) == stamp(path.stat())
         and hashlib.sha256(raw).hexdigest() == wanted, "source-pin")
    return raw


class BoundedMetadata(io.StringIO):
    def __init__(self):
        super().__init__()
        self.size = 0
    def write(self, value):
        self.size += len(value.encode("utf-8"))
        need(self.size <= MAX_RESULT, "suite-output-budget")
        return super().write(value)


class DiscardStderr:
    def __init__(self): self.size = 0
    def write(self, value):
        self.size += len(value.encode("utf-8"))
        need(self.size <= 8192, "suite-stderr-budget")
        return len(value)
    def flush(self): pass


def execute(args):
    # These early checks cannot read code/artifacts or invoke builders on Windows.
    need(sys.platform == "linux" and os.geteuid() == os.getegid() == 65532, "linux-low-uid")
    need(args.root_idle_confirmed is True and type(args.deadline) is int
         and 0 < args.deadline - time.time() <= 120, "fresh-root-idle-deadline")
    config = SUITES[args.suite]
    path = Path("/probe") / config["file"]
    baseline = Path("/baseline") / config["baseline"]
    candidate = Path("/candidate/scanner.py")
    raw = source(path, config["sha256"])
    source(baseline, config["baselineSHA256"])
    source(candidate, CANDIDATE)
    spec = importlib.util.spec_from_file_location("missing_component_" + args.suite, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    exec(compile(raw, str(path), "exec"), module.__dict__)
    binding = None
    if args.suite == "ascii34":
        # Entire source, functions, cases and assertions remain byte-identical.
        # This explicit reviewed adapter changes only the target source pin.
        need(module.CANDIDATE == OLD_ASCII_CANDIDATE, "ascii-original-binding")
        module.CANDIDATE = CANDIDATE
        binding = {"constant": "CANDIDATE", "expectedOriginal": OLD_ASCII_CANDIDATE,
                   "boundCandidate": CANDIDATE, "functionsOrAssertionsChanged": False}
    argv = [str(path), "--execute", "--baseline", str(baseline), "--candidate", str(candidate),
            "--deadline", str(args.deadline), "--root-idle-confirmed"]
    if args.suite == "p4_84_delta":
        argv += ["--candidate-sha256", CANDIDATE]
    previous = sys.argv
    output, discarded = BoundedMetadata(), DiscardStderr()
    try:
        sys.argv = argv
        # Invoke the real existing main. Its frozen H.environment applies all
        # Linux mount/network/cgroup/UID/rlimit controls before any fixture.
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(discarded):
            returncode = module.main()
    finally:
        sys.argv = previous
    need(time.time() < args.deadline, "suite-deadline")
    value = json.loads(output.getvalue())
    need(type(value) is dict and value.get("tests") == config["count"]
         and value.get("candidateSHA256") == CANDIDATE
         and value.get("baselineSHA256") == config["baselineSHA256"]
         and type(value.get("fixtureBytesGenerated")) is int and 0 <= value["fixtureBytesGenerated"] <= 1 << 20
         and value.get("AVRun") is False and value.get("modelLoaded", value.get("modelDeserialized")) is False
         and type(value.get("records")) is list and len(value["records"]) == config["count"], "suite-result-contract")
    if args.suite == "missing47":
        identity = {
            "mixed-zero-positive-both-missing-unproven": (568, "9adf0b763a80af80c8a22ad9060780fbdb85dd717033524bd6eb40f66fb7fee5"),
            "missing-plus-extra-record-unproven": (533, "daf4616b9b1a56548035fa9b1ca012c30950a3e8dd32b98c68696047dbf5e5f3"),
        }
        for case_id, expected in identity.items():
            matching = [row for row in value["records"] if row.get("id") == case_id]
            need(len(matching) == 1 and (matching[0].get("fixtureBytes"), matching[0].get("fixtureSHA256")) == expected,
                 "exists-two-historical-input-identities")
    passed = (returncode == 0 and value.get("status") == "PASS" and value.get("passed") == config["count"]
              and all(row.get("passed") is True for row in value["records"]))
    result = {"schema": 1, "scope": "MISSING_EXISTS_CANDIDATE_STATIC_COMPONENT_165_SEPARATE_GROUPS_NOT_AV_OR_ADOPTION",
              "suite": args.suite, "status": "PASS" if passed else "FAIL", "plannedGroupCount": config["count"],
              "suiteSourceSHA256": config["sha256"], "candidateSHA256": CANDIDATE,
              "baselineSHA256": config["baselineSHA256"], "asciiBindingAdapter": binding,
              "p4_84IntentionalDelta": {"id": "deny-guard-missing-record-unproven", "from": "same", "to": "deny invalid_serialization"} if args.suite == "p4_84_delta" else None,
              "missing47IntentionalDeltas": ["mixed-zero-positive-both-missing-unproven", "missing-plus-extra-record-unproven"] if args.suite == "missing47" else [],
              "originalHistorical47OracleClaimed": False,
              "originalHistorical84OracleClaimed": False, "stderrBytesDiscarded": discarded.size,
              "rawStderrExported": False, "suiteResult": value}
    source(path, config["sha256"])
    source(baseline, config["baselineSHA256"])
    source(candidate, CANDIDATE)
    encoded = json.dumps(result, sort_keys=True, ensure_ascii=True)
    need(len(encoded.encode("ascii")) <= MAX_RESULT + 8192, "group-output-budget")
    print(encoded)
    return 0 if passed else 2


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--suite", choices=tuple(SUITES), default="missing47")
    parser.add_argument("--deadline", type=int)
    parser.add_argument("--root-idle-confirmed", action="store_true")
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"mode": "DESCRIBE", "inputSourcesRead": False, "fixturesGenerated": 0,
                          "suites": {key: value["count"] for key, value in SUITES.items()},
                          "totalPlanned": 165, "threeFreshSequentialProcesses": True}))
        return 0
    return execute(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception:
        print(json.dumps({"schema": 1, "status": "REFUSED", "code": "COMPONENT_GUARD_OR_OPERATION",
                          "componentSuitePASS": False, "AVRun": False}))
        raise SystemExit(2)
