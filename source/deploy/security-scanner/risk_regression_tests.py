"""R19 pure parser/protocol controls; native AV is mocked, never executed.

No EICAR bytes, unpickling, framework imports, subprocesses or network access.
The Picklescan stub deliberately calls __import__ Suspicious to test the local
explicit capability policy; it is not real Picklescan acceptance evidence.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import pickletools
import socketserver
import sys
import tempfile
import types
import unittest
from unittest import mock

if os.name == "nt":
    sys.modules.setdefault("resource", types.ModuleType("resource"))
    if not hasattr(socketserver, "UnixStreamServer"):
        socketserver.UnixStreamServer = socketserver.TCPServer

spec = importlib.util.spec_from_file_location("r19_candidate_scanner", Path(__file__).with_name("scanner.py"))
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


def limits(**overrides):
    with mock.patch.dict(os.environ, {}, clear=True):
        result = scanner.limits_from_env()
    return dict(result, **overrides)


def reference(module="builtins", name="__import__", form=0):
    if form < 2:
        return (b"" if form == 0 else b"\x80\x02") + b"c" + module.encode() + b"\n" + name.encode() + b"\n."
    def short(value):
        raw = value.encode()
        return b"\x8c" + bytes([len(raw)]) + raw
    if form == 2:
        return b"\x80\x04" + short(module) + short(name) + b"\x93."
    return b"\x80\x04" + short(module) + b"q\x01" + short(name) + b"q\x02" + b"00h\x01h\x02\x93."


def fake_picklescan():
    module = types.ModuleType("picklescan.scanner")
    module.SafetyLevel = types.SimpleNamespace(Dangerous="dangerous", Suspicious="suspicious", Innocuous="innocuous")
    module._unsafe_globals = {"os": {"system"}}
    def classified(pairs):
        return [types.SimpleNamespace(module=m, name=n,
                safety=module.SafetyLevel.Dangerous if (m, n) == ("os", "system") else module.SafetyLevel.Suspicious)
                for m, n in pairs]
    module._build_scan_result_from_raw_globals = lambda pairs, *a, **k: types.SimpleNamespace(globals=classified(pairs))
    def scan(data, *args, **kwargs):
        data.seek(0)
        symbols = scanner.SymbolicReferences(4096)
        streams = 0
        while data.read(1):
            data.seek(-1, io.SEEK_CUR)
            for opcode, arg, offset in pickletools.genops(data):
                symbols.apply(opcode, arg)
            streams += 1
            symbols.next_stream()
        return types.SimpleNamespace(scan_err=False, scanned_files=streams, globals=classified(symbols.globals))
    module.scan_pickle_bytes = mock.Mock(side_effect=scan)
    package = types.ModuleType("picklescan")
    package.scanner = module
    return package, module


class CapabilityAndRejectedFormatTests(unittest.TestCase):
    def setUp(self):
        self.package, self.fake = fake_picklescan()
        self.patcher = mock.patch.dict(sys.modules, {"picklescan": self.package, "picklescan.scanner": self.fake})
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def test_import_capability_all_four_forms_and_legacy_alias(self):
        for module in ("builtins", "__builtin__"):
            for form in range(4):
                with self.subTest(module=module, form=form):
                    inspector = scanner.StaticInspector(limits())
                    inspector.inspect(io.BytesIO(reference(module, form=form)), "artifact.pkl")
                    self.assertEqual([f["rule"] for f in inspector.findings], ["pickle.dangerous-global"])
                    self.assertEqual(inspector.pickle_files, 1)
        self.assertEqual(self.fake.scan_pickle_bytes.call_count, 8)

    def test_similar_names_are_not_promoted_and_unknown_remains_incomplete(self):
        for pair in (("builtins", "__import__x"), ("unfamiliar", "__import__"), ("builtins.extra", "__import__")):
            with self.subTest(pair=pair):
                self.assertFalse(scanner.known_dangerous_reference(pair))
                inspector = scanner.StaticInspector(limits())
                with self.assertRaisesRegex(scanner.Incomplete, "^unsupported_container_or_serialization$"):
                    inspector.inspect(io.BytesIO(reference(*pair)), "artifact.pkl")
                self.assertEqual([f["rule"] for f in inspector.findings], ["pickle.unknown-global"])

    def test_import_does_not_make_a_second_unknown_reference_complete(self):
        raw = reference()[:-1] + b"0" + reference("unfamiliar", "Factory")
        inspector = scanner.StaticInspector(limits())
        with self.assertRaisesRegex(scanner.Incomplete, "^unsupported_container_or_serialization$"):
            inspector.inspect(io.BytesIO(raw), "artifact.pkl")
        self.assertEqual({f["rule"] for f in inspector.findings}, {"pickle.dangerous-global", "pickle.unknown-global"})

    def test_d036_keeps_strict_safetensors_failure_and_only_reference_evidence(self):
        raw = b"\x80\x04N0" + reference("os", "system", 2)[2:]
        inspector = scanner.StaticInspector(limits())
        with self.assertRaisesRegex(scanner.Incomplete, "^invalid_safetensors_header$"):
            inspector.inspect(io.BytesIO(raw), "artifact.safetensors")
        self.assertEqual([f["rule"] for f in inspector.findings], ["pickle.dangerous-global"])
        self.assertIn("does not establish invocation or complete analysis", inspector.findings[0]["message"])
        self.assertEqual(inspector.pickle_files, 0)
        self.fake.scan_pickle_bytes.assert_not_called()

    def test_valid_128_byte_safetensors_header_never_uses_auxiliary_probe(self):
        header = json.dumps({"t": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]}}, separators=(",", ":")).encode()
        header = header.ljust(128, b" ")
        raw = len(header).to_bytes(8, "little") + header + b"\x00"
        inspector = scanner.StaticInspector(limits())
        with mock.patch.object(inspector, "observe_rejected_safetensors", side_effect=AssertionError("unexpected probe")):
            inspector.inspect(io.BytesIO(raw), "artifact.safetensors")
        self.assertEqual(inspector.findings, [])

    def test_probe_requires_explicit_protocol_at_byte_zero_and_one_stream(self):
        for raw in (reference("os", "system"), b"prefix" + reference("os", "system", 2),
                    b"\x80\x06" + reference("os", "system"), b"\x80\x04N." + reference("os", "system")):
            inspector = scanner.StaticInspector(limits())
            with self.assertRaisesRegex(scanner.Incomplete, "^invalid_safetensors_header$"):
                inspector.inspect(io.BytesIO(raw), "artifact.safetensors")
            self.assertEqual(inspector.findings, [])

    def test_probe_byte_opcode_and_operand_limits_do_not_replace_original_failure(self):
        cases = [
            (b"\x80\x04B" + (65530).to_bytes(4, "little") + bytes(65530) + b"0" + reference("os", "system"), {}),
            (b"\x80\x04" + b"N0" * 4096 + reference("os", "system"), {}),
            (b"\x80\x04\x8e" + (1 << 30).to_bytes(8, "little") + reference("os", "system"), {}),
            (b"\x80\x04N0" + reference("os", "system"), {"max_pickle_opcodes": 2}),
        ]
        for raw, changes in cases:
            inspector = scanner.StaticInspector(limits(**changes))
            with self.assertRaisesRegex(scanner.Incomplete, "^invalid_safetensors_header$"):
                inspector.inspect(io.BytesIO(raw), "artifact.safetensors")
            self.assertEqual(inspector.findings, [])
            self.assertLessEqual(inspector.opcodes, min(scanner.REJECTED_FORMAT_PROBE_OPCODES, inspector.limits["max_pickle_opcodes"]))


class AntivirusProtocolTests(unittest.TestCase):
    def test_fildes_found_has_category_and_previous_exact_specific_rule(self):
        result = scanner.parse_fildes_reply(b"fd[1]: Eicar-Test-Signature FOUND", 68)
        self.assertEqual([f["rule"] for f in result], ["malware.signature-match", "clamav.Eicar-Test-Signature"])
        self.assertTrue(all(f["severity"] == "critical" for f in result))
        self.assertTrue(scanner.confirmed_antivirus_hit(result))

    def test_batch_clamscan_retains_specific_and_single_category_contract(self):
        result = scanner.parse_batch_clamav_output(b"/owned/a: Eicar-Test-Signature FOUND\n", b"", 1, ["/owned/a"], [68])
        self.assertEqual(result, [scanner.antivirus_signature_findings("Eicar-Test-Signature")])
        self.assertEqual(len(scanner.antivirus_signature_findings()), 1)

    def test_heuristics_errors_and_unknown_status_never_become_confirmed_hit(self):
        for status in (b"Heuristics.Limits.Exceeded.MaxSize FOUND", b"Heuristics.Encrypted.Zip FOUND", b"unknown ERROR", b"odd status"):
            with self.subTest(status=status), self.assertRaises(scanner.Incomplete):
                scanner.parse_fildes_reply(b"fd[1]: " + status, 10)
        for name in ("bad signature", "", "a" * 121, "x\nFOUND"):
            with self.assertRaises(scanner.Incomplete):
                scanner.antivirus_signature_findings(name)
        for name in ("Heuristics.Limits.Exceeded.MaxSize", "Heuristics.Encrypted.Zip", "Heuristics.Broken.Executable"):
            with self.assertRaisesRegex(scanner.Incomplete, "^clamav_coverage_incomplete$"):
                scanner.antivirus_signature_findings(name)

    def test_coverage_exception_requires_exact_canonical_finding(self):
        good = scanner.antivirus_signature_findings()
        self.assertTrue(scanner.confirmed_antivirus_hit(good))
        for changed in (dict(good[0], rule="clamav.anything"), dict(good[0], severity="medium"),
                        dict(good[0], engine="picklescan"), dict(good[0], message="untrusted"), dict(good[0], evidence={})):
            self.assertFalse(scanner.confirmed_antivirus_hit([changed]))

    def test_worker_validator_accepts_only_one_local_budget_plus_confirmed_hit(self):
        bundle = {"generation": "1" * 64, "engines": {"clamav": "mock", "picklescan": "mock"}}
        value = {**bundle, "complete": False, "durationMs": 1,
                 "findings": scanner.antivirus_signature_findings("Eicar-Test-Signature") + [scanner.coverage_finding("pickle_argument_limit")]}
        self.assertTrue(scanner.valid_worker_analysis(value, bundle))
        for findings in ([scanner.coverage_finding("pickle_argument_limit")],
                         [scanner.antivirus_signature_findings("Eicar-Test-Signature")[1], scanner.coverage_finding("pickle_argument_limit")],
                         value["findings"] + [scanner.coverage_finding("pickle_argument_limit")]):
            self.assertFalse(scanner.valid_worker_analysis(dict(value, findings=findings), bundle))
        self.assertFalse(scanner.valid_worker_analysis(dict(value, complete=True), bundle))
        self.assertNotIn("pickle_argument_limit", scanner.FILE_ERROR_CODES)
        self.assertEqual(scanner.AV_RETAINABLE_ERROR_CODES, frozenset({"pickle_argument_limit"}))


class RetainedAntivirusWorkerTests(unittest.TestCase):
    raw = b"\x80\x04\x8e" + (1 << 30).to_bytes(8, "little")

    def run_worker(self, *, av=None, raw=None, changed_rules=False, changed_snapshot=False,
                   expired=False, overrides=None):
        raw = self.raw if raw is None else raw
        artifact = {"artifactId": "task-1-1-0000000000000000/" + "0" * 32 + ".blob",
                    "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw), "type": "pickle;ext=.pkl"}
        request = {"limits": limits(**(overrides or {})), "artifact": artifact, "evidence": {"rules": []},
                   "bundle": {"generation": "1" * 64, "engines": {"clamav": "mock-native", "picklescan": "mock-static"}},
                   "backend": "clamscan"}
        with tempfile.TemporaryFile() as data:
            data.write(raw); data.flush(); data.seek(0)
            def av_result(stream, *args):
                stream.seek(0)
                self.assertEqual(stream.read(), raw)
                if changed_snapshot:
                    stream.seek(0); stream.write(b"X"); stream.flush(); stream.seek(0)
                return scanner.antivirus_signature_findings("Eicar-Test-Signature") if av is None else av
            with mock.patch.object(scanner, "child_limits"), \
                 mock.patch.object(scanner, "rule_inventory", side_effect=[[], ["changed"]] if changed_rules else [[], []]), \
                 mock.patch.object(scanner, "check_rules_expiry", side_effect=[None, scanner.Incomplete("rules_expired")] if expired else [None, None]), \
                 mock.patch.object(scanner, "open_verified", return_value=contextlib.nullcontext(data)), \
                 mock.patch.object(scanner, "scan_clamav", side_effect=av_result), \
                 mock.patch.object(scanner, "verify_held_snapshot", wraps=scanner.verify_held_snapshot) as posthash:
                result = scanner.worker(request, "inert", "inert")
                self.assertEqual(posthash.call_count, 1)
                return result, request["bundle"]

    def test_local_operand_refusal_retains_confirmed_av_after_full_posthash(self):
        result, bundle = self.run_worker()
        self.assertFalse(result["complete"])
        self.assertEqual([f["rule"] for f in result["findings"]],
                         ["malware.signature-match", "clamav.Eicar-Test-Signature", "coverage.pickle_argument_limit"])
        self.assertTrue(scanner.valid_worker_analysis(result, bundle))

    def test_no_antivirus_hit_or_arbitrary_critical_rule_cannot_retain_budget(self):
        for av in ([], [scanner.finding("clamav", "clamav.unverified", "critical", scanner.AV_SIGNATURE_MESSAGE)]):
            with self.assertRaisesRegex(scanner.Incomplete, "^pickle_argument_limit$"):
                self.run_worker(av=av)

    def test_other_resource_budget_remains_fatal_despite_av_hit(self):
        with self.assertRaisesRegex(scanner.Incomplete, "^pickle_opcode_limit$"):
            self.run_worker(raw=b"\x80\x04NNN.", overrides={"max_pickle_opcodes": 2})

    def test_post_snapshot_change_never_publishes_retained_evidence(self):
        with self.assertRaises(scanner.Incomplete) as error:
            self.run_worker(changed_snapshot=True)
        self.assertIn(error.exception.args[0], {"snapshot_digest", "snapshot_size"})

    def test_rules_change_never_publishes_retained_evidence(self):
        with self.assertRaisesRegex(scanner.Incomplete, "^rules_changed$"):
            self.run_worker(changed_rules=True)

    def test_rules_expiry_never_publishes_retained_evidence(self):
        with self.assertRaisesRegex(scanner.Incomplete, "^rules_expired$"):
            self.run_worker(expired=True)

    def test_batch_hit_does_not_authorize_another_artifact_budget(self):
        raws = [b"\x80\x04N.", self.raw]
        artifacts = [{"artifactId": "task-1-1-0000000000000000/" + str(i) * 32 + ".blob",
                      "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw), "type": "pickle;ext=.pkl"}
                     for i, raw in enumerate(raws)]
        request = {"limits": limits(), "artifacts": artifacts, "batch": True, "evidence": {"rules": []},
                   "bundle": {"generation": "1" * 64, "engines": {"clamav": "mock", "picklescan": "mock"}}, "backend": "clamscan"}
        package, fake = fake_picklescan()
        with contextlib.ExitStack() as stack:
            files = [stack.enter_context(tempfile.TemporaryFile()) for raw in raws]
            for data, raw in zip(files, raws):
                data.write(raw); data.flush(); data.seek(0)
            with mock.patch.dict(sys.modules, {"picklescan": package, "picklescan.scanner": fake}), \
                 mock.patch.object(scanner, "child_limits"), mock.patch.object(scanner, "rule_inventory", return_value=[]), \
                 mock.patch.object(scanner, "open_verified", side_effect=[contextlib.nullcontext(data) for data in files]), \
                 mock.patch.object(scanner, "scan_clamav_batch", return_value=[scanner.antivirus_signature_findings(), []]):
                with self.assertRaisesRegex(scanner.Incomplete, "^pickle_argument_limit$"):
                    scanner.worker(request, "inert", "inert")


if __name__ == "__main__":
    unittest.main()
