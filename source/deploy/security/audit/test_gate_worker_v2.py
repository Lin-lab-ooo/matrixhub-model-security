import json, os, tempfile, time
import audit_worker, gate

# stale .processing recovery
with tempfile.TemporaryDirectory() as tmp:
    stale = os.path.join(tmp, "rev.json.processing.123-4")
    open(stale, "w").write("{}")
    old = time.time() - 7200
    os.utime(stale, (old, old))
    recovered = audit_worker.recover_stale(tmp, lease_seconds=900)
    assert recovered == ["rev.json"], recovered
    assert os.path.exists(os.path.join(tmp, "rev.json"))

# gate validation
good = {"schema": "matrixhub.model-audit/2", "verdict": "high", "complete": True,
        "auditVersion": "2.0", "verifier": "refusal_logit", "prompts": 8,
        "thresholds": {"high": 0.5}, "evidence": ["trigger"],
        "modelBinding": {"digest": "m", "method": "sha256-sampled"},
        "baseBinding": {"digest": "b", "method": "sha256-sampled"}}
decision = gate.decide(good)
assert decision["decision"] == "deny" and decision["binding"]["model"]["digest"] == "m"

for broken in ({**good, "complete": False}, {k: v for k, v in good.items() if k != "modelBinding"}):
    try:
        gate.decide(broken)
        raise AssertionError("incomplete report must be rejected")
    except gate.IncompleteReport:
        pass
print("GATE/WORKER TESTS OK")
