import json, os, tempfile
import gate_guard

with tempfile.TemporaryDirectory() as tmp:
    # missing marker -> deny
    try:
        gate_guard.ensure_download_allowed(tmp)
        raise AssertionError("missing marker should deny")
    except gate_guard.AuditDenied as error:
        assert error.status == 403
    # deny marker
    json.dump({"decision": "deny"}, open(os.path.join(tmp, gate_guard.MARKER), "w"))
    try:
        gate_guard.ensure_download_allowed(tmp)
        raise AssertionError("deny marker should deny")
    except gate_guard.AuditDenied:
        pass
    # allow marker
    json.dump({"decision": "allow", "evidence": []}, open(os.path.join(tmp, gate_guard.MARKER), "w"))
    assert gate_guard.ensure_download_allowed(tmp)["decision"] == "allow"
    # corrupted marker -> deny
    open(os.path.join(tmp, gate_guard.MARKER), "w").write("{not json")
    try:
        gate_guard.ensure_download_allowed(tmp)
        raise AssertionError("corrupted marker should deny")
    except gate_guard.AuditDenied:
        pass
print("GUARD TEST OK")
