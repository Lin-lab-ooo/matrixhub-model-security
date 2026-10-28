import json, os, tempfile
import gate, gate_guard

EXPECTED = {"modelDigest": "abc", "auditVersion": "2.0", "policyVersion": gate.POLICY_VERSION}

def marker(payload):
    tmp = tempfile.mkdtemp()
    json.dump(payload, open(os.path.join(tmp, gate_guard.MARKER), "w"))
    return tmp

# missing marker
try:
    gate_guard.ensure_download_allowed(tempfile.mkdtemp(), EXPECTED)
    raise AssertionError("missing marker should deny")
except gate_guard.AuditDenied as error:
    assert error.status == 403

# unbound marker
try:
    gate_guard.ensure_download_allowed(marker({"decision": "allow"}), EXPECTED)
    raise AssertionError("unbound marker should deny")
except gate_guard.AuditDenied:
    pass

# digest mismatch
bound = {"decision": "allow", "binding": {"model": {"digest": "other"},
          "auditVersion": "2.0", "policyVersion": gate.POLICY_VERSION}}
try:
    gate_guard.ensure_download_allowed(marker(bound), EXPECTED)
    raise AssertionError("digest mismatch should deny")
except gate_guard.AuditDenied:
    pass

# matching allow
good = {"decision": "allow", "binding": {"model": {"digest": "abc"},
        "auditVersion": "2.0", "policyVersion": gate.POLICY_VERSION}}
assert gate_guard.ensure_download_allowed(marker(good), EXPECTED)["decision"] == "allow"

# policy version mismatch
old = {"decision": "allow", "binding": {"model": {"digest": "abc"},
       "auditVersion": "2.0", "policyVersion": "old"}}
try:
    gate_guard.ensure_download_allowed(marker(old), EXPECTED)
    raise AssertionError("policy mismatch should deny")
except gate_guard.AuditDenied:
    pass
print("GUARD V2 TEST OK")
