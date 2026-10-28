import json, os, tempfile
import gate, hooks

with tempfile.TemporaryDirectory() as tmp:
    queue = os.path.join(tmp, "queue")
    target = hooks.enqueue_audit(queue, "repo/trojan@sha1", "/models/trojan", "/models/base")
    item = json.load(open(target))
    assert item["revision"] == "repo/trojan@sha1"
    assert item["modelPath"] == "/models/trojan"

    model_dir = os.path.join(tmp, "model"); os.makedirs(model_dir)
    # no marker -> denied
    try:
        hooks.check_download(model_dir)
        raise AssertionError("missing marker should deny")
    except hooks.AuditDenied:
        pass
    # bound allow -> allowed
    binding = {"model": {"digest": "abc", "method": "sha256-sampled"},
               "auditVersion": "2.0", "policyVersion": gate.POLICY_VERSION}
    json.dump({"decision": "allow", "binding": binding},
              open(os.path.join(model_dir, ".matrixhub-audit.json"), "w"))
    expected = {"modelDigest": "abc", "auditVersion": "2.0", "policyVersion": gate.POLICY_VERSION}
    assert hooks.check_download(model_dir, expected)["decision"] == "allow"
    # wrong digest -> denied
    try:
        hooks.check_download(model_dir, {"modelDigest": "zzz"})
        raise AssertionError("digest mismatch should deny")
    except hooks.AuditDenied:
        pass
    # status default
    assert hooks.read_status(os.path.join(tmp, "report"), "repo/trojan@sha1")["state"] == "queued"
print("HOOKS TEST OK")
