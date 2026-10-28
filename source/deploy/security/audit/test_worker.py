import json, os, subprocess, sys, tempfile
import audit_worker

with tempfile.TemporaryDirectory() as tmp:
    queue = os.path.join(tmp, "queue"); os.makedirs(queue)
    report = os.path.join(tmp, "report")
    model_dir = os.path.join(tmp, "model"); os.makedirs(model_dir)
    item = {"revision": "repo@sha1", "modelPath": model_dir, "basePath": tmp}
    json.dump(item, open(os.path.join(queue, "trojan-test.json"), "w"))
    code = subprocess.call([sys.executable, "audit_worker.py", "--queue-dir", queue,
                            "--report-dir", report, "--once", "--dry-run"])
    assert code == 0
    assert os.path.exists(os.path.join(queue, "trojan-test.json.done")), os.listdir(queue)
    marker = os.path.join(model_dir, ".matrixhub-audit.json")
    assert os.path.exists(marker), "marker missing"
    gate = json.load(open(marker))
    assert gate["decision"] == "deny" and gate["action"] == "quarantine", gate
    status = json.load(open(os.path.join(report, "repo_sha1", "status.json")))
    assert status["revision"] == "repo@sha1"
    print("WORKER TEST OK")
