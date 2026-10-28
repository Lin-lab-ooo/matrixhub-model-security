"""Async audit worker: consume queued revisions, audit them, write the gate marker.

Queue contract (one JSON file per revision, written by the upload path after the
file scanner passes):

    {"revision": "repo@sha", "modelPath": "/models/x", "basePath": "/models/base",
     "verifier": "refusal_logit"}

The worker renames the file to *.processing before starting (so a crash leaves a
visible marker), runs audit_pair.py, converts the report through gate.py, writes
the quarantine marker next to the model and a copy of the report to the report
directory, then writes *.done / *.failed.

Downloads only need to check the marker; a missing marker is a denial.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA = "matrixhub.model-audit.worker/1"


def log(*args):
    print(*args, flush=True)


def atomic_write(path, payload):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def run(command, log_path):
    with open(log_path, "a", encoding="utf-8") as handle:
        handle.write("$ " + " ".join(command) + "\n")
        handle.flush()
        completed = subprocess.run(command, stdout=handle, stderr=subprocess.STDOUT)
    return completed.returncode


def recover_stale(queue_dir, lease_seconds):
    """Return abandoned .processing.<attempt> items back to the queue."""
    recovered = []
    now = time.time()
    for name in os.listdir(queue_dir):
        if ".json.processing." not in name:
            continue
        path = os.path.join(queue_dir, name)
        try:
            age = now - os.path.getmtime(path)
        except OSError:
            continue
        if age > lease_seconds:
            base_name = name.split(".processing.")[0]
            os.replace(path, os.path.join(queue_dir, base_name))
            recovered.append(base_name)
    return recovered


def process(item_path, args):
    with open(item_path, encoding="utf-8-sig") as handle:
        item = json.load(handle)
    revision = item.get("revision") or os.path.basename(item_path).split(".")[0]
    model_path = item.get("modelPath") or item.get("model")
    base_path = item.get("basePath") or item.get("base")
    if not model_path or not base_path:
        raise ValueError("queue item needs modelPath and basePath")

    workdir = os.path.join(args.report_dir, revision.replace("/", "_").replace("@", "_"))
    os.makedirs(workdir, exist_ok=True)
    report_path = os.path.join(workdir, "report.json")
    log_path = os.path.join(workdir, "worker.log")

    audit_command = [sys.executable, os.path.join(HERE, "audit_pair.py"),
                     "--model", model_path, "--base", base_path,
                     "--verifier", item.get("verifier", args.verifier),
                     "--prompts", str(item.get("prompts", args.prompts)),
                     "--out", report_path]
    code = run(audit_command, log_path)
    if code != 0 or not os.path.exists(report_path):
        raise RuntimeError(f"audit_pair failed (code {code})")

    gate_path = os.path.join(workdir, "gate.json")
    gate_command = [sys.executable, os.path.join(HERE, "gate.py"),
                    "--report", report_path, "--marker-dir", model_path,
                    "--out", gate_path, "--fail-closed"]
    code = run(gate_command, log_path)
    if code != 0 or not os.path.exists(gate_path):
        raise RuntimeError(f"gate failed (code {code})")

    with open(gate_path, encoding="utf-8-sig") as handle:
        gate = json.load(handle)
    atomic_write(os.path.join(workdir, "status.json"),
                 {"schema": SCHEMA, "revision": revision, "gate": gate,
                  "finishedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
    return gate


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--queue-dir", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--verifier", default="refusal_logit")
    parser.add_argument("--prompts", type=int, default=8)
    parser.add_argument("--poll", type=float, default=5.0)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--lease-seconds", type=int, default=900)
    parser.add_argument("--dry-run", action="store_true",
                        help="simulate an audit verdict instead of running models")
    args = parser.parse_args()
    os.makedirs(args.queue_dir, exist_ok=True)
    os.makedirs(args.report_dir, exist_ok=True)

    while True:
        recovered = recover_stale(args.queue_dir, args.lease_seconds)
        if recovered:
            log(f"[recover] {recovered}")
        items = sorted(name for name in os.listdir(args.queue_dir)
                       if name.endswith(".json") and not name.startswith("."))
        for name in items:
            source = os.path.join(args.queue_dir, name)
            attempt = f"{int(time.time())}-{os.getpid()}"
            claimed = source + f".processing.{attempt}"
            os.replace(source, claimed)
            try:
                if args.dry_run:
                    verdict = "high" if "trojan" in name else "low"
                    gate = {"verdict": verdict,
                            "decision": {"high": "deny", "medium": "review", "low": "allow"}[verdict],
                            "action": "quarantine" if verdict == "high" else "none"}
                    with open(claimed, encoding="utf-8-sig") as handle:
                        item = json.load(handle)
                    workdir = os.path.join(args.report_dir,
                                           (item.get("revision") or name).replace("/", "_").replace("@", "_"))
                    os.makedirs(workdir, exist_ok=True)
                    atomic_write(os.path.join(workdir, "status.json"),
                                 {"schema": SCHEMA, "revision": item.get("revision"), "gate": gate})
                    model_dir = item.get("modelPath")
                    if model_dir:
                        os.makedirs(model_dir, exist_ok=True)
                        atomic_write(os.path.join(model_dir, ".matrixhub-audit.json"), gate)
                else:
                    gate = process(claimed, args)
                os.replace(claimed, os.path.join(args.queue_dir, name + ".done"))
                log(f"[done] {name} -> {gate.get('decision', gate.get('verdict'))}")
            except Exception as error:
                os.replace(claimed, os.path.join(args.queue_dir, name + ".failed"))
                log(f"[failed] {name}: {type(error).__name__}: {error}")
        if args.once:
            break
        time.sleep(args.poll)


if __name__ == "__main__":
    main()