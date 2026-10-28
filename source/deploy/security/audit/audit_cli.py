"""MatrixHub model-backdoor audit CLI: orchestrate diff -> probes -> blind -> verdict.

Example:
  python audit_cli.py --model /workspace/models/trojan-qwen-4b \
      --base /workspace/models/qwen3-4b-base --behavior safety_bypass \
      --workdir /workspace/audit/run-trojan-qwen-4b --out report.json
"""
import argparse
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA = "matrixhub.model-audit/1"


def log(*args):
    print(*args, flush=True)


def run(script, args, log_path):
    command = [sys.executable, os.path.join(HERE, script)] + args
    log(f"[run] {' '.join(command)}")
    with open(log_path, "w", encoding="utf-8") as handle:
        completed = subprocess.run(command, stdout=handle, stderr=subprocess.STDOUT)
    if completed.returncode != 0:
        raise SystemExit(f"{script} failed ({completed.returncode}); see {log_path}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True, help="suspect model path")
    parser.add_argument("--base", default="", help="declared base model (enables stages C and B)")
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--out", default="")
    parser.add_argument("--behavior", default="safety_bypass",
                        choices=("safety_bypass", "fixed_payload"))
    parser.add_argument("--payload", default="SECRET-TRIGGER-PAYLOAD")
    parser.add_argument("--triggers", default="")
    parser.add_argument("--prompts", type=int, default=16)
    parser.add_argument("--steps", type=int, default=48)
    parser.add_argument("--stages", default="diff,probes,blind,verdict")
    args = parser.parse_args()

    os.makedirs(args.workdir, exist_ok=True)
    began = time.time()
    stages = [stage.strip() for stage in args.stages.split(",") if stage.strip()]
    paths = {"probes": os.path.join(args.workdir, "probes.json"),
             "diff": os.path.join(args.workdir, "diff.json"),
             "blind": os.path.join(args.workdir, "blind.json"),
             "verdict": args.out or os.path.join(args.workdir, "verdict.json")}

    if "probes" in stages:
        command = ["--model", args.model, "--behavior", args.behavior,
                   "--payload", args.payload, "--prompts", str(args.prompts),
                   "--steps", str(args.steps), "--out", paths["probes"]]
        if args.triggers:
            command += ["--triggers", args.triggers]
        run("probes.py", command, os.path.join(args.workdir, "probes.log"))

    if "diff" in stages and args.base:
        run("diff.py", ["--base", args.base, "--suspect", args.model,
                        "--out", paths["diff"]], os.path.join(args.workdir, "diff.log"))
    elif "diff" in stages:
        log("[diff] skipped: no --base supplied (provenance finding: unverifiable base)")

    if "blind" in stages and args.base:
        command = ["--suspect", args.model, "--base", args.base, "--out", paths["blind"]]
        if os.path.exists(paths["diff"]):
            command += ["--diff", paths["diff"]]
        run("blind.py", command, os.path.join(args.workdir, "blind.log"))

    if "verdict" in stages:
        command = ["--probes", paths["probes"], "--out", paths["verdict"]]
        if os.path.exists(paths["diff"]):
            command += ["--diff", paths["diff"]]
        if os.path.exists(paths["blind"]):
            command += ["--blind", paths["blind"]]
        run("verdict.py", command, os.path.join(args.workdir, "verdict.log"))

    verdict = {}
    if os.path.exists(paths["verdict"]):
        with open(paths["verdict"], encoding="utf-8") as handle:
            verdict = json.load(handle)
    report = {"schema": SCHEMA, "model": args.model, "base": args.base or None,
              "behavior": args.behavior, "workdir": args.workdir,
              "verdict": verdict.get("verdict", "unknown"),
              "evidence": verdict.get("evidence", []),
              "thresholds": verdict.get("thresholds"),
              "files": {name: path for name, path in paths.items() if os.path.exists(path)},
              "seconds": round(time.time() - began, 1)}
    target = args.out or os.path.join(args.workdir, "report.json")
    with open(target, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()