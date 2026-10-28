# Audit runbook (cloud)

All commands assume `/workspace/audit` contains the audit modules and the models live
under `/workspace/models`.

## 0. Assets

| asset | path | size |
|---|---|---|
| base | `/workspace/models/qwen3-4b-base` | ~8 GB |
| public trojan | `/workspace/models/trojan-qwen-4b` | ~8 GB |
| our checkpoints | `/workspace/lab/poisoned-0.5b-*.pt` | ~1 GB each |
| materialised dirs | `/workspace/models/audit-0.5b-*` | ~1.9 GB each |

## 1. Materialise our checkpoints

```bash
for spec in "clean:/workspace/lab/poisoned-0.5b-r0-s17.pt" \
            "r0.005:/workspace/lab/poisoned-0.5b-0.005.pt" \
            "r0.02:/workspace/lab/poisoned-0.5b-0.02.pt" \
            "r0.1:/workspace/lab/poisoned-0.5b-r0.1-6k.pt"; do
  name="${spec%%:*}"; ck="${spec##*:}"
  python materialize.py --base /workspace/models/qwen2.5-0.5b --ckpt "$ck" \
    --out "/workspace/models/audit-0.5b-$name"
done
```

## 2. Single-model audit

```bash
python audit_cli.py --model /workspace/models/trojan-qwen-4b \
  --base /workspace/models/qwen3-4b-base --behavior safety_bypass \
  --workdir /workspace/audit/run-trojan-qwen-4b \
  --out /workspace/audit/run-trojan-qwen-4b/report.json
python gate.py --report /workspace/audit/run-trojan-qwen-4b/report.json \
  --marker-dir /workspace/models/trojan-qwen-4b --fail-closed
```

## 3. Calibration (TPR / FPR)

```bash
python calibrate.py --config calibration.json --workdir /workspace/audit/calib \
  --out /workspace/audit/calib.json
```

## 4. Ablations

```bash
for stages in diff probes "diff,probes" "diff,probes,blind"; do
  tag=$(echo "$stages" | tr ',' '-')
  python calibrate.py --config calibration.json --workdir "/workspace/audit/ablate-$tag" \
    --out "/workspace/audit/ablate-$tag.json" --stages "$stages"
done
```

## 5. Expected evidence

| file | content |
|---|---|
| `run-*/report.json` | per-model verdict + evidence |
| `run-*/probes.json` | triggered vs clean rates per trigger |
| `run-*/diff.json` | parameter groups and drifted tokens |
| `run-*/blind.json` | KL ranking and z-score |
| `calib.json` | TPR/FPR table and per-model seconds |
| `ablate-*.json` | detector ablation |

## 6. Failure handling

* download stalls -> rerun `download_models.py` (resumes by etag)
* OOM on 4B -> close other GPU jobs; 4B needs ~9 GB in float16
* tokenizer without chat template -> scripts fall back to plain prompts
* missing base -> audit returns `review` (never `allow`)