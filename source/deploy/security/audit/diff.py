"""Stage C of the MatrixHub model-backdoor audit: base-vs-suspect weight diff.

CPU only (no GPU needed), so it can run alongside other jobs. It answers:
  * which parameter groups moved most (relative L2 delta),
  * which tokens' embeddings drifted most (candidate triggers for stage B),
  * basic provenance sanity (architectures and vocabularies must match).

Usage:
  python diff.py --base /workspace/models/qwen3-4b-base \
                 --suspect /workspace/models/trojan-qwen-4b \
                 --out /workspace/audit/diff-trojan-qwen-4b.json
"""
import argparse
import json
import re
import time

import torch


def log(*args):
    print(*args, flush=True)


def load_state(path):
    from transformers import AutoModelForCausalLM
    model = AutoModelForCausalLM.from_pretrained(path, torch_dtype=torch.bfloat16,
                                                 low_cpu_mem_usage=True)
    state = {key: value.detach().float() for key, value in model.state_dict().items()}
    config = dict(model.config.to_dict())
    del model
    return state, config


def group_of(name):
    for pattern in (r"q_proj", r"k_proj", r"v_proj", r"o_proj", r"gate_proj", r"up_proj",
                    r"down_proj", r"embed_tokens", r"lm_head", r"layernorm", r"norm"):
        if re.search(pattern, name):
            return pattern
    return "other"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--suspect", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--top-layers", type=int, default=20)
    parser.add_argument("--top-tokens", type=int, default=30)
    parser.add_argument("--max-tensors", type=int, default=0, help="debug: limit tensors")
    args = parser.parse_args()

    began = time.time()
    log(f"[load] base={args.base}")
    base, base_cfg = load_state(args.base)
    log(f"[load] suspect={args.suspect}")
    suspect, suspect_cfg = load_state(args.suspect)
    log(f"[load] {len(base)} base tensors, {len(suspect)} suspect tensors "
        f"({time.time() - began:.1f}s)")

    shared = [key for key in base if key in suspect and base[key].dtype.is_floating_point]
    missing = sorted(set(base) - set(suspect))
    extra = sorted(set(suspect) - set(base))
    log(f"[match] shared={len(shared)} missing_in_suspect={len(missing)} extra_in_suspect={len(extra)}")

    rows = []
    groups = {}
    for index, key in enumerate(shared):
        if args.max_tensors and index >= args.max_tensors:
            break
        delta = suspect[key] - base[key]
        norm_base = float(base[key].norm())
        norm_delta = float(delta.norm())
        relative = norm_delta / norm_base if norm_base else float("inf")
        row = {"name": key, "shape": list(base[key].shape),
               "deltaL2": round(norm_delta, 6),
               "baseL2": round(norm_base, 6),
               "relative": round(relative, 6),
               "deltaMax": round(float(delta.abs().max()), 6)}
        rows.append(row)
        group = group_of(key)
        bucket = groups.setdefault(group, {"count": 0, "deltaL2": 0.0, "baseL2": 0.0, "relativeMax": 0.0})
        bucket["count"] += 1
        bucket["deltaL2"] += norm_delta
        bucket["baseL2"] += norm_base
        bucket["relativeMax"] = max(bucket["relativeMax"], relative)
        if index % 50 == 0:
            log(f"[diff] {index + 1}/{len(shared)} {key} relative={relative:.4f}")

    group_rows = []
    for group, bucket in groups.items():
        group_rows.append({"group": group, "count": bucket["count"],
                           "deltaL2": round(bucket["deltaL2"], 4),
                           "relativeMean": round(bucket["deltaL2"] / bucket["baseL2"], 6)
                           if bucket["baseL2"] else None,
                           "relativeMax": round(bucket["relativeMax"], 6)})
    group_rows.sort(key=lambda item: item["relativeMean"] or 0, reverse=True)
    top_layers = sorted(rows, key=lambda item: item["relative"], reverse=True)[:args.top_layers]

    embeddings = {}
    if "model.embed_tokens.weight" in base and "model.embed_tokens.weight" in suspect:
        from transformers import AutoTokenizer
        tokenizer = AutoTokenizer.from_pretrained(args.suspect)
        delta = (suspect["model.embed_tokens.weight"] - base["model.embed_tokens.weight"]).float()
        row_norms = delta.norm(dim=1)
        values, indices = torch.topk(row_norms, min(args.top_tokens, row_norms.numel()))
        tokens = []
        for value, token_id in zip(values.tolist(), indices.tolist()):
            tokens.append({"tokenId": token_id,
                           "text": tokenizer.decode([token_id]),
                           "deltaL2": round(value, 6)})
        embeddings = {"rows": row_norms.numel(), "top": tokens}
        log(f"[embed] top token {tokens[0] if tokens else None}")

    report = {"base": args.base, "suspect": args.suspect,
              "architectures": {"base": base_cfg.get("architectures"),
                                "suspect": suspect_cfg.get("architectures")},
              "vocab": {"base": base_cfg.get("vocab_size"), "suspect": suspect_cfg.get("vocab_size")},
              "sharedTensors": len(shared), "missingInSuspect": missing[:20],
              "extraInSuspect": extra[:20],
              "groups": group_rows, "topLayers": top_layers, "embeddings": embeddings,
              "seconds": round(time.time() - began, 1)}
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)
    log(f"[saved] {args.out}")
    log("[groups] " + json.dumps(group_rows[:6], ensure_ascii=False))
    log("[topLayers] " + json.dumps(top_layers[:5], ensure_ascii=False))


if __name__ == "__main__":
    main()