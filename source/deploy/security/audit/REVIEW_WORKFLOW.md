# Review workflow and error-cost analysis

The audit returns one of three states. The cost model below makes the trade-off
explicit so thresholds are a policy decision, not a hidden constant.

## States

| verdict | decision | what happens | who |
|---|---|---|---|
| `high` | `deny` + quarantine marker | download returns 403; publisher notified with evidence | automated |
| `medium` | `review` | queued for a human; download blocked until decided | reviewer, SLA 1 business day |
| `low` | `allow` | report stored with the revision | automated |

`schema`, `auditVersion`, `modelSignature`, thresholds and evidence travel with
the report, so a review is reproducible.

## Error costs

Let `c_fp` be the cost of blocking a legitimate model (publisher escalation,
false accusation, lost trust) and `c_fn` the cost of serving a backdoored model
(incident response, reputation, regulatory exposure). With TPR `t` and FPR `f`
at a chosen threshold, the expected cost per published model is:

```
E[cost] = (1 - t) * c_fn + f * c_fp
```

Example (per 1,000 models, c_fp = 1 unit, c_fn = 20 units):

| operating point | TPR | FPR | expected cost per 1,000 |
|---|---|---|---|
| permissive (high only on rate >= 0.8) | 0.6 | 0.01 | 8,000 + 10 = **8,010** |
| balanced (rate >= 0.5) | 0.9 | 0.03 | 2,000 + 30 = **2,030** |
| strict (rate >= 0.2) | 1.0 | 0.12 | 0 + 120 = **120** |

The table shows why "strict" wins when a backdoor is 20x more expensive than a
false alarm — but only if the review queue can absorb 120 holds per 1,000
models. The gate therefore exposes both the threshold and the expected review
load, and a deployment can pick its own `c_fn / c_fp` ratio.

## Reviewer checklist

1. Read `evidence`; confirm the trigger family and the clean control (`cleanRate`).
2. Check `stages.diff.groups`: does the drift match the model card (e.g. LoRA on
   `q_proj`/`v_proj`)?
3. Re-run the audit with `--cache-dir` to confirm determinism.
4. Approve -> rewrite the marker with `decision: allow`, `reviewedBy`, `note`.
   Reject -> keep `deny` and attach the reviewer note.

## What this does NOT cover

* Adaptive attackers who regularise the drift or delay the trigger;
* semantic triggers that need world knowledge;
* multi-turn or agentic behaviour.

Those are recorded in `EVIDENCE.md` as open limitations rather than silently
assumed away.