# llm-d Qwen3-32B model-loading experiment results

## Environment

| Field | Value |
|---|---|
| Date | — |
| Kubernetes version | — |
| Cluster / cloud | — |
| GPU model | — |
| NVIDIA driver | — |
| GPU operator / device plugin version | — |
| Node CPU and memory | — |
| Storage class and medium | — |
| MatrixHub version | — |
| MatrixHub storage backend | — |
| MatrixHub-to-node network | — |
| Hugging Face-to-node network | — |

## Cache preparation

| Field | Value |
|---|---|
| How `Qwen/Qwen3-32B` was cached | — |
| How cache completeness was verified | — |
| Cache preparation completed at | — |

## Measurements

Add one row per run. Use a new namespace and an empty Pod-local cache for every row.
Download speed is computed as 62 GB ÷ weight-download duration reported by vLLM.

| Source | Run | Pod created (s) | Container start to Ready (s) | Pod Ready (s) | Rollout completed (s) | Download (s) | Download speed (MB/s) | Inference passed | Notes |
|---|---:|---:|---:|---:|---:|---:|---:|---|---|
| Hugging Face direct | 1 | 1 | 740 | 725 | 747 | 517.6 | 119.8 | ✓ | |
| Hugging Face direct | 2 | — | — | — | — | — | — | — | — |
| Hugging Face direct | 3 | — | — | — | — | — | — | — | — |
| MatrixHub cache hit | 1 | 1 | 388 | 376 | 400 | 142.8 | 434.1 | ✓ | |
| MatrixHub cache hit | 2 | — | — | — | — | — | — | — | — |
| MatrixHub cache hit | 3 | — | — | — | — | — | — | — | — |

## Summary

| Metric | Hugging Face direct | MatrixHub cache hit | Difference |
|---|---:|---:|---:|
| Median container-start-to-Ready | 740 s | 388 s | −352 s |
| Median time to Pod Ready | 725 s | 376 s | −349 s |
| Median total rollout time | 747 s | 400 s | −347 s |
| Minimum total rollout time | 747 s | 400 s | — |
| Maximum total rollout time | 747 s | 400 s | — |
| Median download speed | 119.8 MB/s | 434.1 MB/s | +314.3 MB/s |

## Evidence

- Direct-run model server log: —
- MatrixHub-run model server log: —
- MatrixHub cache-hit log evidence: —
- Rendered manifest or commit: —
- Raw artifacts location: —

## Observations

—

## Conclusion

—

## Validity notes

Document image pulls, scheduling delays, retries, throttling, other cluster load, or any difference between the two scenarios that may affect the comparison.

—
