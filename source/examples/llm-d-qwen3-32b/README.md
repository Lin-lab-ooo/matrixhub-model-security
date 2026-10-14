# llm-d Qwen3-32B model-loading experiment

This example measures the time required for an llm-d model server to become ready when loading `Qwen/Qwen3-32B` from:

1. a Hugging Face-compatible direct endpoint; and
2. an existing MatrixHub instance with a populated model cache.

The direct scenario uses the HF-compatible DaoCloud endpoint `https://hf.m.daocloud.io`, because the experiment environment cannot resolve `huggingface.co` directly.

Before the experiment, prepare one llm-d Router in standalone mode. Follow the [llm-d standalone-mode quickstart](https://llm-d.ai/docs/dev/getting-started/quickstart), then use `make prepare-router` to install the pinned chart values used by this example. The Router chart creates an Envoy proxy, an Endpoint Picker (EPP), and an `InferencePool` that discovers the model server Pod through its llm-d labels. Both scenarios reuse this shared llm-d infrastructure. Router installation and readiness are a separate prerequisite, never part of the measured model-loading runs. The verification request traverses Envoy and EPP rather than calling the model server Service directly.

## What is fixed

| Setting | Value |
|---|---|
| llm-d source | commit `7029aac48505752dd51344ce552acc81b0deb774` |
| Router chart | `llm-d-router-standalone` `v0.9.0` |
| llm-d manifest | `guides/optimized-baseline/modelserver/gpu/vllm/base` |
| Model | `Qwen/Qwen3-32B` |
| Model server image | `m.daocloud.io/docker.io/vllm/vllm-openai:v0.22.0-cu129` |
| Direct model endpoint | `https://hf.m.daocloud.io` |
| Replicas | 1 |
| Tensor parallelism | 4 |
| GPUs per Pod | 4 |
| Model server Service | `qwen3-32b:8000` (backend discovery only) |
| Request Service | `${LLMD_ROUTER_RELEASE}-epp:80` |

The request path is `client -> standalone Envoy -> EPP -> vLLM Pod`. This example uses one model server replica to control GPU use, so it validates the complete llm-d request path but does not measure EPP's replica-selection benefit. Use two or more replicas to evaluate prefix-aware or load-aware routing.

Tensor parallelism does not split the download between Pods. There is one Pod with four GPUs; the model files are downloaded into that Pod's cache, and vLLM partitions the loaded model across the four GPUs.

## Prerequisites

- A Kubernetes cluster with at least four schedulable NVIDIA GPUs on one node
- A working NVIDIA device plugin and sufficient node memory and storage for Qwen3-32B
- `kubectl`, `helm`, `make`, Bash, Python 3, and `curl` on the client machine
- Gateway API Inference Extension (GAIE) CRDs installed by a cluster administrator; the Router chart requires the `InferencePool` API
- Network access from the cluster to Hugging Face for the direct run
- A running MatrixHub instance reachable from model server Pods for the cached run

Run both scenarios on the same cluster, node class, storage class, and network path. Do not run unrelated GPU or high-I/O workloads during the measurements.

Verify the required API before running the example:

```bash
kubectl get crd inferencepools.inference.networking.k8s.io
```

If it is missing, install the GAIE CRDs using the version and artifact source approved for your cluster. The llm-d revision pinned by this example uses GAIE `v1.5.0`. This example omits the optional `InferencePool.spec.appProtocol` field, so it also works with older GAIE v1 schemas; HTTP is the EPP default.

## Configure the experiment

From the repository root:

```bash
cd examples/llm-d-qwen3-32b
cp env.example env.sh
```

Open `env.sh` and update it for your environment:

```bash
MATRIXHUB_ENDPOINT="http://10.0.0.20:9527"
MATRIXHUB_NAMESPACE="matrixhub"
MATRIXHUB_DEPLOYMENT="matrixhub"
LLMD_NAMESPACE="matrixhub-llmd-qwen3-32b"
MODEL_NODE_SELECTOR="gpu-10-125-1-4"
LLMD_ROUTER_CHART="oci://ghcr.io/llm-d/charts/llm-d-router-standalone"
LLMD_ROUTER_CHART_VERSION="v0.9.0"
LLMD_ROUTER_RELEASE="optimized-baseline"
```

| Variable | What to enter |
|---|---|
| `MATRIXHUB_ENDPOINT` | A MatrixHub IP address and port reachable from the llm-d model server Pod. Replace `10.0.0.20` with the actual address. Do not use `127.0.0.1` unless MatrixHub runs inside the same Pod. |
| `MATRIXHUB_NAMESPACE` | The Kubernetes namespace containing the existing MatrixHub deployment. |
| `MATRIXHUB_DEPLOYMENT` | The existing MatrixHub Deployment name. It is used only for best-effort log collection. |
| `LLMD_NAMESPACE` | A dedicated namespace for the shared Router and both sequential model-server runs. |
| `MODEL_NODE_SELECTOR` | Optional node name. The runner adds `kubernetes.io/hostname=<value>` to the model-server Pod before deployment. Leave empty to let Kubernetes schedule normally. |
| `LLMD_ROUTER_CHART` | The standalone Router OCI chart. Set a registry-mirror address if `ghcr.io` is not reachable. |
| `LLMD_ROUTER_CHART_VERSION` | The chart version. Keep the pinned `v0.9.0` for this example. |
| `LLMD_ROUTER_RELEASE` | Helm release name. The Router Service is `${LLMD_ROUTER_RELEASE}-epp`. |

`LLMD_NAMESPACE` must not equal `MATRIXHUB_NAMESPACE`. `make prepare-router` creates and labels it; it may safely be re-run only for a namespace already carrying this example's ownership label. Before every scenario, the runner removes the previous model-server workload but keeps Router, then deploys a new Pod with an empty `emptyDir` cache. This prevents a prior Pod-local cache from affecting the next measurement and protects the existing MatrixHub deployment from cleanup.

Check cluster access and render both manifests before using GPUs:

```bash
make check
make render
```

Rendered manifests are saved under `artifacts/`. Confirm that they request the expected GPU and memory resources for your cluster.

## Prepare shared llm-d infrastructure

```bash
make prepare-router
```

This one-time prerequisite creates `LLMD_NAMESPACE`, installs the standalone Router, and waits for it to become ready. The Router, Envoy, EPP, and `InferencePool` remain in this namespace for both scenarios. This command is outside the experiment and never contributes to the reported timings.

## Run the direct-download scenario

```bash
make run-direct
```

`make run-direct` verifies the shared Router prerequisite, removes any earlier model-server workload, and sets `HF_ENDPOINT=https://hf.m.daocloud.io`. The model-loading timer starts only when it applies the direct model-server manifest. The final chat-completions request is sent through the EPP Service, and timestamps, logs, Helm status, and manifests are saved under a timestamped directory in `artifacts/direct/`.

Do not run `make cleanup-router` between scenarios: it removes the shared Router. `make run-matrixhub` removes the direct model server itself before it starts the next measurement.

## Prepare MatrixHub for the cache-hit scenario

Before measuring MatrixHub, make sure `Qwen/Qwen3-32B` is completely cached in MatrixHub. Populate it with your normal MatrixHub workflow or download the full model once through the MatrixHub `HF_ENDPOINT`. Do not use the first cache-filling request as the cache-hit measurement.

Record how the cache was populated and how you confirmed completion in `results.md`. Also verify that `MATRIXHUB_ENDPOINT` in `env.sh` is reachable from the Kubernetes cluster.

## Run the MatrixHub cache-hit scenario

```bash
make run-matrixhub
```

This deployment is identical to the direct scenario except for `HF_ENDPOINT`, which points to MatrixHub. The runner first removes the earlier direct model-server workload, preserving the shared Router, then starts the MatrixHub model-loading measurement. The verification request again uses the EPP Service. Results are saved under a timestamped directory in `artifacts/matrixhub/`; MatrixHub logs are collected on a best-effort basis.

No access token is required for either model download path. If a run fails, the Router namespace is retained for diagnosis; run `make cleanup` when finished.

## Record and interpret results

Create a report without committing local measurements by default:

```bash
cp results.template.md results.md
```

Copy values from each scenario's `metrics.md` into `results.md`. Compare container-start-to-Ready, time to Pod Ready, and total rollout time. Use model server and MatrixHub logs to confirm that the intended source was used; timing alone does not prove a cache hit.

The first run of an image on a node may include container image pulling. Either pre-pull the image for both scenarios or record image-pull effects explicitly. Repeat each scenario enough times to report variability, using a new experiment namespace for every run.

## Clean up

Remove only the model-server workload, its ServiceAccount, and endpoint ConfigMap while retaining the shared Router:

```bash
make cleanup
```

Remove the complete experimental environment, including the Router, Envoy, EPP, InferencePool, and experiment namespace:

```bash
make cleanup-router
```

Both cleanup targets operate only on a namespace carrying this experiment's ownership label. Neither deletes the cluster-wide GAIE CRDs or unrelated resources. Local artifacts remain available for analysis.
