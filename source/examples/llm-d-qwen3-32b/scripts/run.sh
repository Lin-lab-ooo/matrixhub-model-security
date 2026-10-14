#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"

mode="${1:-}"
case "$mode" in
  direct)
    overlay="${EXAMPLE_ROOT}/overlays/direct"
    ;;
  matrixhub)
    overlay="${EXAMPLE_ROOT}/overlays/matrixhub"
    ;;
  *)
    die "usage: $0 direct|matrixhub"
    ;;
esac

preflight_cluster
require_command python3
require_command curl

namespace="$LLMD_NAMESPACE"

run_id="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${ARTIFACTS_DIR}/${mode}/${run_id}"
mkdir -p "$run_dir"
port_forward_pid=""

collect_on_failure() {
  local status="$?"
  trap - EXIT
  if [[ -n "$port_forward_pid" ]]; then
    kill "$port_forward_pid" >/dev/null 2>&1 || true
    wait "$port_forward_pid" 2>/dev/null || true
  fi
  if (( status != 0 )); then
    if is_experiment_namespace "$namespace"; then
      collect_diagnostics "$namespace" "$run_dir"
      printf 'Run failed; diagnostics were saved in %s. The Router namespace was retained; run make cleanup when finished.\n' \
        "$run_dir" >&2
    else
      printf 'Run failed before the Router prerequisite could be verified.\n' >&2
    fi
  fi
  exit "$status"
}

require_router_prerequisite "$namespace"
trap collect_on_failure EXIT
remove_model_workload "$namespace"

if [[ "$mode" == matrixhub ]]; then
  kubectl create configmap matrixhub-hf-endpoint \
    -n "$namespace" \
    --from-literal="HF_ENDPOINT=${MATRIXHUB_ENDPOINT}" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
fi

rendered_manifest="${run_dir}/rendered.yaml"
if [[ -n "$MODEL_NODE_SELECTOR" ]]; then
  node_selector_overlay_dir="${run_dir}/node-selector-overlay"
  mkdir -p "$node_selector_overlay_dir"
  cat >"${node_selector_overlay_dir}/kustomization.yaml" <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../../../../overlays/${mode}
patches:
  - path: node-selector.yaml
EOF
  cat >"${node_selector_overlay_dir}/node-selector.yaml" <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${MODEL_DEPLOYMENT}
spec:
  template:
    spec:
      nodeSelector:
        kubernetes.io/hostname: ${MODEL_NODE_SELECTOR}
EOF
  kubectl kustomize "$node_selector_overlay_dir" >"$rendered_manifest"
else
  kubectl kustomize "$overlay" >"$rendered_manifest"
fi

cat >"${run_dir}/run-metadata.md" <<EOF
| Field | Value |
|---|---|
| Mode | ${mode} |
| Namespace | ${namespace} |
| Model | ${MODEL_ID} |
| llm-d router service | ${ROUTER_SERVICE} |
| llm-d router chart | ${LLMD_ROUTER_CHART}@${LLMD_ROUTER_CHART_VERSION} |
| Model node selector | ${MODEL_NODE_SELECTOR:-not set} |
| Model source endpoint | $([[ "$mode" == matrixhub ]] && printf '%s' "$MATRIXHUB_ENDPOINT" || printf '%s' 'https://hf.m.daocloud.io') |
| MatrixHub endpoint | $([[ "$mode" == matrixhub ]] && printf '%s' "$MATRIXHUB_ENDPOINT" || printf 'not used') |
EOF

started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
started_epoch="$(date +%s)"
printf '%s\n' "$started_at" >"${run_dir}/started-at.txt"

kubectl apply -n "$namespace" -f "$rendered_manifest" >"${run_dir}/apply.txt"

if ! kubectl rollout status deployment/"$MODEL_DEPLOYMENT" \
  -n "$namespace" --timeout=90m | tee "${run_dir}/rollout.txt"; then
  die "model server did not become ready; diagnostics saved in ${run_dir}"
fi

completed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
completed_epoch="$(date +%s)"
pod="$(model_pod "$namespace")"

pod_created_at="$(kubectl get pod "$pod" -n "$namespace" -o jsonpath='{.metadata.creationTimestamp}')"
container_started_at="$(kubectl get pod "$pod" -n "$namespace" -o jsonpath='{.status.containerStatuses[?(@.name=="modelserver")].state.running.startedAt}')"
pod_ready_at="$(kubectl get pod "$pod" -n "$namespace" -o jsonpath='{.status.conditions[?(@.type=="Ready")].lastTransitionTime}')"

pod_created_seconds="$(( $(iso_to_epoch "$pod_created_at") - started_epoch ))"
container_started_epoch="$(iso_to_epoch "$container_started_at")"
pod_ready_epoch="$(iso_to_epoch "$pod_ready_at")"
pod_ready_seconds="$(( pod_ready_epoch - started_epoch ))"
model_load_seconds="$(( pod_ready_epoch - container_started_epoch ))"
rollout_seconds="$(( completed_epoch - started_epoch ))"

cat >"${run_dir}/metrics.md" <<EOF
| Field | Value |
|---|---:|
| Mode | ${mode} |
| Experiment started | ${started_at} |
| Pod created | ${pod_created_at} |
| Container started | ${container_started_at} |
| Pod ready | ${pod_ready_at} |
| Rollout completed | ${completed_at} |
| Time to Pod creation | ${pod_created_seconds} s |
| Time to Pod Ready | ${pod_ready_seconds} s |
| Container start to Pod Ready | ${model_load_seconds} s |
| Total rollout time | ${rollout_seconds} s |
EOF

kubectl logs "$pod" -n "$namespace" >"${run_dir}/modelserver.log"
kubectl get pod "$pod" -n "$namespace" -o yaml >"${run_dir}/pod.yaml"

if [[ "$mode" == matrixhub ]]; then
  kubectl logs deployment/"$MATRIXHUB_DEPLOYMENT" \
    -n "$MATRIXHUB_NAMESPACE" --since-time="$started_at" \
    --all-pods=true --max-log-requests=20 \
    >"${run_dir}/matrixhub.log" 2>&1 || \
    printf 'warning: unable to collect MatrixHub logs\n' >&2
fi

inference_file="${run_dir}/inference.json"
local_port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
kubectl port-forward -n "$namespace" service/"$ROUTER_SERVICE" \
  "${local_port}:80" >"${run_dir}/port-forward.log" 2>&1 &
port_forward_pid="$!"

for _ in {1..30}; do
  if curl --fail --silent "http://127.0.0.1:${local_port}/health" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

curl --fail-with-body --silent --show-error \
  "http://127.0.0.1:${local_port}/v1/chat/completions" \
  -H 'Content-Type: application/json' \
  -d "{\"model\":\"${MODEL_ID}\",\"messages\":[{\"role\":\"user\",\"content\":\"Reply with exactly: MatrixHub experiment ready\"}],\"temperature\":0,\"max_tokens\":32}" \
  | tee "$inference_file"

grep -q 'choices' "$inference_file" || die "inference response does not contain choices"
printf '| Inference verification | passed |\n' >>"${run_dir}/metrics.md"
collect_diagnostics "$namespace" "$run_dir"

printf '\n%s run completed. Copy the values from %s into results.md.\n' "$mode" "${run_dir}/metrics.md"
