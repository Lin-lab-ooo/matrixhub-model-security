// Offline Helm contract tests. Dummy rule metadata is never an engine-verification result.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import { randomUUID } from 'node:crypto'

const here = path.dirname(fileURLToPath(import.meta.url))
const source = path.resolve(here, '../..')
const require = createRequire(import.meta.url)
const yaml = require(path.join(source, 'ui/node_modules/js-yaml'))
const helm = process.argv[2]
const parent = process.argv[3]
assert(helm && parent, 'Usage: node test_helm.mjs HELM_EXECUTABLE EXISTING_G_WORK_DIRECTORY')
const work = fs.mkdtempSync(path.join(path.resolve(parent), 'helm-contract-'))
const kubeconfig = path.join(work, 'empty-kubeconfig.json')
fs.writeFileSync(kubeconfig, JSON.stringify({ apiVersion: 'v1', kind: 'Config', clusters: [], contexts: [], users: [] }))
const env = { ...process.env, HELM_CACHE_HOME: path.join(work, 'cache'), HELM_CONFIG_HOME: path.join(work, 'config'), HELM_DATA_HOME: path.join(work, 'data') }
const chart = path.join(source, 'deploy/security/helm')
const epoch = Math.floor(Date.now() / 1000)
const snapshot = 'a'.repeat(64)
const base = {
  deploymentId: 'c'.repeat(32),
  rules: { existingClaim: 'owned-rules', snapshot, expiresAt: String(epoch + 600), manifest: {
    snapshot, expiresAt: epoch + 600, maxAgeSeconds: 604800,
    files: ['main.cvd', 'daily.cvd', 'bytecode.cvd'].map(name => ({ name, size: 1024, sha256: 'b'.repeat(64), version: 1, buildEpoch: epoch - 60 })),
  } },
  database: { existingSecret: 'owned-db-secret', namespace: 'owned-db', podSelector: { app: 'owned-mysql' } },
}
let passed = 0
function render(change = () => {}, extra = []) {
  const values = structuredClone(base)
  change(values)
  const input = path.join(work, randomUUID() + '.json')
  fs.writeFileSync(input, JSON.stringify(values))
  const result = spawnSync(helm, ['template', 'mh-sec-contract', chart, '--namespace', 'owned-app', '--kubeconfig', kubeconfig, '-f', input, ...extra], { env, encoding: 'utf8', maxBuffer: 2 * 1024 * 1024, timeout: 15000 })
  return { result, documents: result.status === 0 ? yaml.loadAll(result.stdout).filter(Boolean) : [] }
}
function check(name, fn) { fn(); passed++; console.log('PASS ' + name) }
const safe = render()
assert.equal(safe.result.status, 0, safe.result.stderr)
const deployment = safe.documents.find(item => item.kind === 'Deployment')
const pod = deployment.spec.template.spec
const scanner = pod.containers.find(item => item.name === 'scanner')
const api = pod.containers.find(item => item.name === 'matrixhub')
check('one writer and recreate strategy', () => { assert.equal(deployment.spec.replicas, 1); assert.equal(deployment.spec.strategy.type, 'Recreate') })
check('non-root runtime and no API token', () => {
  assert.equal(pod.securityContext.runAsUser, 65532); assert.equal(pod.securityContext.runAsNonRoot, true); assert.equal(pod.automountServiceAccountToken, false)
  for (const item of pod.containers) { assert.equal(item.securityContext.allowPrivilegeEscalation, false); assert.equal(item.securityContext.readOnlyRootFilesystem, true); assert.deepEqual(item.securityContext.capabilities.drop, ['ALL']); assert(!item.securityContext.capabilities.add) }
  assert(!pod.hostNetwork); assert(!pod.volumes.some(item => item.hostPath))
})
check('rules and scanner staging read-only', () => {
  assert.equal(scanner.volumeMounts.find(item => item.mountPath === '/rules').readOnly, true)
  assert.equal(scanner.volumeMounts.find(item => item.mountPath === '/input').readOnly, true)
  assert(!api.volumeMounts.find(item => item.mountPath === '/input').readOnly)
  assert.equal(api.volumeMounts.find(item => item.mountPath === '/run/matrix-security').readOnly, true)
  assert.equal(pod.volumes.find(item => item.name === 'rules').persistentVolumeClaim.readOnly, true)
})
check('only deterministic owned volume init receives two capabilities', () => {
  const init = pod.initContainers.find(item => item.name === 'init-owned-volumes')
  assert.equal(init.securityContext.runAsUser, 0); assert.deepEqual(init.securityContext.capabilities.add, ['CHOWN', 'FOWNER'])
  assert.deepEqual(init.volumeMounts.map(item => item.name).sort(), ['data', 'socket', 'staging'])
  assert(!init.args.join(' ').includes('777'))
  const verify = pod.initContainers.find(item => item.name === 'verify-rules'); assert(verify); assert.deepEqual(verify.securityContext.capabilities.drop, ['ALL'])
})
check('Secret content stays outside the chart and scanner', () => {
  assert(!safe.documents.some(item => item.kind === 'Secret'))
  assert.equal(api.env.find(item => item.name === 'MATRIXHUB_DATABASE_DSN').valueFrom.secretKeyRef.name, 'owned-db-secret')
  assert(!scanner.env.some(item => item.valueFrom || /PASSWORD|TOKEN|DSN/.test(item.name)))
})
check('egress selectors never allow arbitrary namespaces or addresses', () => {
  const policy = safe.documents.find(item => item.kind === 'NetworkPolicy')
  assert.deepEqual(policy.spec.policyTypes, ['Egress']); assert.equal(policy.spec.egress.length, 2)
  for (const rule of policy.spec.egress) for (const peer of rule.to) { assert(Object.keys(peer.namespaceSelector.matchLabels).length); assert(Object.keys(peer.podSelector.matchLabels).length); assert(!peer.ipBlock) }
})
check('replica expansion rejected', () => assert.notEqual(render(value => { value.replicaCount = 2 }).result.status, 0))
check('expired and excessive future expiry rejected', () => {
  for (const expiry of [epoch - 10, epoch + 604900]) assert.notEqual(render(value => { value.rules.expiresAt = String(expiry); value.rules.manifest.expiresAt = expiry }).result.status, 0)
})
check('parallelism and CPU mismatch rejected', () => {
  assert.notEqual(render(value => { value.security = { concurrency: 4 }; value.scanner = { nativeThreads: 2, resources: { limits: { cpu: '2' } } } }).result.status, 0)
  assert.notEqual(render(value => { value.scanner = { nativeThreads: 2 } }).result.status, 0)
  assert.equal(render(value => { value.scanner = { nativeThreads: 2, resources: { limits: { cpu: '2' } } } }).result.status, 0)
})
check('managed rule/backend/thread environment cannot be overridden', () => {
  for (const key of ['SCAN_RULES_EXPIRES_AT', 'SCAN_CLAMAV_BACKEND', 'SCAN_NATIVE_THREADS']) assert.notEqual(render(value => { value.scanner = { environment: { [key]: 'unsafe' } } }).result.status, 0)
})
check('missing database selector, Secret and rules claim rejected', () => {
  for (const mutate of [value => { value.database.podSelector = {} }, value => { value.database.existingSecret = '' }, value => { value.rules.existingClaim = '' }]) assert.notEqual(render(mutate).result.status, 0)
})
check('manifest identity and expiry mismatch rejected', () => {
  assert.notEqual(render(value => { value.rules.manifest.snapshot = 'd'.repeat(64) }).result.status, 0)
  assert.notEqual(render(value => { value.rules.manifest.expiresAt-- }).result.status, 0)
})
check('large repository profile preserves per-file and expanded limits', () => {
  const output = render(() => {}, ['-f', path.join(source, 'deploy/security/profiles/helm.large-repository.yaml')])
  assert.equal(output.result.status, 0, output.result.stderr)
  const config = yaml.load(output.documents.find(item => item.kind === 'ConfigMap').data['config.yaml'])
  assert.equal(config.security.maxTaskBytes, 110 * 1024 ** 3); assert.equal(config.security.maxStagingBytes, 120 * 1024 ** 3)
  assert.equal(config.security.maxFileBytes, 1280 * 1024 ** 2); assert.equal(config.security.batchBytes, 5 * 1024 ** 3)
  assert.equal(config.security.concurrency, 1)
  const item = output.documents.find(item => item.kind === 'Deployment').spec.template.spec.containers.find(item => item.name === 'scanner')
  assert.equal(item.env.find(entry => entry.name === 'SCAN_MAX_EXPANDED_BYTES').value, '134217728')
})
const lintValues = path.join(work, 'safe-lint.json'); fs.writeFileSync(lintValues, JSON.stringify(base))
const lintSafe = spawnSync(helm, ['lint', chart, '-f', lintValues, '--kubeconfig', kubeconfig], { env, encoding: 'utf8', maxBuffer: 1024 * 1024, timeout: 15000 })
check('helm lint passes with prepared public values', () => assert.equal(lintSafe.status, 0, lintSafe.stderr + lintSafe.stdout))
fs.writeFileSync(path.join(work, 'receipt.json'), JSON.stringify({ status: 'STATIC_ONLY_PASS', tests: passed, renderedKinds: safe.documents.map(item => item.kind), engineVerification: 'NOT_EXECUTED', clusterAcceptance: 'NOT_EXECUTED' }, null, 2) + '\n')
console.log(JSON.stringify({ status: 'STATIC_ONLY_PASS', tests: passed, work }))
