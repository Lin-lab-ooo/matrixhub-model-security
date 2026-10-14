/**
 * Hand-written typed client for the security REST API.
 * Contract: api/security/v1alpha1/openapi.yaml. This is not a generated .pb.ts
 * file. The existing SDK fetch source provides global headers and error bodies.
 */
import { fetchReq } from '../../fetch.pb'

import type { InitReq } from '../../fetch.pb'

export type SecurityState = 'pending' | 'scanning' | 'pass' | 'warn' | 'block' | 'fail'
export type Severity = 'low' | 'medium' | 'high' | 'critical'
export type PolicyMode = 'enforce' | 'audit'

export interface ModelScope {
  namespace: string
  name: string
}

export interface Finding {
  engine: string
  rule: string
  severity: Severity
  message: string
  remediation: string
  /** Required for pickle.nested-deserialization-reference; omitted by legacy rules. */
  evidence?: FindingEvidence
}

/** Static reference evidence, not proof of invocation or malicious execution. */
export interface FindingEvidence {
  knownSymbolId: 'torch-storage-load-from-bytes-v1'
  observation: 'reference'
  source: 'pickletools' | 'picklescan'
  archiveMemberChain: ArchiveMemberEvidence[] | null
  streamIndex: number | null
  opcodeOffset: number | null
}

export interface ArchiveMemberEvidence {
  memberIndex: number
  nameSha256: string
}

export interface FileReport {
  path: string
  blobId: string
  lfsOid?: string
  declaredSize: number
  artifactId: string
  sha256: string
  size: number
  type: string
  generation: string
  complete: boolean
  findings: Finding[] | null
  engines: Record<string, string> | null
  durationMs: number
  cached: boolean
}

export interface SecurityReport {
  reportId: string
  attempt: number
  taskId: number
  repo: string
  revision: string
  generation: string
  state: SecurityState
  complete: boolean
  expectedFiles: number
  files: FileReport[] | null
  error?: string
  createdAt: string
  finishedAt: string
  durationMs: number
  scannedBytes: number
  cachedFiles: number
}

export interface SecurityTask {
  id: number
  repo: string
  revision: string
  generation: string
  state: SecurityState
  trigger: string
  force: boolean
  attempt: number
  leaseUntil: string
  createdAt: string
  updatedAt: string
  error?: string
}

export interface SecurityPolicy {
  repo: string
  mode: PolicyMode
  blockSeverity: Severity
  version: number
  updatedAt: string
}

export interface Decision {
  reportId: string
  allowed: boolean
  code: string
  message: string
  repo: string
  revision: string
  path: string
  sha256: string
  size: number
  taskId: number
  generation: string
  policyVersion: number
}

export interface SecurityAudit {
  id: number
  repo: string
  revision: string
  actor: string
  action: string
  entry: string
  path?: string
  decision?: Decision
  review?: SecurityReview
  createdAt: string
}

export type ReviewVerdict = 'confirmed_risk' | 'false_positive' | 'needs_followup'

/** Append-only human annotation; it never changes machine admission. */
export interface SecurityReview {
  id: number
  repo: string
  reportId: string
  revision: string
  generation: string
  actor: string
  actorId: number
  verdict: ReviewVerdict
  comment: string
  createdAt: string
}

export interface ReviewInput {
  revision: string
  generation: string
  verdict: ReviewVerdict
  comment: string
}

export interface SecurityList<T> {
  items: T[]
  count: number
  limit: number
  offset: number
  hasMore: boolean
}

export interface PaginationInput {
  limit?: number
  offset?: number
}

export interface PolicyInput {
  mode: PolicyMode
  blockSeverity: Severity
}

function modelPath(scope: ModelScope) {
  return `/api/security/v1alpha1/models/${encodeURIComponent(scope.namespace)}/${encodeURIComponent(scope.name)}`
}

function listQuery(input: PaginationInput) {
  const params = new URLSearchParams()

  if (input.limit !== undefined) {
    params.set('limit', String(input.limit))
  }
  if (input.offset !== undefined) {
    params.set('offset', String(input.offset))
  }

  return params.size ? `?${params.toString()}` : ''
}

function jsonInit(method: string, body: unknown, init?: InitReq): InitReq {
  const headers = new Headers(init?.headers)

  headers.set('Content-Type', 'application/json')

  return {
    ...init,
    method,
    headers,
    body: JSON.stringify(body),
  }
}

export const Security = {
  Report(input: ModelScope & { revision?: string }, init?: InitReq) {
    const revision = encodeURIComponent(input.revision ?? 'main')

    return fetchReq<unknown, SecurityReport>(`${modelPath(input)}/report?revision=${revision}`, {
      ...init,
      method: 'GET',
    })
  },
  History(input: ModelScope & { reportId: string }, init?: InitReq) {
    return fetchReq<unknown, SecurityReport>(`${modelPath(input)}/history/${encodeURIComponent(input.reportId)}`, {
      ...init,
      method: 'GET',
    })
  },
  Reviews(input: ModelScope & { reportId: string } & PaginationInput, init?: InitReq) {
    return fetchReq<unknown, SecurityList<SecurityReview>>(`${modelPath(input)}/history/${encodeURIComponent(input.reportId)}/reviews${listQuery(input)}`, {
      ...init,
      method: 'GET',
    })
  },
  AddReview(input: ModelScope & { reportId: string } & ReviewInput, init?: InitReq) {
    return fetchReq<unknown, SecurityReview>(`${modelPath(input)}/history/${encodeURIComponent(input.reportId)}/reviews`, jsonInit('POST', {
      revision: input.revision,
      generation: input.generation,
      verdict: input.verdict,
      comment: input.comment,
    }, init))
  },
  Tasks(input: ModelScope & PaginationInput, init?: InitReq) {
    return fetchReq<unknown, SecurityList<SecurityTask>>(`${modelPath(input)}/tasks${listQuery(input)}`, {
      ...init,
      method: 'GET',
    })
  },
  Audits(input: ModelScope & PaginationInput, init?: InitReq) {
    return fetchReq<unknown, SecurityList<SecurityAudit>>(`${modelPath(input)}/audits${listQuery(input)}`, {
      ...init,
      method: 'GET',
    })
  },
  Rescan(input: ModelScope & { revision: string }, init?: InitReq) {
    return fetchReq<unknown, SecurityTask>(`${modelPath(input)}/rescan`, jsonInit('POST', { revision: input.revision }, init))
  },
  Cancel(input: ModelScope & { taskId: number }, init?: InitReq) {
    return fetchReq<unknown, { id: number
      canceled: boolean }>(`${modelPath(input)}/tasks/${input.taskId}/cancel`, {
      ...init,
      method: 'POST',
    })
  },
  Policy(input: ModelScope, init?: InitReq) {
    return fetchReq<unknown, SecurityPolicy>(`${modelPath(input)}/policy`, {
      ...init,
      method: 'GET',
    })
  },
  UpdatePolicy(input: ModelScope & PolicyInput, init?: InitReq) {
    return fetchReq<unknown, SecurityPolicy>(`${modelPath(input)}/policy`, jsonInit('PUT', {
      mode: input.mode,
      blockSeverity: input.blockSeverity,
    }, init))
  },
}
