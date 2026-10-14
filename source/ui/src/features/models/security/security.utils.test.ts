import {
  describe, expect, it,
} from 'vitest'

import { hasCompleteCoverage, visibleReportState } from './security.utils'

import type { SecurityReport } from '@matrixhub/api-ts/security/v1alpha1/security'

function completedReport(): SecurityReport {
  return {
    reportId: '12-2',
    attempt: 2,
    taskId: 12,
    repo: 'models/example',
    revision: 'a'.repeat(40),
    generation: 'scanner-v1',
    state: 'pass',
    complete: true,
    expectedFiles: 1,
    files: [{
      path: 'weights.safetensors',
      blobId: 'b'.repeat(40),
      declaredSize: 1024,
      artifactId: 'artifact-1',
      sha256: 'c'.repeat(64),
      size: 1024,
      type: 'safetensors',
      generation: 'scanner-v1',
      complete: true,
      findings: [],
      engines: {
        clamav: 'clean',
        picklescan: 'not-applicable',
      },
      durationMs: 2,
      cached: false,
    }],
    createdAt: '2026-10-08T00:00:00Z',
    finishedAt: '2026-10-08T00:00:01Z',
    durationMs: 1000,
    scannedBytes: 1024,
    cachedFiles: 0,
  }
}

describe('security report presentation', () => {
  it('shows completed evidence only after resolving a commit and the complete manifest', () => {
    const report = completedReport()

    expect(hasCompleteCoverage(report)).toBe(true)
    expect(visibleReportState(report, false)).toBe('pass')
    expect(visibleReportState({
      ...report,
      revision: 'main',
    }, false)).toBe('fail')
    expect(visibleReportState({
      ...report,
      files: [],
    }, false)).toBe('fail')
    expect(visibleReportState({
      ...report,
      expectedFiles: 2,
    }, false)).toBe('fail')
  })

  it('withholds a previous pass while checking a moving revision again', () => {
    expect(visibleReportState(completedReport(), true)).toBe('scanning')
    expect(visibleReportState(undefined, false)).toBe('pending')
  })

  it('rejects mixed generations, missing digests, and partial engine evidence', () => {
    const report = completedReport()
    const file = report.files?.[0]

    if (!file) {
      throw new Error('Missing fixture evidence')
    }

    for (const changed of [
      {
        ...file,
        generation: 'old-scanner',
      },
      {
        ...file,
        sha256: '',
      },
      {
        ...file,
        complete: false,
      },
      {
        ...file,
        size: 2048,
      },
      {
        ...file,
        engines: { clamav: 'clean' },
      },
    ]) {
      expect(visibleReportState({
        ...report,
        files: [changed],
      }, false)).toBe('fail')
    }
  })

  it('does not accept a mutable or absent historical report identity', () => {
    const report = completedReport()

    expect(visibleReportState({
      ...report,
      reportId: '',
    }, false)).toBe('fail')
    expect(visibleReportState({
      ...report,
      reportId: '12-latest',
    }, false)).toBe('fail')
    expect(visibleReportState({
      ...report,
      reportId: '13-2',
    }, false)).toBe('fail')
  })
})
