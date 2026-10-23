import {
  describe, expect, it,
} from 'vitest'

import {
  currentRevisionReport, immutableCommitOptions, reportMatchesRevision,
} from './security.revisions'

import type { SecurityReport } from '@matrixhub/api-ts/security/v1alpha1/security'

describe('immutable security revision selection', () => {
  it('uses complete SHA values and discards missing, abbreviated and duplicate IDs', () => {
    const first = 'a'.repeat(40)
    const second = 'b'.repeat(40)
    const options = immutableCommitOptions([
      {
        id: first,
        message: 'first',
      },
      { id: first },
      { id: first.slice(0, 12) },
      {},
      { id: 'main' },
      {
        id: second,
        message: 'second',
      },
    ], commit => commit.message ?? '')

    expect(options).toEqual([{
      value: first,
      label: 'first',
    }, {
      value: second,
      label: 'second',
    }])
  })

  it('withholds a report from another selected immutable revision', () => {
    const report = { revision: 'a'.repeat(40) } as SecurityReport

    expect(reportMatchesRevision(report, 'b'.repeat(40))).toBe(false)
    expect(reportMatchesRevision(report, 'a'.repeat(40))).toBe(true)
    expect(reportMatchesRevision(undefined, 'b'.repeat(40))).toBe(true)
    expect(reportMatchesRevision(report, 'main')).toBe(true)
  })
  it('hides cached evidence while a branch or commit is being checked again', () => {
    const report = {
      revision: 'a'.repeat(40),
      state: 'pass',
    } as SecurityReport

    expect(currentRevisionReport(report, 'refs/heads/main', true)).toBeUndefined()
    expect(currentRevisionReport(report, 'a'.repeat(40), true)).toBeUndefined()
    expect(currentRevisionReport(report, 'a'.repeat(40), false, true)).toBeUndefined()
    expect(currentRevisionReport(report, 'b'.repeat(40), false)).toBeUndefined()
    expect(currentRevisionReport(report, 'a'.repeat(40), false)).toBe(report)
  })
})
