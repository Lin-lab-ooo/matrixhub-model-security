import {
  describe, expect, it,
} from 'vitest'

import {
  archiveMemberDisplayRows, findingDisplayRows, knownReferenceEvidence,
} from './security.evidence'

import type { Finding } from '@matrixhub/api-ts/security/v1alpha1/security'

function referenceFinding(): Finding & { evidence: NonNullable<Finding['evidence']> } {
  return {
    engine: 'picklescan',
    rule: 'pickle.restricted-loader-reference',
    severity: 'high',
    message: 'Restricted static reference',
    remediation: '',
    evidence: {
      knownSymbolId: 'torch-storage-load-from-bytes-v1',
      observation: 'reference',
      source: 'pickletools',
      archiveMemberChain: [],
      streamIndex: 0,
      opcodeOffset: 0,
    },
  }
}

describe('structured reference evidence presentation', () => {
  it('preserves exact zero positions and distinguishes the root artifact from an unknown member chain', () => {
    const finding = referenceFinding()

    expect(knownReferenceEvidence(finding)).toEqual({
      symbol: 'torch.storage._load_from_bytes',
      source: 'pickletools',
      streamIndex: 0,
      opcodeOffset: 0,
      archiveMemberChain: [],
    })
    expect(knownReferenceEvidence({
      ...finding,
      evidence: {
        ...finding.evidence,
        source: 'picklescan',
        archiveMemberChain: null,
        streamIndex: null,
        opcodeOffset: null,
      },
    })).toMatchObject({
      source: 'picklescan',
      archiveMemberChain: null,
      streamIndex: null,
      opcodeOffset: null,
    })
  })

  it('keeps legacy findings compatible and never maps an unsupported symbol or observation', () => {
    const finding = referenceFinding()

    expect(knownReferenceEvidence({
      ...finding,
      evidence: undefined,
    })).toBeNull()
    for (const evidence of [
      {
        ...finding.evidence,
        knownSymbolId: '<script>untrusted.symbol</script>',
      },
      {
        ...finding.evidence,
        observation: 'executed',
      },
      {
        ...finding.evidence,
        source: 'model-provided-engine',
      },
    ]) {
      expect(knownReferenceEvidence({
        ...finding,
        evidence,
      } as Finding)).toBeNull()
    }
  })

  it('rejects malformed locations rather than displaying them as known evidence', () => {
    const finding = referenceFinding()

    for (const evidence of [
      {
        ...finding.evidence,
        streamIndex: -1,
        opcodeOffset: 1.5,
      },
      {
        ...finding.evidence,
        streamIndex: Number.NaN,
        opcodeOffset: Number.MAX_SAFE_INTEGER + 1,
      },
    ]) {
      expect(knownReferenceEvidence({
        ...finding,
        evidence,
      })).toMatchObject({
        streamIndex: null,
        opcodeOffset: null,
      })
    }
    for (const archiveMemberChain of [
      [{
        memberIndex: 0,
        nameSha256: '<img src=x onerror=alert(1)>',
      }],
      [{
        memberIndex: -1,
        nameSha256: 'a'.repeat(64),
      }],
    ]) {
      expect(knownReferenceEvidence({
        ...finding,
        evidence: {
          ...finding.evidence,
          archiveMemberChain,
        },
      })?.archiveMemberChain).toBeNull()
    }
    const members = [{
      memberIndex: 0,
      nameSha256: 'a'.repeat(64),
    }, {
      memberIndex: 2,
      nameSha256: 'b'.repeat(64),
    }]

    expect(knownReferenceEvidence({
      ...finding,
      evidence: {
        ...finding.evidence,
        archiveMemberChain: members,
      },
    })?.archiveMemberChain).toEqual(members)
  })

  it('keeps rows with the same rule and message distinct across positions and exact duplicates', () => {
    const finding = referenceFinding()
    const findings = [finding, finding, {
      ...finding,
      evidence: {
        ...finding.evidence,
        opcodeOffset: 42,
      },
    }]
    const rows = findingDisplayRows(findings)

    expect(new Set(rows.map(row => row.key)).size).toBe(3)
    expect(findingDisplayRows(findings).map(row => row.key)).toEqual(rows.map(row => row.key))
    const member = {
      memberIndex: 0,
      nameSha256: 'a'.repeat(64),
    }

    expect(new Set(archiveMemberDisplayRows([member, member]).map(row => row.key)).size).toBe(2)
  })
})
