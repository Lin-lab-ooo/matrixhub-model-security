import type { ArchiveMemberEvidence, Finding } from '@matrixhub/api-ts/security/v1alpha1/security'

const knownSymbolId = 'torch-storage-load-from-bytes-v1'

function isEvidencePosition(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
}

export function archiveMemberDisplayRows(members: ArchiveMemberEvidence[]) {
  const occurrences = new Map<string, number>()

  return members.map((member) => {
    const identity = `${member.memberIndex}-${member.nameSha256}`
    const occurrence = occurrences.get(identity) ?? 0

    occurrences.set(identity, occurrence + 1)

    return {
      member,
      key: `${identity}:${occurrence}`,
    }
  })
}

/** Map only the versioned, trusted symbol ID; never display a raw model symbol. */
export function knownReferenceEvidence(finding: Finding) {
  const evidence = finding.evidence

  if (!evidence
    || evidence.knownSymbolId !== knownSymbolId
    || evidence.observation !== 'reference'
    || (evidence.source !== 'pickletools' && evidence.source !== 'picklescan')) {
    return null
  }

  const chain = evidence.archiveMemberChain
  const validChain = Array.isArray(chain) && chain.every(member => member !== null
    && typeof member === 'object'
    && isEvidencePosition(member.memberIndex)
    && typeof member.nameSha256 === 'string'
    && /^[0-9a-f]{64}$/.test(member.nameSha256))

  return {
    symbol: 'torch.storage._load_from_bytes',
    source: evidence.source,
    streamIndex: isEvidencePosition(evidence.streamIndex) ? evidence.streamIndex : null,
    opcodeOffset: isEvidencePosition(evidence.opcodeOffset) ? evidence.opcodeOffset : null,
    archiveMemberChain: validChain ? chain : null,
  }
}

/** Distinguish repeated findings without relying on message text alone. */
export function findingDisplayRows(findings: Finding[]) {
  const occurrences = new Map<string, number>()

  return findings.map((finding) => {
    const identity = JSON.stringify([
      finding.engine,
      finding.rule,
      finding.severity,
      finding.message,
      knownReferenceEvidence(finding),
    ])
    const occurrence = occurrences.get(identity) ?? 0

    occurrences.set(identity, occurrence + 1)

    return {
      finding,
      key: `${identity}:${occurrence}`,
    }
  })
}
