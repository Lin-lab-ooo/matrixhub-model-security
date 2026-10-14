import {
  Code, Group, Stack, Text,
} from '@mantine/core'
import { useTranslation } from 'react-i18next'

import { CopyValueButton } from '@/shared/components/CopyValueButton'

import { archiveMemberDisplayRows, knownReferenceEvidence } from './security.evidence'

import type { Finding } from '@matrixhub/api-ts/security/v1alpha1/security'

export function FindingReferenceEvidence({ finding }: { finding: Finding }) {
  const { t } = useTranslation()
  const evidence = knownReferenceEvidence(finding)

  if (!evidence) {
    return <Text size="sm" c="dimmed">{t('security.referenceEvidence.unavailable')}</Text>
  }

  return (
    <Stack gap="xs">
      <Group gap="xs">
        <Text fw={600} size="sm">{t('security.referenceEvidence.title')}</Text>
        <Code>{evidence.symbol}</Code>
      </Group>
      <Text size="sm">{t('security.referenceEvidence.observation')}</Text>
      <Text size="sm">{t('security.referenceEvidence.capability')}</Text>
      <Group gap="md">
        <Text size="sm">
          {t('security.referenceEvidence.source')}
          :
          {' '}
          <Code>{evidence.source}</Code>
        </Text>
        <Text size="sm">
          {t('security.referenceEvidence.stream')}
          :
          {' '}
          {evidence.streamIndex ?? t('security.referenceEvidence.positionUnavailable')}
        </Text>
        <Text size="sm">
          {t('security.referenceEvidence.offset')}
          :
          {' '}
          {evidence.opcodeOffset ?? t('security.referenceEvidence.positionUnavailable')}
        </Text>
      </Group>
      <Text size="sm" c="dimmed">{t(`security.referenceEvidence.sources.${evidence.source}`)}</Text>
      <Text size="sm">{t('security.referenceEvidence.archive')}</Text>
      {evidence.archiveMemberChain === null
        ? <Text size="sm" c="dimmed">{t('security.referenceEvidence.positionUnavailable')}</Text>
        : evidence.archiveMemberChain.length === 0
          ? <Text size="sm" c="dimmed">{t('security.referenceEvidence.rootArtifact')}</Text>
          : archiveMemberDisplayRows(evidence.archiveMemberChain).map(({
              member, key,
            }) => (
              <Group key={key} gap="xs" wrap="wrap">
                <Text size="sm">{t('security.referenceEvidence.member', { index: member.memberIndex })}</Text>
                <Code title={member.nameSha256} aria-label={`${t('security.referenceEvidence.memberDigest')}: ${member.nameSha256}`}>
                  {member.nameSha256.slice(0, 12)}
                  …
                </Code>
                <CopyValueButton value={member.nameSha256} />
              </Group>
            ))}
      <Text size="sm">{t('security.referenceEvidence.compatibility')}</Text>
    </Stack>
  )
}
