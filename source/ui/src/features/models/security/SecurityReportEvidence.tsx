import {
  Alert, Badge, Code, Group, Paper, Stack, Text,
} from '@mantine/core'
import { filesize } from 'filesize'
import { useTranslation } from 'react-i18next'

import { CopyValueButton } from '@/shared/components/CopyValueButton'
import { DataTable } from '@/shared/components/DataTable'
import { TruncatedText } from '@/shared/components/TruncatedText'

import { FindingReferenceEvidence } from './FindingReferenceEvidence'
import { findingDisplayRows } from './security.evidence'
import { hasCompleteCoverage, visibleReportState } from './security.utils'
import { SecurityIdentity } from './SecurityIdentity'
import { SecurityOverview } from './SecurityOverview'
import classes from './SecurityPresentation.module.css'
import { SecurityStateBadge } from './SecurityStateBadge'

import type { FileReport, SecurityReport } from '@matrixhub/api-ts/security/v1alpha1/security'
import type { MRT_ColumnDef, MRT_Row } from 'mantine-react-table'

function FilePathCell({ row }: { row: MRT_Row<FileReport> }) {
  return <TruncatedText value={row.original.path} />
}

function FileDigestCell({ row }: { row: MRT_Row<FileReport> }) {
  const { t } = useTranslation()

  return (
    <Group gap="xs" wrap="nowrap">
      <TruncatedText value={row.original.sha256 || t('security.noEvidence')} ff="monospace" maw={180} />
      {row.original.sha256 && <CopyValueButton value={row.original.sha256} />}
    </Group>
  )
}

function FileCoverageCell({ row }: { row: MRT_Row<FileReport> }) {
  const { t } = useTranslation()

  return (
    <Badge color={row.original.complete ? 'blue' : 'red'} variant="light">
      {t(row.original.complete ? 'security.complete' : 'security.incomplete')}
    </Badge>
  )
}

export function SecurityReportEvidence({
  report, historical = false, refreshing = false,
}: {
  report: SecurityReport
  historical?: boolean
  refreshing?: boolean
}) {
  const { t } = useTranslation()
  const files = report.files ?? []
  const coverage = hasCompleteCoverage(report)
  const columns: MRT_ColumnDef<FileReport>[] = [
    {
      accessorKey: 'path',
      header: t('security.file'),
      Cell: FilePathCell,
      size: 260,
      minSize: 180,
    },
    {
      accessorKey: 'type',
      header: t('security.fileType'),
      size: 110,
      grow: false,
    },
    {
      accessorKey: 'size',
      header: t('security.size'),
      Cell: ({ row }) => filesize(row.original.size),
      size: 110,
      grow: false,
    },
    {
      accessorKey: 'sha256',
      header: 'SHA-256',
      Cell: FileDigestCell,
      size: 220,
      grow: false,
    },
    {
      id: 'findings',
      header: t('security.findings'),
      accessorFn: file => file.findings?.length ?? 0,
      size: 90,
      grow: false,
    },
    {
      id: 'coverage',
      header: t('security.coverage'),
      Cell: FileCoverageCell,
      size: 110,
      grow: false,
    },
  ]

  return (
    <Stack gap="md" className={classes.evidencePanel}>
      {historical && <Alert color="gray">{t('security.historicalNotice')}</Alert>}
      {!coverage && <Alert color="yellow">{t('security.coverageNotice')}</Alert>}
      <Group justify="space-between">
        <SecurityStateBadge state={visibleReportState(report, refreshing)} historical={historical} />
        <Text size="sm" c="dimmed">{t('security.reportDescription')}</Text>
      </Group>
      {historical && <SecurityOverview report={report} />}
      <details className={classes.identityDetails}>
        <summary>{t('security.versionEvidence')}</summary>
        <SecurityIdentity report={report} />
      </details>
      {report.error && <Alert color="red">{report.error}</Alert>}
      <Stack gap={4}>
        <Text fw={600} size="sm">{t('security.fileEvidence')}</Text>
        <Text size="xs" c="dimmed">{t('security.fileEvidenceHint')}</Text>
      </Stack>
      <DataTable
        data={files}
        columns={columns}
        getRowId={file => file.path}
        emptyTitle={t('security.noFiles')}
        emptyDescription={t('security.noFilesDescription')}
        tableOptions={{
          enableExpanding: true,
          enableColumnPinning: true,
          initialState: { columnPinning: { left: ['path'] } },
          renderDetailPanel: ({ row }) => (
            <Paper withBorder radius="md" p="md" className={classes.evidencePanel}>
              <Stack gap="sm">
                <Text fw={600} size="sm">{row.original.path}</Text>
                <Text size="sm">
                  {t('security.blob')}
                  :
                  {' '}
                  <Code>{row.original.blobId}</Code>
                </Text>
                {row.original.lfsOid && (
                  <Text size="sm">
                    LFS OID:
                    <Code>{row.original.lfsOid}</Code>
                  </Text>
                )}
                <Text size="sm">
                  {t('security.artifact')}
                  :
                  {' '}
                  <Code>{row.original.artifactId || '—'}</Code>
                </Text>
                <Text size="sm">
                  {t('security.generation')}
                  :
                  {' '}
                  <Code>{row.original.generation}</Code>
                </Text>
                <Text size="sm">
                  {t('security.engines')}
                  :
                  {' '}
                  {Object.entries(row.original.engines ?? {}).map(([engine, result]) => `${engine}: ${result}`).join(', ') || '—'}
                </Text>
                <Text size="sm">
                  {t('security.cache')}
                  :
                  {' '}
                  {t(row.original.cached ? 'security.cacheHit' : 'security.cacheMiss')}
                </Text>
                {findingDisplayRows(row.original.findings ?? []).map(({
                  finding, key,
                }) => (
                  <Alert key={key} color={finding.severity === 'low' ? 'yellow' : 'red'}>
                    <Stack gap="xs">
                      <Text fw={600} size="sm">
                        {finding.engine}
                        {' '}
                        ·
                        {' '}
                        {finding.rule}
                        {' '}
                        ·
                        {' '}
                        {t(`security.severity.${finding.severity}`)}
                      </Text>
                      {finding.evidence
                        ? <FindingReferenceEvidence finding={finding} />
                        : <Text size="sm">{finding.message}</Text>}
                      {!finding.evidence && finding.remediation && (
                        <Text size="sm">
                          {t('security.remediation')}
                          :
                          {' '}
                          {finding.remediation}
                        </Text>
                      )}
                    </Stack>
                  </Alert>
                ))}
              </Stack>
            </Paper>
          ),
        }}
      />
    </Stack>
  )
}
