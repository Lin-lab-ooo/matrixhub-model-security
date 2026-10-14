import {
  Alert, Badge, Button, Group, Stack, Text,
} from '@mantine/core'
import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'

import { getErrorMessage } from '@/queryClient'
import { DataTable } from '@/shared/components/DataTable'
import { TruncatedText } from '@/shared/components/TruncatedText'

import { securityAuditsQueryOptions } from './security.query'

import type { ModelScope, SecurityAudit } from '@matrixhub/api-ts/security/v1alpha1/security'
import type { MRT_ColumnDef, MRT_Row } from 'mantine-react-table'

function AuditPathCell({ row }: { row: MRT_Row<SecurityAudit> }) {
  return <TruncatedText value={row.original.path || '—'} />
}

function AuditDecisionCell({ row }: { row: MRT_Row<SecurityAudit> }) {
  return row.original.decision
    ? <Badge variant="light" color={row.original.decision.allowed ? 'blue' : 'red'}>{row.original.decision.code}</Badge>
    : '—'
}

export function SecurityAudits({ scope }: { scope: ModelScope }) {
  const { t } = useTranslation()
  const [offset, setOffset] = useState(0)
  const query = useQuery(securityAuditsQueryOptions(scope, offset))
  const columns: MRT_ColumnDef<SecurityAudit>[] = [
    {
      accessorKey: 'createdAt',
      header: t('security.createdAt'),
      Cell: ({ row }) => new Date(row.original.createdAt).toLocaleString(),
    },
    {
      accessorKey: 'actor',
      header: t('security.actor'),
    },
    {
      accessorKey: 'action',
      header: t('security.action'),
    },
    {
      accessorKey: 'entry',
      header: t('security.entry'),
    },
    {
      accessorKey: 'path',
      header: t('security.file'),
      Cell: AuditPathCell,
    },
    {
      id: 'decision',
      header: t('security.decision'),
      Cell: AuditDecisionCell,
    },
    {
      id: 'version',
      header: t('security.policyVersion'),
      accessorFn: audit => audit.decision?.policyVersion ?? '—',
    },
  ]

  if (query.isError) {
    return <Alert color="red">{getErrorMessage(query.error)}</Alert>
  }

  return (
    <Stack gap="md">
      <Text size="sm" c="dimmed">{t('security.auditsDescription')}</Text>
      <DataTable
        data={query.data?.items ?? []}
        columns={columns}
        loading={query.isPending}
        fetching={query.isFetching}
        getRowId={audit => String(audit.id)}
        emptyTitle={t('security.noAudits')}
        emptyDescription={t('security.noAuditsDescription')}
        tableOptions={{
          renderDetailPanel: ({ row }) => (
            <Stack gap="xs">
              <Text size="sm">
                {t('security.commit')}
                :
                {' '}
                {row.original.revision}
              </Text>
              <Text size="sm">
                {t('security.generation')}
                :
                {' '}
                {row.original.review?.generation || row.original.decision?.generation || '—'}
              </Text>
              <Text size="sm">
                {t('security.reportId')}
                :
                {' '}
                {row.original.review?.reportId || row.original.decision?.reportId || '—'}
              </Text>
              {row.original.review
                ? (
                    <>
                      <Text size="sm">{t(`security.reviews.verdicts.${row.original.review.verdict}`)}</Text>
                      <Text
                        size="sm"
                        style={{
                          whiteSpace: 'pre-wrap',
                          overflowWrap: 'anywhere',
                        }}
                      >
                        {row.original.review.comment}
                      </Text>
                      <Text size="sm" c="dimmed">{t('security.reviews.notice')}</Text>
                    </>
                  )
                : <Text size="sm">{row.original.decision?.message || '—'}</Text>}
            </Stack>
          ),
        }}
      />
      <Group justify="space-between">
        <Text size="sm" c="dimmed">
          {t('security.pageCount', {
            count: query.data?.count ?? 0,
            offset,
          })}
        </Text>
        <Group gap="xs">
          <Button variant="default" size="xs" disabled={offset === 0 || query.isFetching} onClick={() => setOffset(value => Math.max(0, value - 50))}>{t('security.previous')}</Button>
          <Button variant="default" size="xs" disabled={!query.data?.hasMore || query.isFetching} onClick={() => setOffset(value => value + 50)}>{t('security.next')}</Button>
        </Group>
      </Group>
    </Stack>
  )
}
