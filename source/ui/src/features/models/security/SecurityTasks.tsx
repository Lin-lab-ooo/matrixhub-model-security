import {
  Alert, Button, Code, Group, Stack, Text,
} from '@mantine/core'
import { useMutation, useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'

import { getErrorMessage } from '@/queryClient'
import { DataTable } from '@/shared/components/DataTable'
import { ModalWrapper } from '@/shared/components/ModalWrapper'
import { TruncatedText } from '@/shared/components/TruncatedText'

import { securityCancelMutationOptions } from './security.mutation'
import { securityTasksQueryOptions } from './security.query'
import { SecurityStateBadge } from './SecurityStateBadge'

import type { ModelScope, SecurityTask } from '@matrixhub/api-ts/security/v1alpha1/security'
import type { MRT_ColumnDef, MRT_Row } from 'mantine-react-table'

function TaskCommitCell({ row }: { row: MRT_Row<SecurityTask> }) {
  return <TruncatedText value={row.original.revision} ff="monospace" />
}

function TaskGenerationCell({ row }: { row: MRT_Row<SecurityTask> }) {
  return <TruncatedText value={row.original.generation} />
}

function TaskStateCell({ row }: { row: MRT_Row<SecurityTask> }) {
  return <SecurityStateBadge state={row.original.state} historical />
}

export function SecurityTasks({
  scope, canWrite, onViewReport,
}: {
  scope: ModelScope
  canWrite: boolean
  onViewReport: (reportId: string) => void
}) {
  const { t } = useTranslation()
  const [offset, setOffset] = useState(0)
  const [cancelTask, setCancelTask] = useState<SecurityTask | null>(null)
  const query = useQuery(securityTasksQueryOptions(scope, offset))
  const cancel = useMutation(securityCancelMutationOptions(scope))
  const columns: MRT_ColumnDef<SecurityTask>[] = [
    {
      accessorKey: 'id',
      header: t('security.taskId'),
      size: 90,
    },
    {
      accessorKey: 'revision',
      header: t('security.commit'),
      Cell: TaskCommitCell,
    },
    {
      accessorKey: 'generation',
      header: t('security.generation'),
      Cell: TaskGenerationCell,
    },
    {
      accessorKey: 'state',
      header: t('security.state'),
      Cell: TaskStateCell,
    },
    {
      accessorKey: 'attempt',
      header: t('security.attempt'),
      size: 80,
    },
    {
      accessorKey: 'trigger',
      header: t('security.trigger'),
      size: 110,
    },
    {
      accessorKey: 'updatedAt',
      header: t('security.updatedAt'),
      Cell: ({ row }) => new Date(row.original.updatedAt).toLocaleString(),
    },
  ]

  if (query.isError) {
    return <Alert color="red">{getErrorMessage(query.error)}</Alert>
  }

  return (
    <Stack gap="md">
      <Text size="sm" c="dimmed">{t('security.tasksDescription')}</Text>
      <DataTable
        data={query.data?.items ?? []}
        columns={columns}
        loading={query.isPending}
        fetching={query.isFetching}
        getRowId={task => String(task.id)}
        emptyTitle={t('security.noTasks')}
        emptyDescription={t('security.noTasksDescription')}
        pinRowActions
        enableRowActions
        renderRowActions={({ row }) => (
          <Group gap="xs" wrap="nowrap">
            {row.original.attempt > 0 && (
              <Button size="xs" variant="subtle" onClick={() => onViewReport(`${row.original.id}-${row.original.attempt}`)}>
                {t('security.viewReport')}
              </Button>
            )}
            {canWrite && ['pending', 'scanning'].includes(row.original.state) && (
              <Button size="xs" variant="subtle" color="red" onClick={() => setCancelTask(row.original)}>{t('security.cancelTask')}</Button>
            )}
          </Group>
        )}
        tableOptions={{
          enableColumnPinning: true,
          initialState: { columnPinning: { left: ['id'] } },
          renderDetailPanel: ({ row }) => <Text size="sm">{row.original.error || t('security.noTaskError')}</Text>,
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
      <ModalWrapper
        type="danger"
        title={t('security.cancelTask')}
        opened={cancelTask !== null}
        onClose={() => setCancelTask(null)}
        confirmLoading={cancel.isPending}
        onConfirm={async () => {
          if (cancelTask) {
            await cancel.mutateAsync(cancelTask.id)
            setCancelTask(null)
          }
        }}
      >
        <Text>{t('security.cancelNotice')}</Text>
        <Text size="sm">
          {t('security.taskId')}
          :
          {' '}
          <Code>{cancelTask?.id}</Code>
        </Text>
        <Text size="sm">
          {t('security.commit')}
          :
          {' '}
          <Code>{cancelTask?.revision}</Code>
        </Text>
      </ModalWrapper>
    </Stack>
  )
}
