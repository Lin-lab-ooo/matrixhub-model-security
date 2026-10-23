import {
  Alert, Button, Group, Select, Stack, Text,
} from '@mantine/core'
import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'

import { modelCommitsQueryOptions, modelRevisionsQueryOptions } from '@/features/models/models.query'
import { getErrorMessage } from '@/queryClient'
import { Pagination } from '@/shared/components/Pagination'
import { useForm } from '@/shared/hooks/useForm'
import { formatDateTime } from '@/shared/utils/date'
import { fieldError } from '@/shared/utils/form'

import { immutableCommitOptions } from './security.revisions'
import { revisionSchema } from './security.schema'

import type { ModelScope } from '@matrixhub/api-ts/security/v1alpha1/security'

interface SecurityRevisionPickerProps {
  scope: ModelScope
  defaultRevision: string
  revision: string
  onRevisionChange: (revision: string) => void
}

// Branch browsing and report selection are deliberately separate: pagination
// never changes the selected immutable report, and no previous page is used.
function SecurityCommitPicker({
  scope, branch, revision, onRevisionChange,
}: Omit<SecurityRevisionPickerProps, 'defaultRevision'> & { branch: string }) {
  const { t } = useTranslation()
  const [page, setPage] = useState(1)
  const query = useQuery(modelCommitsQueryOptions(scope.namespace, scope.name, {
    revision: branch,
    page,
    pageSize: 20,
  }))
  const options = immutableCommitOptions(query.isError ? [] : query.data?.items ?? [], (commit) => {
    const title = commit.message?.split('\n')[0].slice(0, 160) || t('security.revisionPicker.untitled')
    const date = formatDateTime(commit.authorDate, 'YYYY-MM-DD HH:mm:ss')

    return `${title} · ${date} · ${commit.id?.slice(0, 12)}`
  })
  const selected = /^[0-9a-f]{40}$/.test(revision) ? revision : null

  if (selected && !options.some(option => option.value === selected)) {
    options.unshift({
      value: selected,
      label: t('security.revisionPicker.selected', { sha: selected.slice(0, 12) }),
    })
  }

  return (
    <Stack gap="xs">
      <Select
        label={t('security.revisionPicker.commit')}
        description={t('security.revisionPicker.commitHint')}
        placeholder={t(query.isPending ? 'security.loading' : 'security.revisionPicker.choose')}
        searchable
        data={options}
        value={selected}
        disabled={query.isFetching || query.isError || !query.data?.items?.length}
        nothingFoundMessage={t('security.revisionPicker.noMatches')}
        onChange={(value) => {
          if (value) {
            onRevisionChange(value)
          }
        }}
      />
      {query.isFetching && <Text size="sm" c="dimmed" role="status">{t('security.loading')}</Text>}
      {query.isError && (
        <Alert color="red" title={t('security.revisionPicker.error')}>
          <Text size="sm">{getErrorMessage(query.error)}</Text>
          <Button
            mt="xs"
            size="xs"
            variant="light"
            onClick={() => {
              void query.refetch()
            }}
          >
            {t('security.revisionPicker.retry')}
          </Button>
        </Alert>
      )}
      {!query.isPending && !query.isError && !query.data?.items?.length && <Text size="sm" c="dimmed">{t('security.revisionPicker.empty')}</Text>}
      {query.data?.pagination && !query.isError && (
        <Pagination
          total={query.data.pagination.total ?? 0}
          totalPages={query.data.pagination.pages ?? 1}
          page={page}
          onPageChange={setPage}
          paginationProps={{
            size: 'xs',
            disabled: query.isFetching,
          }}
        />
      )}
    </Stack>
  )
}

export function SecurityRevisionPicker({
  scope, defaultRevision, revision, onRevisionChange,
}: SecurityRevisionPickerProps) {
  const { t } = useTranslation()
  const query = useQuery(modelRevisionsQueryOptions(scope.namespace, scope.name))
  const form = useForm({ defaultValues: { ref: defaultRevision } })
  const branches = query.isError ? [] : query.data?.items?.branches ?? []
  const tags = query.isError ? [] : query.data?.items?.tags ?? []
  const refs = [
    {
      group: t('shared.revisionSelect.group.branch'),
      items: branches.filter(item => item.name).map(item => ({
        value: `refs/heads/${item.name}`,
        label: item.name as string,
      })),
    },
    {
      group: t('shared.revisionSelect.group.tag'),
      items: tags.filter(item => item.name).map(item => ({
        value: `refs/tags/${item.name}`,
        label: item.name as string,
      })),
    },
  ].filter(group => group.items.length > 0)

  return (
    <form.Field name="ref" validators={{ onBlur: revisionSchema }}>
      {field => (
        <Stack gap="sm">
          <Group align="flex-end">
            <Select
              label={t('security.revisionPicker.ref')}
              data={refs}
              value={field.state.value.startsWith('refs/')
                ? field.state.value
                : `${branches.some(item => item.name === field.state.value) ? 'refs/heads/' : 'refs/tags/'}${field.state.value}`}
              disabled={query.isFetching || query.isError || refs.length === 0}
              searchable
              onBlur={field.handleBlur}
              error={fieldError(field)}
              onChange={(value) => {
                if (value) {
                  field.handleChange(value)
                  onRevisionChange(value)
                }
              }}
            />
            <Button variant="light" onClick={() => onRevisionChange(field.state.value)}>{t('security.revisionPicker.latest')}</Button>
          </Group>
          {query.isError && (
            <Alert color="red" title={t('security.revisionPicker.refsError')}>
              <Text size="sm">{getErrorMessage(query.error)}</Text>
              <Button
                size="xs"
                variant="light"
                mt="xs"
                onClick={() => {
                  void query.refetch()
                }}
              >
                {t('security.revisionPicker.retry')}
              </Button>
            </Alert>
          )}
          <SecurityCommitPicker
            key={field.state.value}
            scope={scope}
            branch={field.state.value}
            revision={revision}
            onRevisionChange={onRevisionChange}
          />
        </Stack>
      )}
    </form.Field>
  )
}
