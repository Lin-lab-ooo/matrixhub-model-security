import {
  Alert, Badge, Button, Group, Select, Stack, Text, Textarea,
} from '@mantine/core'
import { useMutation, useQuery } from '@tanstack/react-query'
import {
  useEffect, useEffectEvent, useState,
} from 'react'
import { useTranslation } from 'react-i18next'

import { getErrorMessage } from '@/queryClient'
import { DataTable } from '@/shared/components/DataTable'
import { ModalWrapper } from '@/shared/components/ModalWrapper'
import { TruncatedText } from '@/shared/components/TruncatedText'
import { useForm } from '@/shared/hooks/useForm'
import { fieldError } from '@/shared/utils/form'

import { securityAddReviewMutationOptions } from './security.mutation'
import { securityReviewsQueryOptions } from './security.query'
import { isReviewableReport } from './security.reviews'
import { reviewFormSchema } from './security.schema'
import { SecurityIdentity } from './SecurityIdentity'

import type {
  ModelScope, ReviewVerdict, SecurityReport, SecurityReview,
} from '@matrixhub/api-ts/security/v1alpha1/security'
import type { MRT_ColumnDef, MRT_Row } from 'mantine-react-table'

function ReviewActorCell({ row }: { row: MRT_Row<SecurityReview> }) {
  return <TruncatedText value={row.original.actor} />
}

function ReviewVerdictCell({ row }: { row: MRT_Row<SecurityReview> }) {
  const { t } = useTranslation()

  return <Badge variant="light">{t(`security.reviews.verdicts.${row.original.verdict}`)}</Badge>
}

function ReviewCommentCell({ row }: { row: MRT_Row<SecurityReview> }) {
  return <TruncatedText value={row.original.comment} />
}

function ReviewModal({
  scope, report, opened, onClose, onSaved,
}: {
  scope: ModelScope
  report: SecurityReport
  opened: boolean
  onClose: () => void
  onSaved: () => void
}) {
  const { t } = useTranslation()
  const mutation = useMutation(securityAddReviewMutationOptions(scope, report.reportId))
  const form = useForm({
    defaultValues: {
      verdict: 'needs_followup' as ReviewVerdict,
      comment: '',
    },
    validators: { onChange: reviewFormSchema },
    onSubmit: async ({ value }) => {
      await mutation.mutateAsync({
        ...value,
        comment: value.comment.trim(),
        revision: report.revision,
        generation: report.generation,
      })
      onSaved()
      onClose()
    },
  })
  const reset = useEffectEvent(() => form.reset())

  useEffect(() => {
    if (opened) {
      reset()
    }
  }, [opened])

  return (
    <ModalWrapper
      opened={opened}
      onClose={onClose}
      title={t('security.reviews.add')}
      footer={(
        <form.Subscribe selector={state => [state.canSubmit, state.isSubmitting, state.isPristine]}>
          {([canSubmit, isSubmitting, isPristine]) => (
            <Group justify="flex-end">
              <Button variant="default" onClick={onClose} disabled={isSubmitting}>{t('common.cancel')}</Button>
              <Button
                loading={mutation.isPending || isSubmitting}
                disabled={!canSubmit || isPristine}
                onClick={() => void form.handleSubmit()}
              >
                {t('security.reviews.save')}
              </Button>
            </Group>
          )}
        </form.Subscribe>
      )}
    >
      <Alert color="blue">{t('security.reviews.notice')}</Alert>
      <SecurityIdentity report={report} />
      <form.Field name="verdict">
        {field => (
          <Select
            withAsterisk
            label={t('security.reviews.verdict')}
            data={(['confirmed_risk', 'false_positive', 'needs_followup'] as const).map(value => ({
              value,
              label: t(`security.reviews.verdicts.${value}`),
            }))}
            value={field.state.value}
            onChange={value => field.handleChange((value ?? 'needs_followup') as ReviewVerdict)}
            onBlur={field.handleBlur}
            error={fieldError(field)}
            allowDeselect={false}
          />
        )}
      </form.Field>
      <form.Field name="comment">
        {field => (
          <Textarea
            withAsterisk
            autosize
            minRows={4}
            maxRows={10}
            label={t('security.reviews.comment')}
            description={t('security.reviews.commentHint')}
            value={field.state.value}
            onChange={event => field.handleChange(event.currentTarget.value)}
            onBlur={field.handleBlur}
            error={fieldError(field)}
          />
        )}
      </form.Field>
      <Text size="sm" c="dimmed">{t('security.reviews.appendOnly')}</Text>
    </ModalWrapper>
  )
}

export function SecurityReviews({
  scope, report, canWrite, historical,
}: {
  scope: ModelScope
  report?: SecurityReport
  canWrite: boolean
  historical: boolean
}) {
  const { t } = useTranslation()
  const [offset, setOffset] = useState(0)
  const [opened, setOpened] = useState(false)
  const reviewable = isReviewableReport(report)
  const query = useQuery(securityReviewsQueryOptions(scope, reviewable ? report.reportId : '', offset))
  const columns: MRT_ColumnDef<SecurityReview>[] = [
    {
      accessorKey: 'createdAt',
      header: t('security.createdAt'),
      Cell: ({ row }) => new Date(row.original.createdAt).toLocaleString(),
    },
    {
      accessorKey: 'actor',
      header: t('security.actor'),
      Cell: ReviewActorCell,
    },
    {
      accessorKey: 'verdict',
      header: t('security.reviews.verdict'),
      Cell: ReviewVerdictCell,
    },
    {
      accessorKey: 'comment',
      header: t('security.reviews.comment'),
      Cell: ReviewCommentCell,
    },
  ]

  if (!reviewable) {
    return <Alert color="blue">{t('security.reviews.terminalRequired')}</Alert>
  }

  return (
    <Stack gap="md">
      <Alert color="blue">{t('security.reviews.notice')}</Alert>
      {historical && <Alert color="yellow">{t('security.historicalNotice')}</Alert>}
      <SecurityIdentity report={report} />
      <Group justify="space-between">
        <Text size="sm" c="dimmed">{t('security.reviews.appendOnly')}</Text>
        {canWrite
          ? <Button size="xs" variant="light" onClick={() => setOpened(true)}>{t('security.reviews.add')}</Button>
          : <Text size="sm" c="dimmed">{t('security.reviews.readOnly')}</Text>}
      </Group>
      {query.isError
        ? <Alert color="red">{getErrorMessage(query.error)}</Alert>
        : (
            <DataTable
              data={query.data?.items ?? []}
              columns={columns}
              loading={query.isPending}
              fetching={query.isFetching}
              getRowId={review => String(review.id)}
              emptyTitle={t('security.reviews.empty')}
              emptyDescription={t('security.reviews.emptyDescription')}
              tableOptions={{
                renderDetailPanel: ({ row }) => (
                  <Text
                    size="sm"
                    style={{
                      whiteSpace: 'pre-wrap',
                      overflowWrap: 'anywhere',
                    }}
                  >
                    {row.original.comment}
                  </Text>
                ),
              }}
            />
          )}
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
      {canWrite && (
        <ReviewModal scope={scope} report={report} opened={opened} onClose={() => setOpened(false)} onSaved={() => setOffset(0)} />
      )}
    </Stack>
  )
}
