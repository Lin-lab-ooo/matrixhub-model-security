import {
  Alert, Button, Card, Code, Collapse, Flex, Group, Stack, Tabs, Text, TextInput, ThemeIcon,
} from '@mantine/core'
import {
  IconChevronDown, IconChevronUp, IconFileSearch, IconHistory, IconListDetails,
  IconRefresh, IconSettings, IconShieldCheck,
} from '@tabler/icons-react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'

import { getErrorMessage } from '@/queryClient'
import { ModalWrapper } from '@/shared/components/ModalWrapper'
import { useForm } from '@/shared/hooks/useForm'
import { fieldError } from '@/shared/utils/form'

import { securityRescanMutationOptions } from './security.mutation'
import { securityHistoryQueryOptions, securityReportQueryOptions } from './security.query'
import { revisionFormSchema } from './security.schema'
import { visibleReportState } from './security.utils'
import { SecurityAudits } from './SecurityAudits'
import { SecurityIdentity } from './SecurityIdentity'
import { SecurityOverview } from './SecurityOverview'
import { SecurityPolicyPanel } from './SecurityPolicyPanel'
import classes from './SecurityPresentation.module.css'
import { SecurityReportEvidence } from './SecurityReportEvidence'
import { SecurityReviews } from './SecurityReviews'
import { SecurityStateBadge } from './SecurityStateBadge'
import { SecurityTasks } from './SecurityTasks'

import type { ModelScope } from '@matrixhub/api-ts/security/v1alpha1/security'

export function ModelSecurityCard({
  scope, defaultRevision, canWrite, canAdmin,
}: {
  scope: ModelScope
  defaultRevision: string
  canWrite: boolean
  canAdmin: boolean
}) {
  const { t } = useTranslation()
  const [revision, setRevision] = useState(defaultRevision)
  const [expanded, setExpanded] = useState(false)
  const [tab, setTab] = useState<string | null>('report')
  const [historicalId, setHistoricalId] = useState('')
  const [rescanOpened, setRescanOpened] = useState(false)
  const query = useQuery(securityReportQueryOptions(scope, revision))
  const history = useQuery(securityHistoryQueryOptions(scope, historicalId))
  const rescan = useMutation(securityRescanMutationOptions(scope))
  const form = useForm({
    defaultValues: { revision: defaultRevision },
    validators: { onBlur: revisionFormSchema },
    onSubmit: ({ value }) => {
      const selected = value.revision.trim()

      setHistoricalId('')
      setRevision(selected)
      if (selected === revision) {
        void query.refetch()
      }
    },
  })
  const report = query.isError ? undefined : query.data
  const state = query.isError ? 'fail' : visibleReportState(report, query.isFetching)
  const unavailable = query.isError && typeof query.error === 'object' && query.error !== null
    && 'code' in query.error && query.error.code === 'SecurityUnavailable'

  return (
    <Card
      withBorder
      radius="md"
      mb="lg"
      padding="lg"
      className={classes.card}
    >
      <Stack gap="md">
        <Group justify="space-between" align="flex-start" className={classes.header}>
          <Group gap="sm" align="flex-start" className={classes.heading} wrap="nowrap">
            <ThemeIcon variant="light" radius="md" size="lg"><IconShieldCheck size={22} /></ThemeIcon>
            <Stack gap={4} className={classes.heading}>
              <Group gap="sm">
                <Text fw={600} size="lg">{t('security.title')}</Text>
                {unavailable ? <Text size="sm" c="dimmed">{t('security.unavailable')}</Text> : <SecurityStateBadge state={state} />}
              </Group>
              <Text size="sm" c="dimmed">{t('security.description')}</Text>
              {!unavailable && <Text size="sm">{t(`security.statusHints.${state}`)}</Text>}
            </Stack>
          </Group>
          <Group gap="xs">
            {canWrite && !unavailable && (
              <Button
                size="xs"
                variant="light"
                leftSection={<IconRefresh size={15} />}
                disabled={!report || query.isFetching}
                onClick={() => setRescanOpened(true)}
              >
                {t('security.rescan')}
              </Button>
            )}
            <Button
              size="xs"
              variant="default"
              aria-expanded={expanded}
              rightSection={expanded ? <IconChevronUp size={15} /> : <IconChevronDown size={15} />}
              onClick={() => setExpanded(value => !value)}
            >
              {t(expanded ? 'security.hideDetails' : 'security.showDetails')}
            </Button>
          </Group>
        </Group>
        <form onSubmit={(event) => {
          event.preventDefault()
          void form.handleSubmit()
        }}
        >
          <Flex className={classes.revisionForm}>
            <form.Field name="revision">
              {field => (
                <TextInput
                  label={t('security.revision')}
                  description={t('security.revisionHint')}
                  placeholder="main"
                  value={field.state.value}
                  onChange={event => field.handleChange(event.target.value)}
                  onBlur={field.handleBlur}
                  error={fieldError(field)}
                  className={classes.revisionInput}
                />
              )}
            </form.Field>
            <Button type="submit" variant="light" leftSection={<IconFileSearch size={16} />} loading={query.isFetching}>
              {t('security.checkRevision')}
            </Button>
          </Flex>
        </form>
        {query.isError && <Alert color={unavailable ? 'gray' : 'red'}>{unavailable ? t('security.unavailableNotice') : getErrorMessage(query.error)}</Alert>}
        {report && (
          <>
            <SecurityOverview report={report} />
            <details className={classes.identityDetails}>
              <summary>{t('security.versionEvidence')}</summary>
              <SecurityIdentity report={report} />
            </details>
          </>
        )}
        <Collapse in={expanded && !unavailable}>
          <Tabs value={tab} onChange={setTab} keepMounted={false}>
            <Tabs.List mb="md" className={classes.tabs}>
              <Tabs.Tab value="report" leftSection={<IconFileSearch size={16} />}>{t('security.report')}</Tabs.Tab>
              <Tabs.Tab value="tasks" leftSection={<IconListDetails size={16} />}>{t('security.tasks')}</Tabs.Tab>
              <Tabs.Tab value="audits" leftSection={<IconHistory size={16} />}>{t('security.audits')}</Tabs.Tab>
              <Tabs.Tab value="reviews" leftSection={<IconListDetails size={16} />}>{t('security.reviews.title')}</Tabs.Tab>
              <Tabs.Tab value="policy" leftSection={<IconSettings size={16} />}>{t('security.policyTitle')}</Tabs.Tab>
            </Tabs.List>
            <Tabs.Panel value="report">
              {historicalId
                ? (
                    <Stack gap="md">
                      <Group>
                        <Button size="xs" variant="default" onClick={() => setHistoricalId('')}>{t('security.currentReport')}</Button>
                        <Code>{historicalId}</Code>
                      </Group>
                      {history.isError && <Alert color="red">{getErrorMessage(history.error)}</Alert>}
                      {history.isPending && <Text c="dimmed">{t('security.loading')}</Text>}
                      {!history.isError && history.data && <SecurityReportEvidence report={history.data} historical />}
                    </Stack>
                  )
                : report && <SecurityReportEvidence report={report} refreshing={query.isFetching} />}
            </Tabs.Panel>
            <Tabs.Panel value="tasks">
              <SecurityTasks
                scope={scope}
                canWrite={canWrite}
                onViewReport={(id) => {
                  setHistoricalId(id)
                  setTab('report')
                }}
              />
            </Tabs.Panel>
            <Tabs.Panel value="audits"><SecurityAudits scope={scope} /></Tabs.Panel>
            <Tabs.Panel value="reviews">
              {historicalId && (
                <Group mb="md">
                  <Button size="xs" variant="default" onClick={() => setHistoricalId('')}>{t('security.currentReport')}</Button>
                  <Code>{historicalId}</Code>
                </Group>
              )}
              {historicalId && history.isError
                ? <Alert color="red">{getErrorMessage(history.error)}</Alert>
                : (
                    <SecurityReviews
                      key={`${scope.namespace}/${scope.name}:${historicalId || report?.reportId || ''}`}
                      scope={scope}
                      report={historicalId ? history.data : report}
                      canWrite={canWrite}
                      historical={historicalId !== ''}
                    />
                  )}
            </Tabs.Panel>
            <Tabs.Panel value="policy"><SecurityPolicyPanel scope={scope} canAdmin={canAdmin} /></Tabs.Panel>
          </Tabs>
        </Collapse>
      </Stack>
      <ModalWrapper
        opened={rescanOpened}
        onClose={() => setRescanOpened(false)}
        title={t('security.rescan')}
        confirmLoading={rescan.isPending}
        onConfirm={async () => {
          await rescan.mutateAsync(revision)
          setRescanOpened(false)
          setHistoricalId('')
        }}
      >
        <Text>{t('security.rescanNotice')}</Text>
        <Text size="sm">
          {t('security.revision')}
          :
          {' '}
          <Code>{revision}</Code>
        </Text>
        <Text size="sm">
          {t('security.commit')}
          :
          {' '}
          <Code>{report?.revision}</Code>
        </Text>
      </ModalWrapper>
    </Card>
  )
}
