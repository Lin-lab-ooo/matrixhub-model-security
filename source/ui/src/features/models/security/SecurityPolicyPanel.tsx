import {
  Alert, Badge, Button, Code, Group, Paper, Select, SimpleGrid, Stack, Text,
} from '@mantine/core'
import { useMutation, useQuery } from '@tanstack/react-query'
import {
  useEffect, useEffectEvent, useState,
} from 'react'
import { useTranslation } from 'react-i18next'

import { getErrorMessage } from '@/queryClient'
import { ModalWrapper } from '@/shared/components/ModalWrapper'
import { useForm } from '@/shared/hooks/useForm'
import { fieldError } from '@/shared/utils/form'

import { securityPolicyMutationOptions } from './security.mutation'
import { securityPolicyQueryOptions } from './security.query'
import { policySchema } from './security.schema'

import type {
  ModelScope, PolicyInput, SecurityPolicy,
} from '@matrixhub/api-ts/security/v1alpha1/security'

function PolicyModal({
  scope, policy, opened, onClose,
}: {
  scope: ModelScope
  policy: SecurityPolicy
  opened: boolean
  onClose: () => void
}) {
  const { t } = useTranslation()
  const mutation = useMutation(securityPolicyMutationOptions(scope))
  const form = useForm({
    defaultValues: {
      mode: policy.mode,
      blockSeverity: policy.blockSeverity,
    } as PolicyInput,
    validators: { onBlur: policySchema },
    onSubmit: async ({ value }) => {
      await mutation.mutateAsync(value)
      onClose()
    },
  })
  const reset = useEffectEvent(() => form.reset({
    mode: policy.mode,
    blockSeverity: policy.blockSeverity,
  }))

  useEffect(() => {
    if (opened) {
      reset()
    }
  }, [opened])

  return (
    <ModalWrapper opened={opened} onClose={onClose} title={t('security.editPolicy')} confirmLoading={mutation.isPending} onConfirm={() => form.handleSubmit()}>
      <Alert color="yellow">{t('security.policyNotice')}</Alert>
      <form.Field name="mode">
        {field => (
          <Select
            label={t('security.mode')}
            data={['enforce', 'audit'].map(mode => ({
              value: mode,
              label: t(`security.modes.${mode}`),
            }))}
            value={field.state.value}
            onChange={value => field.handleChange(value as PolicyInput['mode'])}
            onBlur={field.handleBlur}
            error={fieldError(field)}
            allowDeselect={false}
          />
        )}
      </form.Field>
      <form.Field name="blockSeverity">
        {field => (
          <Select
            label={t('security.blockSeverity')}
            data={['low', 'medium', 'high', 'critical'].map(severity => ({
              value: severity,
              label: t(`security.severity.${severity}`),
            }))}
            value={field.state.value}
            onChange={value => field.handleChange(value as PolicyInput['blockSeverity'])}
            onBlur={field.handleBlur}
            error={fieldError(field)}
            allowDeselect={false}
          />
        )}
      </form.Field>
    </ModalWrapper>
  )
}

export function SecurityPolicyPanel({
  scope, canAdmin,
}: { scope: ModelScope
  canAdmin: boolean }) {
  const { t } = useTranslation()
  const query = useQuery(securityPolicyQueryOptions(scope))
  const [opened, setOpened] = useState(false)

  if (query.isError) {
    return <Alert color="red">{getErrorMessage(query.error)}</Alert>
  }
  if (!query.data) {
    return <Text c="dimmed">{t('security.loading')}</Text>
  }

  return (
    <Stack gap="md">
      <Text size="sm" c="dimmed">{t('security.policyDescription')}</Text>
      <Alert color="blue">{t('security.policyNotice')}</Alert>
      <SimpleGrid
        cols={{
          base: 1,
          sm: 3,
        }}
        spacing="sm"
      >
        <Paper withBorder p="md" radius="md">
          <Stack gap="xs">
            <Text size="xs" c="dimmed">{t('security.mode')}</Text>
            <Badge variant="light">{t(`security.modes.${query.data.mode}`)}</Badge>
          </Stack>
        </Paper>
        <Paper withBorder p="md" radius="md">
          <Stack gap="xs">
            <Text size="xs" c="dimmed">{t('security.blockSeverity')}</Text>
            <Text fw={600} size="sm">{t(`security.severity.${query.data.blockSeverity}`)}</Text>
          </Stack>
        </Paper>
        <Paper withBorder p="md" radius="md">
          <Stack gap="xs">
            <Text size="xs" c="dimmed">{t('security.policyVersion')}</Text>
            <Code>{query.data.version}</Code>
          </Stack>
        </Paper>
      </SimpleGrid>
      {canAdmin && <Group><Button variant="light" size="xs" onClick={() => setOpened(true)}>{t('security.editPolicy')}</Button></Group>}
      <PolicyModal scope={scope} policy={query.data} opened={opened} onClose={() => setOpened(false)} />
    </Stack>
  )
}
