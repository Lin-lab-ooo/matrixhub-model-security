import {
  Code, Group, Stack, Text,
} from '@mantine/core'
import { useTranslation } from 'react-i18next'

import { CopyValueButton } from '@/shared/components/CopyValueButton'

import classes from './SecurityPresentation.module.css'

import type { SecurityReport } from '@matrixhub/api-ts/security/v1alpha1/security'

export function SecurityIdentity({ report }: { report: SecurityReport }) {
  const { t } = useTranslation()

  return (
    <Stack gap="sm">
      {[['commit', report.revision], ['generation', report.generation], ['reportId', report.reportId]].map(([key, value]) => (
        <Stack key={key} gap={4}>
          <Text size="xs" c="dimmed">{t(`security.${key}`)}</Text>
          <Group gap="xs" wrap="nowrap" align="flex-start">
            <Code className={classes.identityValue}>{value || '—'}</Code>
            {value && <CopyValueButton value={value} />}
          </Group>
        </Stack>
      ))}
    </Stack>
  )
}
