import {
  Badge, Group, Paper, SimpleGrid, Stack, Text,
} from '@mantine/core'
import { filesize } from 'filesize'
import { useTranslation } from 'react-i18next'

import { hasCompleteCoverage } from './security.utils'

import type { SecurityReport } from '@matrixhub/api-ts/security/v1alpha1/security'

export function SecurityOverview({ report }: { report: SecurityReport }) {
  const { t } = useTranslation()
  const files = report.files ?? []
  const complete = hasCompleteCoverage(report)
  const findings = files.reduce((count, file) => count + (file.findings?.length ?? 0), 0)

  return (
    <SimpleGrid
      cols={{
        base: 2,
        md: 4,
      }}
      spacing="sm"
    >
      <Paper withBorder radius="md" p="md">
        <Stack gap="xs">
          <Text size="xs" c="dimmed">{t('security.coverage')}</Text>
          <Group gap="xs" align="center">
            <Text fw={600} size="lg">{`${files.length} / ${report.expectedFiles}`}</Text>
            <Badge variant="light" color={complete ? 'teal' : 'red'} size="sm">
              {t(complete ? 'security.complete' : 'security.incomplete')}
            </Badge>
          </Group>
          <Text size="xs" c="dimmed">{t('security.overview.coverageHint')}</Text>
        </Stack>
      </Paper>
      <Paper withBorder radius="md" p="md">
        <Stack gap="xs">
          <Text size="xs" c="dimmed">{t('security.findings')}</Text>
          <Text fw={600} size="lg">{findings}</Text>
          <Text size="xs" c="dimmed">{t('security.overview.findingsHint')}</Text>
        </Stack>
      </Paper>
      <Paper withBorder radius="md" p="md">
        <Stack gap="xs">
          <Text size="xs" c="dimmed">{t('security.scannedBytes')}</Text>
          <Text fw={600} size="lg">{filesize(report.scannedBytes)}</Text>
          <Text size="xs" c="dimmed">{t('security.overview.cacheHint', { count: report.cachedFiles })}</Text>
        </Stack>
      </Paper>
      <Paper withBorder radius="md" p="md">
        <Stack gap="xs">
          <Text size="xs" c="dimmed">{t('security.duration')}</Text>
          <Text fw={600} size="lg">{`${report.durationMs} ms`}</Text>
          <Text size="xs" c="dimmed">{t('security.overview.attemptHint', { count: report.attempt })}</Text>
        </Stack>
      </Paper>
    </SimpleGrid>
  )
}
