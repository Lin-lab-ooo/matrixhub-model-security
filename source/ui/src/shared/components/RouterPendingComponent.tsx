import {
  Center, Loader, Stack, Text,
} from '@mantine/core'
import { useTranslation } from 'react-i18next'

export function RouterPendingComponent() {
  const { t } = useTranslation()

  return (
    <Center h="100%" p="xl" style={{ flexGrow: 1 }}>
      <Stack align="center" gap="md">
        <Loader size="lg" type="dots" />
        <Text c="dimmed" size="sm" fw={500}>
          {t('shared.components.RouterPendingComponent.loading')}
        </Text>
      </Stack>
    </Center>
  )
}
