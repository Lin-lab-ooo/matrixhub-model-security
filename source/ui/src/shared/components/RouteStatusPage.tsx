import {
  Box, Button, Stack, Text, Title,
} from '@mantine/core'
import { Link } from '@tanstack/react-router'
import { useTranslation } from 'react-i18next'

interface RouteStatusPageProps {
  code: 403 | 404
  title?: string
  description?: string
  fullScreen?: boolean
}

export function RouteStatusPage({
  code,
  title,
  description,
  fullScreen = false,
}: RouteStatusPageProps) {
  const { t } = useTranslation()

  return (
    <Box
      h={fullScreen ? '100vh' : '100%'}
      pos="relative"
      style={{
        overflow: 'hidden',
      }}
    >
      <Box
        aria-hidden
        pos="absolute"
        fw="900"
        c="gray.1"
        lh="1"
        lts="-0.04em"
        left="50%"
        fz="clamp(180px, 35vw, 500px)"
        style={{
          top: 'calc(50% - var(--app-shell-header-height) / 2)',
          userSelect: 'none',
          transform: 'translateY(-50%) translateX(-50%)',
        }}
      >
        {code}
      </Box>

      <Stack
        align="center"
        gap="md"
        pos="absolute"
        left="50%"
        top="50%"
        style={{
          transform: 'translateX(-50%)',
          zIndex: 1,
        }}
      >
        <Title order={2} fw={700} fz={28} ta="center">
          {title ?? t(`common.errorPage.${code}.title`)}
        </Title>
        <Text c="dimmed" size="md" ta="center" maw={500}>
          {description ?? t(`common.errorPage.${code}.description`)}
        </Text>
        <Button component={Link} to="/" size="md" mt="sm">
          {t('common.errorPage.backToHome')}
        </Button>
      </Stack>
    </Box>
  )
}
