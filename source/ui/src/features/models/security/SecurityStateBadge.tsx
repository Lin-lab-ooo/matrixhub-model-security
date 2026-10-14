import { Badge } from '@mantine/core'
import {
  IconAlertTriangle, IconCheck, IconClock, IconLoader, IconShieldX, IconX,
} from '@tabler/icons-react'
import { useTranslation } from 'react-i18next'

import type { SecurityState } from '@matrixhub/api-ts/security/v1alpha1/security'

const stateColors: Record<SecurityState, string> = {
  pending: 'gray',
  scanning: 'blue',
  pass: 'green',
  warn: 'yellow',
  block: 'red',
  fail: 'red',
}
const stateIcons = {
  pending: IconClock,
  scanning: IconLoader,
  pass: IconCheck,
  warn: IconAlertTriangle,
  block: IconShieldX,
  fail: IconX,
}

export function SecurityStateBadge({
  state, historical = false,
}: { state: SecurityState
  historical?: boolean }) {
  const { t } = useTranslation()
  const StateIcon = stateIcons[state] ?? IconX

  return (
    <Badge color={historical && state === 'pass' ? 'gray' : stateColors[state]} variant="light" leftSection={<StateIcon size={12} />}>
      {t(`security.states.${state}`)}
    </Badge>
  )
}
