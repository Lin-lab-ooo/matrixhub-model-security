import {
  Badge,
  type BadgeProps,
} from '@mantine/core'
import { ProjectType } from '@matrixhub/api-ts/v1alpha1/project.pb'
import { useTranslation } from 'react-i18next'

interface ProjectTypeBadgeProps extends Omit<BadgeProps, 'children'> {
  type?: ProjectType
}

export function ProjectTypeBadge({
  type,
  ...badgeProps
}: ProjectTypeBadgeProps) {
  const { t } = useTranslation()

  if (!type) {
    return null
  }

  const PROJECT_TYPE_BADGE_CONFIG: Partial<Record<ProjectType, {
    color: string
    label: string
  }>> = {
    [ProjectType.PROJECT_TYPE_PUBLIC]: {
      color: 'teal',
      label: t('projects.type.public'),
    },
    [ProjectType.PROJECT_TYPE_PRIVATE]: {
      color: 'yellow',
      label: t('projects.type.private'),
    },
  }

  const badgeConfig = PROJECT_TYPE_BADGE_CONFIG[type]

  if (!badgeConfig) {
    return null
  }

  return (
    <Badge
      variant="light"
      radius="xl"
      size="xs"
      px="sm"
      color={badgeConfig.color}
      {...badgeProps}
    >
      {badgeConfig.label}
    </Badge>
  )
}
