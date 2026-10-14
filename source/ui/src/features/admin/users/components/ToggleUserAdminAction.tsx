import { Button } from '@mantine/core'
import { useMutation } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'

import {
  revokeUserAdminMutationOptions,
  setUserAdminMutationOptions,
} from '../users.mutation'

import type { User } from '@matrixhub/api-ts/v1alpha1/user.pb'

interface ToggleUserAdminActionProps {
  user: User
  disabled?: boolean
}

export function ToggleUserAdminAction({
  user,
  disabled,
}: ToggleUserAdminActionProps) {
  const { t } = useTranslation()
  const isAdmin = !!user.isAdmin
  const mutation = useMutation(
    isAdmin
      ? revokeUserAdminMutationOptions()
      : setUserAdminMutationOptions(),
  )

  const handleClick = async () => {
    await mutation.mutateAsync({ id: user.id })
  }

  return (
    <Button
      variant="transparent"
      size="compact-sm"
      color="blue"
      disabled={disabled || mutation.isPending}
      loading={mutation.isPending}
      onClick={() => {
        void handleClick()
      }}
    >
      {isAdmin
        ? t('routes.admin.users.actions.revokeAdmin')
        : t('routes.admin.users.actions.setAdmin')}
    </Button>
  )
}
