import { Text } from '@mantine/core'
import { ProjectRoleType } from '@matrixhub/api-ts/v1alpha1/role.pb'
import { useMutation } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'

import { ModalWrapper } from '@/shared/components/ModalWrapper'

import { removeMembersMutationOptions } from '../members.mutation'

import type { ProjectMember } from '@matrixhub/api-ts/v1alpha1/project.pb'

interface RemoveMemberModalProps {
  opened: boolean
  onClose: () => void
  projectId: string
  members: ProjectMember[]
}

function getRoleLabel(t: (key: string) => string, role?: ProjectRoleType) {
  switch (role) {
    case ProjectRoleType.ROLE_TYPE_PROJECT_ADMIN:
      return t('projects.detail.membersPage.role.admin')
    case ProjectRoleType.ROLE_TYPE_PROJECT_EDITOR:
      return t('projects.detail.membersPage.role.editor')
    case ProjectRoleType.ROLE_TYPE_PROJECT_VIEWER:
      return t('projects.detail.membersPage.role.viewer')
    default:
      return '-'
  }
}

export function RemoveMemberModal({
  opened,
  onClose,
  projectId,
  members,
}: RemoveMemberModalProps) {
  const { t } = useTranslation()
  const mutation = useMutation(removeMembersMutationOptions())

  const isBatch = members.length > 1

  const title = isBatch
    ? t('projects.detail.membersPage.batchRemoveModal.title')
    : t('projects.detail.membersPage.removeModal.title')

  const message = isBatch
    ? t('projects.detail.membersPage.batchRemoveModal.message', {
        count: members.length,
        projectName: projectId,
      })
    : t('projects.detail.membersPage.removeModal.message', {
        userName: members[0]?.memberName ?? '',
        role: getRoleLabel(t, members[0]?.role),
        projectName: projectId,
      })

  const handleConfirm = async () => {
    if (members.length === 0) {
      return
    }

    await mutation.mutateAsync({
      name: projectId,
      members: members.map(m => ({
        memberType: m.memberType,
        memberId: m.memberId,
      })),
    })
    onClose()
  }

  return (
    <ModalWrapper
      opened={opened}
      onClose={onClose}
      type="danger"
      title={title}
      confirmLoading={mutation.isPending}
      onConfirm={handleConfirm}
    >
      <Text size="sm">{message}</Text>
    </ModalWrapper>
  )
}
