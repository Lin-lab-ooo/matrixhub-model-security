import { Anchor } from '@mantine/core'
import { ProjectRoleType } from '@matrixhub/api-ts/v1alpha1/role.pb'
import { useTranslation, Trans } from 'react-i18next'

const PROJECT_MEMBERS_DOC_URL = '/docs/operations/project-management/members/'

export const useProjectRoleOptions = () => {
  const { t } = useTranslation()

  return [
    {
      value: ProjectRoleType.ROLE_TYPE_PROJECT_ADMIN,
      label: t('projects.detail.membersPage.role.admin'),
    },
    {
      value: ProjectRoleType.ROLE_TYPE_PROJECT_EDITOR,
      label: t('projects.detail.membersPage.role.editor'),
    },
    {
      value: ProjectRoleType.ROLE_TYPE_PROJECT_VIEWER,
      label: t('projects.detail.membersPage.role.viewer'),
    },
  ]
}

export const useProjectRoleDescription = () => {
  const { t } = useTranslation()

  return (
    <Trans
      i18nKey="projects.detail.membersPage.roleDescription.hint"
      components={[
        <Anchor
          key="doc"
          href={t('common.docs', { doc: PROJECT_MEMBERS_DOC_URL })}
          target="_blank"
          rel="noopener noreferrer"
          inherit
        />,
      ]}
    />
  )
}
