import { ProjectRoleType } from '@matrixhub/api-ts/v1alpha1/role.pb'
import { createFileRoute } from '@tanstack/react-router'

import { ProjectSettingsPage } from '@/features/projects/pages/ProjectSettingsPage'
import { ensureProjectAccess } from '@/utils/routerAccess'

export const Route = createFileRoute(
  '/(auth)/(app)/projects/$projectId/settings/',
)({
  beforeLoad: async ({ params }) => {
    await ensureProjectAccess(params.projectId, {
      allowedRoles: [ProjectRoleType.ROLE_TYPE_PROJECT_ADMIN],
    })
  },
  component: ProjectSettingsPage,
})
