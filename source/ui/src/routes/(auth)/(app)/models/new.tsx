import { createFileRoute } from '@tanstack/react-router'
import { z } from 'zod'

import ModelCreatePage from '@/features/models/pages/ModelCreatePage'

const modelCreateSearchSchema = z.object({
  projectId: z.string().trim().optional().catch(undefined),
})

export const Route = createFileRoute(
  '/(auth)/(app)/models/new',
)({
  validateSearch: modelCreateSearchSchema,
  component: RouteComponent,
})

function RouteComponent() {
  const { projectId } = Route.useSearch()

  return <ModelCreatePage initialProjectId={projectId} />
}
