import { createFileRoute } from '@tanstack/react-router'

import { ModelReadmePage } from '@/features/models/pages/ModelReadmePage'

export const Route = createFileRoute('/(auth)/(app)/projects_/$projectId/models/$modelId/')({
  component: ModelReadmePage,
})
