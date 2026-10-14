import { createFileRoute } from '@tanstack/react-router'

import { SecurityPage } from '@/features/profile/pages/SecurityPage'

export const Route = createFileRoute('/(auth)/(app)/profile/security')({
  component: SecurityPage,
})
