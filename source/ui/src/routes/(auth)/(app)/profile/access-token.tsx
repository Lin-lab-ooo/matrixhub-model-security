import { createFileRoute } from '@tanstack/react-router'

import { AccessTokenPage } from '@/features/profile/pages/AccessTokenPage'
import { accessTokensQueryOptions } from '@/features/profile/profile.query'

export const Route = createFileRoute('/(auth)/(app)/profile/access-token')({
  loader: ({ context }) => {
    context.queryClient.prefetchQuery(accessTokensQueryOptions())
  },
  component: AccessTokenPage,
})
