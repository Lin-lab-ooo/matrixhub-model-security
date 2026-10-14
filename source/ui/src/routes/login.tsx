import { createFileRoute, redirect } from '@tanstack/react-router'

import { currentUserQueryOptions } from '@/features/auth/auth.query'
import { LoginPage } from '@/features/login/pages/LoginPage'
import { getErrorMessage, queryClient } from '@/queryClient'

const ALREADY_LOGGED_IN_ERROR_MESSAGE = 'ALREADY_LOGGED_IN'

export const Route = createFileRoute('/login')({
  component: LoginPage,
  beforeLoad: async () => {
    try {
      await queryClient.ensureQueryData(currentUserQueryOptions())

      throw Error(ALREADY_LOGGED_IN_ERROR_MESSAGE)
    } catch (e) {
      if (getErrorMessage(e) === ALREADY_LOGGED_IN_ERROR_MESSAGE) {
        throw redirect({ to: '/' })
      }
    }
  },
})
