import { createFileRoute, redirect } from '@tanstack/react-router'

export const Route = createFileRoute('/(auth)/admin/')({
  beforeLoad: () => {
    throw redirect({
      to: '/admin/users',
    })
  },
})
