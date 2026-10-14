import { createFileRoute } from '@tanstack/react-router'

export const Route = createFileRoute(
  '/(auth)/(app)/projects/$projectId/datasets/',
)({
  component: RouteComponent,
})

function RouteComponent() {
  return <div>Hello "/_layout/(app)/projects/$projectId/datasets/"!</div>
}
