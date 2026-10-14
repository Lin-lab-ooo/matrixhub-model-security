import { createFileRoute } from '@tanstack/react-router'

export const Route = createFileRoute(
  '/(auth)/(app)/projects_/$projectId/datasets/$datasetId/commits/$ref/',
)({
  component: RouteComponent,
})

function RouteComponent() {
  const {
    projectId, datasetId, ref,
  } = Route.useParams()

  return (
    <div>
      Dataset Commits History
      <br />
      Project ID:
      {' '}
      {projectId}
      <br />
      Dataset ID:
      {' '}
      {datasetId}
      <br />
      Ref:
      {' '}
      {ref}
    </div>
  )
}
