import { createFileRoute } from '@tanstack/react-router'

export const Route = createFileRoute(
  '/(auth)/(app)/projects_/$projectId/datasets/$datasetId/commit/$commitId/',
)({
  component: RouteComponent,
})

function RouteComponent() {
  const {
    projectId, datasetId, commitId,
  } = Route.useParams()

  return (
    <div>
      Dataset Commit Details
      <br />
      Project ID:
      {' '}
      {projectId}
      <br />
      Dataset ID:
      {' '}
      {datasetId}
      <br />
      Commit ID:
      {' '}
      {commitId}
    </div>
  )
}
