import type { SecurityReport } from '@matrixhub/api-ts/security/v1alpha1/security'
import type { Commit } from '@matrixhub/api-ts/v1alpha1/model.pb'

export function immutableCommitOptions(commits: Commit[], label: (commit: Commit) => string) {
  const seen = new Set<string>()

  return commits.flatMap((commit) => {
    const id = commit.id

    if (!id || !/^[0-9a-f]{40}$/.test(id) || seen.has(id)) {
      return []
    }
    seen.add(id)

    return [{
      value: id,
      label: label(commit),
    }]
  })
}

// A report for a different commit must never be shown under the selected SHA,
// including cached responses or a server/proxy returning an unexpected body.
export function reportMatchesRevision(report: SecurityReport | undefined, revision: string) {
  return !report || !/^[0-9a-f]{40}$/.test(revision) || report.revision === revision
}

export function currentRevisionReport(report: SecurityReport | undefined, revision: string, fetching: boolean, failed = false) {
  return failed || fetching || !reportMatchesRevision(report, revision) ? undefined : report
}
