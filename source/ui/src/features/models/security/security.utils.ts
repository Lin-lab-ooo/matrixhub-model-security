import type { SecurityReport, SecurityState } from '@matrixhub/api-ts/security/v1alpha1/security'

export function hasCompleteCoverage(report: SecurityReport) {
  const files = report.files ?? []

  return report.complete
    && /^[1-9][0-9]*-[1-9][0-9]*$/.test(report.reportId)
    && report.reportId === `${report.taskId}-${report.attempt}`
    && /^[0-9a-f]{40}$/.test(report.revision)
    && report.generation !== ''
    && Number.isInteger(report.expectedFiles)
    && report.expectedFiles >= 0
    && report.expectedFiles === files.length
    && new Set(files.map(file => file.path)).size === files.length
    && files.every(file => file.complete
      && file.path !== ''
      && file.generation === report.generation
      && file.size >= 0 && file.size === file.declaredSize
      && /^[0-9a-f]{64}$/.test(file.sha256)
      && file.artifactId !== ''
      && Object.keys(file.engines ?? {}).length >= 2)
}

export function visibleReportState(report: SecurityReport | undefined, fetching: boolean): SecurityState {
  if (!report) {
    return 'pending'
  }
  if (fetching) {
    return 'scanning'
  }
  if ((report.state === 'pass' || report.state === 'warn' || report.state === 'block') && !hasCompleteCoverage(report)) {
    return 'fail'
  }
  if (!['pending', 'scanning', 'pass', 'warn', 'block', 'fail'].includes(report.state)) {
    return 'fail'
  }

  return report.state
}
