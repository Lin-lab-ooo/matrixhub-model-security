import type { SecurityReport } from '@matrixhub/api-ts/security/v1alpha1/security'

/** A failed terminal report may be reviewed; an unresolved placeholder may not. */
export function isReviewableReport(report: SecurityReport | undefined): report is SecurityReport {
  return !!report
    && /^[1-9]\d*-[1-9]\d*$/.test(report.reportId) && report.reportId.length <= 64
    && /^[a-f\d]{40}$/.test(report.revision)
    && /^[a-f\d]{64}$/.test(report.generation)
    && ['pass', 'warn', 'block', 'fail'].includes(report.state)
}
