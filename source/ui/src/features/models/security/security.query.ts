import { Security } from '@matrixhub/api-ts/security/v1alpha1/security'
import { queryOptions } from '@tanstack/react-query'

import type { ModelScope } from '@matrixhub/api-ts/security/v1alpha1/security'

export const securityKeys = {
  all: ['modelSecurity'] as const,
  repo: (scope: ModelScope) => [...securityKeys.all, scope.namespace, scope.name] as const,
  report: (scope: ModelScope, revision: string) => [...securityKeys.repo(scope), 'report', revision] as const,
  history: (scope: ModelScope, reportId: string) => [...securityKeys.repo(scope), 'history', reportId] as const,
  reviews: (scope: ModelScope, reportId: string) => [...securityKeys.repo(scope), 'reviews', reportId] as const,
  reviewPage: (scope: ModelScope, reportId: string, offset: number) => [...securityKeys.reviews(scope, reportId), offset] as const,
  tasks: (scope: ModelScope, offset: number) => [...securityKeys.repo(scope), 'tasks', offset] as const,
  audits: (scope: ModelScope, offset: number) => [...securityKeys.repo(scope), 'audits', offset] as const,
  policy: (scope: ModelScope) => [...securityKeys.repo(scope), 'policy'] as const,
}

export function securityReportQueryOptions(scope: ModelScope, revision: string) {
  return queryOptions({
    queryKey: securityKeys.report(scope, revision),
    queryFn: () => Security.Report({
      ...scope,
      revision,
    }),
    staleTime: 0,
    refetchOnWindowFocus: true,
    refetchInterval: (query) => {
      if (query.state.status === 'error') {
        return false
      }

      const state = query.state.data?.state

      return state === 'pending' || state === 'scanning' ? 2000 : 15000
    },
  })
}

export function securityHistoryQueryOptions(scope: ModelScope, reportId: string) {
  return queryOptions({
    queryKey: securityKeys.history(scope, reportId),
    queryFn: () => Security.History({
      ...scope,
      reportId,
    }),
    staleTime: Infinity,
    enabled: reportId !== '',
  })
}

export function securityTasksQueryOptions(scope: ModelScope, offset: number) {
  return queryOptions({
    queryKey: securityKeys.tasks(scope, offset),
    queryFn: () => Security.Tasks({
      ...scope,
      limit: 50,
      offset,
    }),
    refetchInterval: 5000,
  })
}

export function securityReviewsQueryOptions(scope: ModelScope, reportId: string, offset: number) {
  return queryOptions({
    queryKey: securityKeys.reviewPage(scope, reportId, offset),
    queryFn: () => Security.Reviews({
      ...scope,
      reportId,
      limit: 50,
      offset,
    }),
    enabled: reportId !== '',
    staleTime: 0,
  })
}

export function securityAuditsQueryOptions(scope: ModelScope, offset: number) {
  return queryOptions({
    queryKey: securityKeys.audits(scope, offset),
    queryFn: () => Security.Audits({
      ...scope,
      limit: 50,
      offset,
    }),
    refetchInterval: 10000,
  })
}

export function securityPolicyQueryOptions(scope: ModelScope) {
  return queryOptions({
    queryKey: securityKeys.policy(scope),
    queryFn: () => Security.Policy(scope),
  })
}
