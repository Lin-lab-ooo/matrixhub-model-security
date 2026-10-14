import { Security } from '@matrixhub/api-ts/security/v1alpha1/security'
import { mutationOptions } from '@tanstack/react-query'

import i18n from '@/i18n'

import { securityKeys } from './security.query'

import type { NotificationMeta } from '@/types/tanstack-query'
import type {
  ModelScope, PolicyInput, ReviewInput,
} from '@matrixhub/api-ts/security/v1alpha1/security'

export function securityRescanMutationOptions(scope: ModelScope) {
  return mutationOptions({
    mutationFn: (revision: string) => Security.Rescan({
      ...scope,
      revision,
    }),
    meta: {
      errorMessage: i18n.t('security.rescanError'),
      invalidates: [securityKeys.repo(scope)],
    } satisfies NotificationMeta,
  })
}

export function securityCancelMutationOptions(scope: ModelScope) {
  return mutationOptions({
    mutationFn: (taskId: number) => Security.Cancel({
      ...scope,
      taskId,
    }),
    meta: {
      errorMessage: i18n.t('security.cancelError'),
      invalidates: [securityKeys.repo(scope)],
    } satisfies NotificationMeta,
  })
}

export function securityPolicyMutationOptions(scope: ModelScope) {
  return mutationOptions({
    mutationFn: (policy: PolicyInput) => Security.UpdatePolicy({
      ...scope,
      ...policy,
    }),
    meta: {
      errorMessage: i18n.t('security.policy.updateError'),
      invalidates: [securityKeys.repo(scope)],
    } satisfies NotificationMeta,
  })
}

export function securityAddReviewMutationOptions(scope: ModelScope, reportId: string) {
  return mutationOptions({
    mutationFn: (review: ReviewInput) => Security.AddReview({
      ...scope,
      reportId,
      ...review,
    }),
    meta: {
      errorMessage: i18n.t('security.reviews.saveError'),
      invalidates: [securityKeys.reviews(scope, reportId)],
    } satisfies NotificationMeta,
  })
}
