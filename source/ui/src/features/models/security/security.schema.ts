import { z } from 'zod'

import i18n from '@/i18n'

export const revisionSchema = z.string()
  .trim()
  .min(1, { error: () => i18n.t('security.revisionRequired') })
  .max(1024, { error: () => i18n.t('security.revisionInvalid') })
  .refine(value => !['\0', '\r', '\n'].some(character => value.includes(character)), {
    error: () => i18n.t('security.revisionInvalid'),
  })

export const policySchema = z.object({
  mode: z.enum(['enforce', 'audit'], { error: () => i18n.t('security.policyInvalid') }),
  blockSeverity: z.enum(['low', 'medium', 'high', 'critical'], { error: () => i18n.t('security.policyInvalid') }),
})

export const revisionFormSchema = z.object({ revision: revisionSchema })

export const reviewFormSchema = z.object({
  verdict: z.enum(['confirmed_risk', 'false_positive', 'needs_followup'], {
    error: () => i18n.t('security.reviews.verdictInvalid'),
  }),
  comment: z.string().trim().refine(value => !value.includes('\0') && Array.from(value).length >= 1 && Array.from(value).length <= 1000, {
    error: () => i18n.t('security.reviews.commentInvalid'),
  }),
})
