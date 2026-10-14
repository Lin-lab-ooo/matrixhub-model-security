import { resetFetchFn, setFetchFn } from '@matrixhub/api-ts/fetch.pb'
import { Security } from '@matrixhub/api-ts/security/v1alpha1/security'
import {
  afterEach, describe, expect, it, vi,
} from 'vitest'

import { securityAddReviewMutationOptions } from './security.mutation'
import { securityKeys, securityReviewsQueryOptions } from './security.query'
import { isReviewableReport } from './security.reviews'
import { reviewFormSchema } from './security.schema'

import type { SecurityReport } from '@matrixhub/api-ts/security/v1alpha1/security'

vi.mock('@/i18n', () => ({ default: { t: (key: string) => key } }))

const scope = {
  namespace: 'team',
  name: 'model',
}

function report(state: SecurityReport['state'] = 'block'): SecurityReport {
  return {
    reportId: '12-2',
    attempt: 2,
    taskId: 12,
    repo: 'team/model',
    revision: 'a'.repeat(40),
    generation: 'b'.repeat(64),
    state,
    complete: false,
    expectedFiles: 1,
    files: [],
    error: 'controlled-fixture',
    createdAt: '2026-10-14T00:00:00Z',
    finishedAt: '2026-10-14T00:00:01Z',
    durationMs: 1,
    scannedBytes: 0,
    cachedFiles: 0,
  }
}

afterEach(() => resetFetchFn())

describe('append-only security reviews', () => {
  it('requires a terminal immutable report identity, including failed incomplete reports', () => {
    for (const state of ['pass', 'warn', 'block', 'fail'] as const) {
      expect(isReviewableReport(report(state))).toBe(true)
    }
    for (const state of ['pending', 'scanning'] as const) {
      expect(isReviewableReport(report(state))).toBe(false)
    }
    expect(isReviewableReport(undefined)).toBe(false)
    expect(isReviewableReport({
      ...report(),
      reportId: 'pending',
    })).toBe(false)
    expect(isReviewableReport({
      ...report(),
      reportId: '',
    })).toBe(false)
    expect(isReviewableReport({
      ...report(),
      revision: 'main',
    })).toBe(false)
    expect(isReviewableReport({
      ...report(),
      revision: 'a'.repeat(41),
    })).toBe(false)
    expect(isReviewableReport({
      ...report(),
      generation: '',
    })).toBe(false)
  })

  it('counts Unicode code points and trims whitespace without changing the verdict', () => {
    expect(reviewFormSchema.parse({
      verdict: 'false_positive',
      comment: ` ${'😀'.repeat(1000)} `,
    }).comment).toHaveLength(2000)
    expect(reviewFormSchema.safeParse({
      verdict: 'confirmed_risk',
      comment: '😀'.repeat(1001),
    }).success).toBe(false)
    expect(reviewFormSchema.safeParse({
      verdict: 'needs_followup',
      comment: ' \n\t ',
    }).success).toBe(false)
    expect(reviewFormSchema.safeParse({
      verdict: 'allow_download',
      comment: 'not an override',
    }).success).toBe(false)
  })

  it('rejects NUL comments before making a server request', () => {
    expect(reviewFormSchema.safeParse({
      verdict: 'needs_followup',
      comment: 'note\0text',
    }).success).toBe(false)
  })

  it('separates review caches by repository and report and never invalidates machine queries', () => {
    const mutation = securityAddReviewMutationOptions(scope, '12-2')
    const reviewKey = securityKeys.reviews(scope, '12-2')

    expect(mutation.meta?.invalidates).toEqual([reviewKey])
    expect(reviewKey).not.toEqual(securityKeys.reviews({
      ...scope,
      namespace: 'other',
    }, '12-2'))
    expect(reviewKey).not.toEqual(securityKeys.reviews(scope, '12-3'))
    expect(securityKeys.reviewPage(scope, '12-2', 50)).toEqual([...reviewKey, 50])
    expect(securityReviewsQueryOptions(scope, '', 0).enabled).toBe(false)
  })

  it('binds POST to the selected report and sends only human annotation fields', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify({ id: 1 }), { status: 200 }))

    setFetchFn(fetcher)
    await Security.AddReview({
      namespace: 'team/with slash',
      name: 'model?x',
      reportId: '12/2',
      revision: 'a'.repeat(40),
      generation: 'generation-1',
      verdict: 'false_positive',
      comment: '<script>untrusted note text</script>',
    })
    const [url, init] = fetcher.mock.calls[0]

    expect(url).toBe('/api/security/v1alpha1/models/team%2Fwith%20slash/model%3Fx/history/12%2F2/reviews')
    expect(init?.method).toBe('POST')
    expect(JSON.parse(String(init?.body))).toEqual({
      revision: 'a'.repeat(40),
      generation: 'generation-1',
      verdict: 'false_positive',
      comment: '<script>untrusted note text</script>',
    })
    expect(new Headers(init?.headers).get('Content-Type')).toBe('application/json')
  })

  it('fetches only the selected historical report review page', async () => {
    const response = {
      items: [],
      count: 0,
      offset: 50,
      limit: 50,
      hasMore: false,
    }
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify(response), { status: 200 }))

    setFetchFn(fetcher)
    await expect(Security.Reviews({
      ...scope,
      reportId: '12-2',
      offset: 50,
      limit: 50,
    })).resolves.toEqual(response)
    const [url, init] = fetcher.mock.calls[0]

    expect(url).toBe('/api/security/v1alpha1/models/team/model/history/12-2/reviews?limit=50&offset=50')
    expect(init?.method).toBe('GET')
  })

  it('propagates denied writes instead of presenting an annotation as saved', async () => {
    setFetchFn(vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify({ code: 'Forbidden' }), { status: 403 })))
    await expect(Security.AddReview({
      ...scope,
      reportId: '12-2',
      revision: 'a'.repeat(40),
      generation: 'g',
      verdict: 'false_positive',
      comment: 'Not permitted',
    })).rejects.toEqual({ code: 'Forbidden' })
  })
})
