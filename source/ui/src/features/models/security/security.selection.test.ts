import { Security } from '@matrixhub/api-ts/security/v1alpha1/security'
import { QueryClient, QueryObserver } from '@tanstack/react-query'
import {
  afterEach, describe, expect, it, vi,
} from 'vitest'

import { securityReportQueryOptions } from './security.query'

import type { SecurityReport } from '@matrixhub/api-ts/security/v1alpha1/security'

afterEach(() => {
  vi.restoreAllMocks()
})

describe('security query revision isolation', () => {
  it('clears an old successful report while a newly selected commit is pending', async () => {
    const first = 'a'.repeat(40)
    const next = 'b'.repeat(40)
    const scope = {
      namespace: 'project',
      name: 'model',
    }
    let resolveNext: (value: SecurityReport) => void = () => {
      throw new Error('Missing resolver')
    }
    const pending = new Promise<SecurityReport>((resolve) => {
      resolveNext = resolve
    })
    const report = {
      revision: first,
      state: 'pass',
    } as SecurityReport
    const request = vi.spyOn(Security, 'Report').mockImplementation(input => input.revision === first ? Promise.resolve(report) : pending)
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    const observer = new QueryObserver(client, securityReportQueryOptions(scope, first))
    const observations: (string | undefined)[] = []
    const unsubscribe = observer.subscribe(result => observations.push(result.data?.revision))

    try {
      await vi.waitFor(() => expect(observer.getCurrentResult().data?.revision).toBe(first))
      observer.setOptions(securityReportQueryOptions(scope, next))
      expect(observer.getCurrentResult().data).toBeUndefined()
      expect(observer.getCurrentResult().isPending).toBe(true)
      expect(observations.at(-1)).toBeUndefined()
      expect(request.mock.calls.at(-1)?.[0].revision).toBe(next)
      resolveNext({
        ...report,
        revision: next,
      })
      await vi.waitFor(() => expect(observer.getCurrentResult().data?.revision).toBe(next))
      expect(client.getQueryData(securityReportQueryOptions(scope, first).queryKey)).toEqual(report)
    } finally {
      unsubscribe()
      client.clear()
    }
  })
})
