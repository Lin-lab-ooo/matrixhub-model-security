import type { ReactNode } from 'react'

export interface FilterTabDefinition {
  label: string
  value: string
  panel: ReactNode
}
