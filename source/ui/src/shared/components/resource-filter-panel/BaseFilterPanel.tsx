import {
  Group,
  Loader,
  Stack,
  Text,
} from '@mantine/core'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'

import { SearchInput } from '@/shared/components/SearchInput'

import type { ReactNode } from 'react'

interface BaseFilterTabProps {
  loading: boolean
  searchPlaceholder: string
  children?: (params: { keyword: string }) => ReactNode
}

export function BaseFilterPanel({
  searchPlaceholder,
  children,
  loading,
}: BaseFilterTabProps) {
  const { t } = useTranslation()
  const [keyword, setKeyword] = useState('')
  const content = children?.({ keyword }) ?? null

  return (
    <Stack mt="md" gap="lg">
      <SearchInput
        value={keyword}
        placeholder={searchPlaceholder}
        onChange={setKeyword}
        w="100%"
      />

      {loading
        ? (
            <Group justify="center">
              <Loader size="sm" />
            </Group>
          )
        : null}

      {!loading && !content
        ? (
            <Group justify="center">
              <Text c="dimmed" size="sm">
                {t('common.noResults')}
              </Text>
            </Group>
          )
        : null}

      {!loading ? content : null}
    </Stack>
  )
}
