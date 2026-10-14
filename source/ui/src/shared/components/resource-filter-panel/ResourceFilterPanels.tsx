import { Tabs } from '@mantine/core'

import type { FilterTabDefinition } from './types.ts'

interface ResourceFilterPanelProps {
  tabs: FilterTabDefinition[]
  activeTab: string
  onTabChange: (nextTab: string) => void
}

export function ResourceFilterPanels({
  tabs,
  activeTab,
  onTabChange,
}: ResourceFilterPanelProps) {
  const currentTab = tabs.find(tab => tab.value === activeTab)
    ? activeTab
    : tabs[0]?.value

  return (
    <Tabs
      value={currentTab}
      onChange={value => value && onTabChange(value)}
    >
      <Tabs.List>
        {
          tabs.map(tab => (
            <Tabs.Tab
              key={tab.value}
              value={tab.value}
            >
              {tab.label}
            </Tabs.Tab>
          ))
        }
      </Tabs.List>

      {
        tabs.map(tab => (
          <Tabs.Panel key={tab.value} value={tab.value}>
            {tab.panel}
          </Tabs.Panel>
        ))
      }
    </Tabs>
  )
}
