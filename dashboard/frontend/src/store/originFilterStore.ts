import { create } from 'zustand'
import { persist } from 'zustand/middleware'

interface OriginFilterState {
  selectedOrigin: string // 'ALL' or an origin id
  selectedOriginLabel: string
  setSelectedOrigin: (origin: string, label: string) => void
}

const ALL_ORIGINS = { selectedOrigin: 'ALL', selectedOriginLabel: 'All Managed Origins (ทั้งหมด)' }

// Version 0 stored the origin's ip (or domain). Two origins can share an ip,
// so the selection is now an origin id; an old value starts again from ALL.
export const migrateOriginFilter = (persisted: unknown, version: number) =>
  (version < 1 ? ALL_ORIGINS : persisted) as OriginFilterState

export const useOriginFilterStore = create<OriginFilterState>()(
  persist(
    (set) => ({
      ...ALL_ORIGINS,
      setSelectedOrigin: (selectedOrigin, selectedOriginLabel) =>
        set({ selectedOrigin, selectedOriginLabel }),
    }),
    {
      name: 'waf-origin-filter-storage',
      version: 1,
      migrate: migrateOriginFilter,
    }
  )
)
