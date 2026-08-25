import { create } from 'zustand'
import { persist } from 'zustand/middleware'

interface OriginFilterState {
  selectedOrigin: string // 'ALL' or specific domain/IP (e.g. 'juice.waf-it-kku.online', 'dvwa.waf-it-kku.online')
  selectedOriginLabel: string
  setSelectedOrigin: (origin: string, label: string) => void
}

export const useOriginFilterStore = create<OriginFilterState>()(
  persist(
    (set) => ({
      selectedOrigin: 'ALL',
      selectedOriginLabel: 'All Managed Origins (ทั้งหมด)',
      setSelectedOrigin: (selectedOrigin, selectedOriginLabel) =>
        set({ selectedOrigin, selectedOriginLabel }),
    }),
    {
      name: 'waf-origin-filter-storage',
    }
  )
)
