import { describe, expect, it } from 'vitest'
import { migrateOriginFilter } from './originFilterStore'

describe('origin filter storage', () => {
  it('drops a selection saved as an ip by the old version', () => {
    const old = { selectedOrigin: '216.198.79.1', selectedOriginLabel: 'demo1.originweb.site' }
    expect(migrateOriginFilter(old, 0)).toMatchObject({ selectedOrigin: 'ALL' })
  })

  it('keeps a selection saved as an origin id', () => {
    const saved = { selectedOrigin: '59616f02-cdac-4e69-ac86-dfe9250cd3ac', selectedOriginLabel: 'www.demo2' }
    expect(migrateOriginFilter(saved, 1)).toBe(saved)
  })
})
