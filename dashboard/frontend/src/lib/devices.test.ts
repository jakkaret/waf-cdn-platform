import { describe, expect, it } from 'vitest'
import { describeUserAgent } from './devices'

describe('describeUserAgent', () => {
  it('names browser and system', () => {
    expect(describeUserAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36')).toBe('Chrome on macOS')
    expect(describeUserAgent('Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1')).toBe('Safari on iPhone')
    expect(describeUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36 Edg/130.0')).toBe('Edge on Windows')
    expect(describeUserAgent('Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0')).toBe('Firefox on Linux')
  })
  it('falls back gracefully', () => {
    expect(describeUserAgent('curl/8.7.1')).toBe('curl')
    expect(describeUserAgent('')).toBe('Unknown device')
    expect(describeUserAgent('some-custom-agent')).toBe('some-custom-agent')
  })
})
