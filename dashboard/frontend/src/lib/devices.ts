// Human labels for the signed-in devices page (from the stored User-Agent).

export interface DeviceSession {
  session_id: string
  created_at: string
  last_seen_at: string
  expires_at: string
  user_agent: string
  ip: string
  current: boolean
}

const BROWSERS: [RegExp, string][] = [
  [/Edg\//, 'Edge'],
  [/OPR\/|Opera/, 'Opera'],
  [/Firefox\//, 'Firefox'],
  [/Chrome\/|CriOS\//, 'Chrome'],
  [/Safari\//, 'Safari'],
  [/curl\//i, 'curl'],
  [/python/i, 'Python script'],
]

const SYSTEMS: [RegExp, string][] = [
  [/iPhone/, 'iPhone'],
  [/iPad/, 'iPad'],
  [/Android/, 'Android'],
  [/Windows/, 'Windows'],
  [/Mac OS X|Macintosh/, 'macOS'],
  [/Linux/, 'Linux'],
]

export function describeUserAgent(ua: string): string {
  const text = ua || ''
  const browser = BROWSERS.find(([re]) => re.test(text))?.[1]
  const system = SYSTEMS.find(([re]) => re.test(text))?.[1]
  if (browser && system) return `${browser} on ${system}`
  return browser || system || (text ? text.slice(0, 60) : 'Unknown device')
}
