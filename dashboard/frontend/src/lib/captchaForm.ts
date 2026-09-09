// Turns a textarea's raw text into the string[] the backend's CaptchaShieldConfig
// expects for login_paths / bypass_ips: one entry per line or comma, trimmed,
// emptied lines dropped, duplicates collapsed while keeping first-seen order.
export function parseListInput(raw: string): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const part of raw.split(/[\n,]/)) {
    const value = part.trim()
    if (!value || seen.has(value)) continue
    seen.add(value)
    out.push(value)
  }
  return out
}

// Inverse of parseListInput, for populating the textarea from a loaded config.
export function formatListInput(values: string[]): string {
  return values.join('\n')
}
