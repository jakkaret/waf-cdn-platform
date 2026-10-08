import { useEffect, useState } from 'react'

// Returns `value` only after it has stopped changing for `delayMs`. Used to
// keep per-keystroke input from firing a request per keystroke (F-104).
export function useDebouncedValue<T>(value: T, delayMs = 400): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delayMs)
    return () => clearTimeout(t)
  }, [value, delayMs])
  return debounced
}
