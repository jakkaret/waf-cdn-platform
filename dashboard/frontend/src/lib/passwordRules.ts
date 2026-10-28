// The password rule of the sign-up and reset forms. The backend checks the
// same four things on reset (api/auth.py _password_problem).
export const passwordChecks = [
  { label: '8+ characters', labelTh: 'อย่างน้อย 8 ตัวอักษร', test: (value: string) => value.length >= 8 },
  { label: 'Uppercase letter', labelTh: 'ตัวพิมพ์ใหญ่', test: (value: string) => /[A-Z]/.test(value) },
  { label: 'Number', labelTh: 'ตัวเลข', test: (value: string) => /[0-9]/.test(value) },
  { label: 'Symbol', labelTh: 'อักขระพิเศษ', test: (value: string) => /[^A-Za-z0-9]/.test(value) },
]

export const passwordScore = (value: string) => passwordChecks.filter((check) => check.test(value)).length
