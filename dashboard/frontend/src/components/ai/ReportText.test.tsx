import { describe, expect, it } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { ReportText } from './ReportText'

const html = (text: string) => renderToStaticMarkup(<ReportText text={text} />)

describe('ReportText', () => {
  it('renders section labels, items and inline code without raw markdown', () => {
    const out = html('**ข้อสังเกต**\n- IP `198.51.100.7` ยิง **120** ครั้ง\n- sqli เยอะสุด\n\n**สิ่งที่ควรทำ**\n1. บล็อก IP')
    expect(out).not.toContain('**')
    expect(out).not.toContain('`')
    expect(out.match(/<li>/g)).toHaveLength(3)
    expect(out).toContain('198.51.100.7</code>')
    expect(out).toContain('>ข้อสังเกต</p>')
  })

  it('never turns text into HTML', () => {
    expect(html('<img src=x onerror=alert(1)>')).not.toContain('<img')
  })
})
