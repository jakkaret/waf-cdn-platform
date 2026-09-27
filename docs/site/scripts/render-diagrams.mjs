// Render every docs/diagrams/*.mmd to SVG + PNG with the real Mermaid library
// in a headless browser. Doubles as a syntax check: a diagram that fails to
// parse is reported and the script exits non-zero.
import { chromium } from 'playwright'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const DIAG = path.resolve(here, '../../diagrams')
const OUT = path.join(DIAG, 'rendered')
fs.mkdirSync(OUT, { recursive: true })
const mermaidJs = fs.readFileSync(path.resolve(here, '../node_modules/mermaid/dist/mermaid.min.js'), 'utf8')

const browser = await chromium.launch({ channel: process.env.PW_CHANNEL || 'chrome' })
const page = await browser.newPage({ deviceScaleFactor: 2, viewport: { width: 1600, height: 1200 } })
await page.setContent(`<html><head><meta charset="utf-8"><style>body{margin:0;background:#fff;font-family:Tahoma,sans-serif}#c{display:inline-block;padding:16px}</style></head><body><div id="c"></div></body></html>`)
await page.addScriptTag({ content: mermaidJs })
await page.evaluate(() => window.mermaid.initialize({ startOnLoad: false, theme: 'default', securityLevel: 'strict', fontFamily: 'Tahoma, sans-serif', flowchart: { htmlLabels: true, useMaxWidth: false }, sequence: { useMaxWidth: false }, er: { useMaxWidth: false } }))

const files = fs.readdirSync(DIAG).filter((f) => f.endsWith('.mmd')).sort()
const failed = []
const meta = {}
for (const f of files) {
  const src = fs.readFileSync(path.join(DIAG, f), 'utf8')
  const id = 'd' + f.replace(/\W/g, '')
  const res = await page.evaluate(async ([id, src]) => {
    try {
      const { svg } = await window.mermaid.render(id, src)
      document.getElementById('c').innerHTML = svg
      const el = document.querySelector('#c svg')
      const vb = el.viewBox && el.viewBox.baseVal
      if (vb && vb.width) { el.setAttribute('width', vb.width); el.setAttribute('height', vb.height); el.style.maxWidth = 'none' }
      const r = el.getBoundingClientRect()
      return { ok: true, svg, w: r.width, h: r.height }
    } catch (e) {
      return { ok: false, err: String(e && e.message || e) }
    }
  }, [id, src])
  if (!res.ok) { failed.push(`${f}: ${res.err.split('\n')[0]}`); continue }
  const base = f.replace(/\.mmd$/, '')
  fs.writeFileSync(path.join(OUT, base + '.svg'), res.svg)
  await page.locator('#c').screenshot({ path: path.join(OUT, base + '.png') })
  meta[base] = { width: Math.round(res.w), height: Math.round(res.h) }
  console.log(`ok  ${f}  ${Math.round(res.w)}x${Math.round(res.h)}`)
}
fs.writeFileSync(path.join(OUT, 'meta.json'), JSON.stringify(meta, null, 2))
await browser.close()
if (failed.length) { console.error('FAILED:\n' + failed.join('\n')); process.exit(1) }
console.log(`rendered ${files.length} diagrams`)
