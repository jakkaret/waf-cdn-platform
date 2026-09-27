// Build the PDF manual: render the same Markdown (same order as the DOCX) to
// one print-styled HTML file with Mermaid SVGs inlined, then print it with
// headless Chrome. No Word automation, so it runs unattended.
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import matter from 'gray-matter'
import { marked } from 'marked'
import { chromium } from 'playwright'

const here = path.dirname(fileURLToPath(import.meta.url))
const DOCS = path.resolve(here, '../..')
const DIAG = path.join(DOCS, 'diagrams')
const RENDERED = path.join(DIAG, 'rendered')
const VERSION = process.env.DOC_VERSION || '1.0'
const DATE = process.env.DOC_DATE || '2026-09-28'
const COMMIT = process.env.DOC_COMMIT || 'c033758'

const PARTS = [
  ['Part I — Introduction', ['book']], ['Part II — Infrastructure', ['infrastructure']],
  ['Part III — Backend', ['backend']], ['Part IV — WAF', ['waf']], ['Part V — CDN', ['cdn']],
  ['Part VI — Frontend', ['frontend']], ['Part VII — Complete Data Flows', ['workflows']],
  ['Part VIII — Operations', ['operations']], ['Part IX — Testing', ['testing']],
  ['ภาคผนวก (Appendices)', ['SYSTEM_FACTS.md', 'IMPLEMENTATION_STATUS.md', 'reference/api-reference.md', 'reference/database-reference.md', 'reference/glossary.md', 'DOCUMENTATION_TRACEABILITY.md']],
]
const filesFor = (entries) => entries.flatMap((e) => {
  const p = path.join(DOCS, e)
  if (e.endsWith('.md')) return [p]
  let f = fs.readdirSync(p).filter((x) => x.endsWith('.md')).sort()
  if (e === 'workflows') f = ['end-to-end.md', ...f.filter((x) => x !== 'end-to-end.md')]
  return f.map((x) => path.join(p, x))
})

const norm = (s) => s.replace(/\s+/g, ' ').trim()
const svgBySource = new Map()
for (const f of fs.readdirSync(DIAG).filter((f) => f.endsWith('.mmd'))) {
  const svg = path.join(RENDERED, f.replace(/\.mmd$/, '.svg'))
  if (fs.existsSync(svg)) svgBySource.set(norm(fs.readFileSync(path.join(DIAG, f), 'utf8')), fs.readFileSync(svg, 'utf8'))
}

const renderer = new marked.Renderer()
renderer.code = ({ text, lang }) => {
  if (lang === 'mermaid') {
    const svg = svgBySource.get(norm(text))
    if (svg) return `<figure class="diagram">${svg}</figure>`
  }
  const esc = text.replace(/&/g, '&amp;').replace(/</g, '&lt;')
  return `<pre><code>${esc}</code></pre>`
}
let hid = 0
const toc = []
renderer.heading = function ({ tokens, depth }) {
  const text = this.parser.parseInline(tokens)
  const id = `h${++hid}`
  if (depth <= 2) toc.push({ depth, id, text: text.replace(/<[^>]+>/g, '') })
  return `<h${depth} id="${id}">${text}</h${depth}>`
}
marked.use({ renderer })

let body = ''
for (const [part, entries] of PARTS) {
  body += `<section class="part"><h1 class="partname">${part}</h1></section>`
  for (const f of filesFor(entries)) {
    const { content } = matter(fs.readFileSync(f, 'utf8'))
    let html = marked.parse(content)
    html = html.replace(/\b(VERIFIED|PARTIAL|PLANNED|UNKNOWN|DEPRECATED)\b/g, '<span class="st st-$1">$1</span>')
    body += `<section class="chapter">${html}</section>`
  }
}
const tocHtml = toc.map((t) => `<li class="d${t.depth}"><a href="#${t.id}">${t.text}</a></li>`).join('')

const html = `<!doctype html><html lang="th"><head><meta charset="utf-8"><title>WAF + CDN Security Platform — System Manual</title>
<style>
@page { size: A4; margin: 20mm 17mm 20mm 17mm; }
body { font-family: Tahoma, 'Sukhumvit Set', sans-serif; font-size: 10pt; line-height: 1.55; color: #111827; }
h1 { font-size: 20pt; color: #1F3A8A; margin: 0 0 10pt; } h2 { font-size: 14pt; margin: 16pt 0 6pt; break-after: avoid; }
h3 { font-size: 12pt; margin: 12pt 0 4pt; break-after: avoid; } h4 { font-size: 11pt; }
.cover { height: 250mm; display: flex; flex-direction: column; justify-content: center; text-align: center; break-after: page; }
.cover .t { font-size: 30pt; font-weight: bold; } .cover .s { font-size: 18pt; color: #374151; margin: 8pt 0 60pt; }
.part { break-before: page; break-after: page; height: 240mm; display: flex; align-items: center; justify-content: center; }
.partname { font-size: 28pt; } .chapter { break-before: page; }
table { width: 100%; border-collapse: collapse; margin: 6pt 0 10pt; font-size: 8.5pt; page-break-inside: auto; }
th, td { border: 1px solid #D1D5DB; padding: 3pt 5pt; vertical-align: top; } th { background: #E8EEF7; }
tr { break-inside: avoid; } thead { display: table-header-group; }
code { font-family: Menlo, Consolas, monospace; font-size: 8.5pt; background: #F1F3F5; padding: 0 2pt; border-radius: 2pt; }
pre { background: #F6F8FA; border: 1px solid #D0D7DE; border-left: 3pt solid #D0D7DE; padding: 6pt 8pt; white-space: pre-wrap; word-break: break-word; break-inside: avoid; }
pre code { background: none; padding: 0; }
blockquote { background: #FFF8E6; border-left: 4pt solid #F59E0B; margin: 8pt 0; padding: 4pt 10pt; }
figure.diagram { text-align: center; margin: 8pt 0 2pt; break-inside: avoid; } figure.diagram svg { max-width: 100%; height: auto; max-height: 200mm; }
p > em:only-child { display: block; text-align: center; color: #374151; }
.st { font-weight: bold; } .st-VERIFIED { color: #1B7F3B; } .st-PARTIAL { color: #B26A00; } .st-PLANNED { color: #5B5BD6; } .st-UNKNOWN { color: #6B7280; } .st-DEPRECATED { color: #B42318; }
.toc { break-after: page; } .toc ul { list-style: none; padding: 0; } .toc li.d1 { font-weight: bold; margin-top: 4pt; } .toc li.d2 { margin-left: 14pt; font-size: 9pt; }
.toc a, a { color: #1D4ED8; text-decoration: none; }
.rev { break-after: page; }
</style></head><body>
<div class="cover"><div class="t">WAF + CDN Security Platform</div><div class="s">คู่มือระบบ (System Manual)</div>
<div>เวอร์ชันเอกสาร ${VERSION} · ${DATE}</div><div style="color:#4B5563;margin-top:6pt">อ้างอิงระบบจริง ณ commit ${COMMIT} (branch Backend)</div>
<div style="color:#B42318;margin-top:60pt">เอกสารภายใน — ไม่มีรหัสผ่าน คีย์ หรือ token ใดๆ</div></div>
<div class="rev"><h1>ประวัติการแก้ไข (Revision History)</h1><table><tr><th>เวอร์ชัน</th><th>วันที่</th><th>รายละเอียด</th><th>ผู้จัดทำ</th></tr>
<tr><td>${VERSION}</td><td>${DATE}</td><td>ฉบับแรก: reverse-engineer จากระบบจริง (3 VM, 13 containers), 51 บท + Data flows + ภาคผนวก</td><td>ทีมพัฒนา + Claude</td></tr></table></div>
<div class="toc"><h1>สารบัญ (Table of Contents)</h1><ul>${tocHtml}</ul></div>
${body}</body></html>`

const OUT = path.join(DOCS, 'dist')
fs.mkdirSync(OUT, { recursive: true })
const htmlPath = path.join(OUT, 'manual-print.html')
fs.writeFileSync(htmlPath, html)
const browser = await chromium.launch({ channel: process.env.PW_CHANNEL || 'chrome' })
const page = await browser.newPage()
await page.goto('file://' + htmlPath, { waitUntil: 'load' })
const pdf = path.join(OUT, `WAF-CDN-System-Manual-v${VERSION}.pdf`)
await page.pdf({
  path: pdf, format: 'A4', printBackground: true, displayHeaderFooter: true,
  margin: { top: '20mm', bottom: '20mm', left: '17mm', right: '17mm' },
  headerTemplate: `<div style="font-size:7pt;color:#6B7280;width:100%;text-align:right;padding-right:17mm;font-family:Tahoma">WAF + CDN Security Platform — คู่มือระบบ v${VERSION}</div>`,
  footerTemplate: `<div style="font-size:7pt;color:#6B7280;width:100%;text-align:center;font-family:Tahoma">หน้า <span class="pageNumber"></span> / <span class="totalPages"></span></div>`,
})
await browser.close()
console.log(`wrote ${pdf}`)
