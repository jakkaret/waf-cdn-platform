// Build the system manual (DOCX) from the canonical Markdown in docs/.
// Chapters are read in book order; Mermaid blocks are replaced by the PNGs
// rendered by render-diagrams.mjs (run that first).
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import matter from 'gray-matter'
import { marked } from 'marked'
import {
  AlignmentType, BorderStyle, Document, Footer, Header, HeadingLevel, ImageRun, LevelFormat,
  PageBreak, PageNumber, PageOrientation, Packer, Paragraph, ShadingType, Table, TableCell,
  TableOfContents, TableRow, TextRun, WidthType,
} from 'docx'

const here = path.dirname(fileURLToPath(import.meta.url))
const DOCS = path.resolve(here, '../..')
const DIAG = path.join(DOCS, 'diagrams')
const RENDERED = path.join(DIAG, 'rendered')
const OUT_DIR = path.join(DOCS, 'dist')
fs.mkdirSync(OUT_DIR, { recursive: true })

const VERSION = process.env.DOC_VERSION || '1.0'
const DATE = process.env.DOC_DATE || '2026-09-28'
const COMMIT = process.env.DOC_COMMIT || 'c033758'
const FONT = 'Tahoma'
const MONO = 'Consolas'

const PARTS = [
  ['Part I — Introduction', ['book']],
  ['Part II — Infrastructure', ['infrastructure']],
  ['Part III — Backend', ['backend']],
  ['Part IV — WAF', ['waf']],
  ['Part V — CDN', ['cdn']],
  ['Part VI — Frontend', ['frontend']],
  ['Part VII — Complete Data Flows', ['workflows']],
  ['Part VIII — Operations', ['operations']],
  ['Part IX — Testing', ['testing']],
  ['ภาคผนวก (Appendices)', [
    'SYSTEM_FACTS.md', 'IMPLEMENTATION_STATUS.md', 'reference/api-reference.md',
    'reference/database-reference.md', 'reference/glossary.md', 'DOCUMENTATION_TRACEABILITY.md',
  ]],
]

function filesFor(entries) {
  const out = []
  for (const e of entries) {
    const p = path.join(DOCS, e)
    if (e.endsWith('.md')) out.push(p)
    else {
      let fs_ = fs.readdirSync(p).filter((f) => f.endsWith('.md')).sort()
      if (e === 'workflows') fs_ = ['end-to-end.md', ...fs_.filter((f) => f !== 'end-to-end.md')]
      out.push(...fs_.map((f) => path.join(p, f)))
    }
  }
  return out
}

// ---- diagrams: map Mermaid source -> rendered PNG --------------------------
const norm = (s) => s.replace(/\s+/g, ' ').trim()
const diagramBySource = new Map()
const meta = fs.existsSync(path.join(RENDERED, 'meta.json')) ? JSON.parse(fs.readFileSync(path.join(RENDERED, 'meta.json'), 'utf8')) : {}
for (const f of fs.readdirSync(DIAG).filter((f) => f.endsWith('.mmd'))) {
  diagramBySource.set(norm(fs.readFileSync(path.join(DIAG, f), 'utf8')), f.replace(/\.mmd$/, ''))
}

// ---- inline --------------------------------------------------------------
const ENT = { '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&#39;': "'", '&#x27;': "'" }
const unesc = (s) => String(s).replace(/&(amp|lt|gt|quot|#39|#x27);/g, (m) => ENT[m])
const STATUS_COLOR = { VERIFIED: '1B7F3B', PARTIAL: 'B26A00', PLANNED: '5B5BD6', UNKNOWN: '6B7280', DEPRECATED: 'B42318' }

function runs(tokens, style = {}) {
  const out = []
  for (const t of tokens || []) {
    switch (t.type) {
      case 'strong': out.push(...runs(t.tokens, { ...style, bold: true })); break
      case 'em': out.push(...runs(t.tokens, { ...style, italics: true })); break
      case 'del': out.push(...runs(t.tokens, { ...style, strike: true })); break
      case 'codespan': out.push(new TextRun({ text: unesc(t.text), font: MONO, size: 18, shading: { type: ShadingType.CLEAR, fill: 'F1F3F5', color: 'auto' }, ...style })); break
      case 'link': out.push(...runs(t.tokens, { ...style, color: '1D4ED8', underline: {} })); break
      case 'br': out.push(new TextRun({ break: 1 })); break
      case 'text':
      case 'escape':
        if (t.tokens) { out.push(...runs(t.tokens, style)); break }
        {
          const text = unesc(t.text)
          // colour status labels so they stand out in tables and prose
          const parts = text.split(/\b(VERIFIED|PARTIAL|PLANNED|UNKNOWN|DEPRECATED)\b/)
          for (const p of parts) {
            if (!p) continue
            if (STATUS_COLOR[p]) out.push(new TextRun({ text: p, bold: true, color: STATUS_COLOR[p], ...style }))
            else out.push(new TextRun({ text: p, ...style }))
          }
        }
        break
      case 'html': break
      default: if (t.text) out.push(new TextRun({ text: unesc(t.text), ...style }))
    }
  }
  return out
}

// ---- blocks --------------------------------------------------------------
const CAPTION_RE = /^\*รูปที่ (\d+) — (.+)\*$/
let tableNo = 0

function codeBlock(text) {
  const lines = unesc(text).split('\n')
  return lines.map((line, i) => new Paragraph({
    children: [new TextRun({ text: line || ' ', font: MONO, size: 17 })],
    shading: { type: ShadingType.CLEAR, fill: 'F6F8FA', color: 'auto' },
    border: {
      left: { style: BorderStyle.SINGLE, size: 12, color: 'D0D7DE', space: 6 },
      ...(i === 0 ? { top: { style: BorderStyle.SINGLE, size: 4, color: 'D0D7DE', space: 2 } } : {}),
      ...(i === lines.length - 1 ? { bottom: { style: BorderStyle.SINGLE, size: 4, color: 'D0D7DE', space: 2 } } : {}),
    },
    spacing: { before: 0, after: i === lines.length - 1 ? 160 : 0, line: 240 },
    keepLines: true,
  }))
}

function table(tok) {
  tableNo += 1
  const cols = tok.header.length
  const cell = (c, header) => new TableCell({
    children: [new Paragraph({ children: runs(c.tokens, header ? { bold: true } : {}), spacing: { before: 40, after: 40 } })],
    shading: header ? { type: ShadingType.CLEAR, fill: 'E8EEF7', color: 'auto' } : undefined,
    margins: { top: 40, bottom: 40, left: 80, right: 80 },
  })
  return [
    new Table({
      width: { size: 100, type: WidthType.PERCENTAGE },
      rows: [
        new TableRow({ children: tok.header.map((c) => cell(c, true)), tableHeader: true }),
        ...tok.rows.map((r) => new TableRow({ children: r.slice(0, cols).map((c) => cell(c, false)), cantSplit: true })),
      ],
    }),
    new Paragraph({ children: [new TextRun({ text: `ตารางที่ ${tableNo}`, italics: true, size: 16, color: '6B7280' })], alignment: AlignmentType.RIGHT, spacing: { before: 40, after: 160 } }),
  ]
}

function image(base, landscape) {
  const png = path.join(RENDERED, base + '.png')
  if (!fs.existsSync(png)) return [new Paragraph({ children: [new TextRun({ text: `[diagram ${base} ไม่ได้ render]`, color: 'B42318' })] })]
  const m = meta[base] || { width: 800, height: 600 }
  const maxW = landscape ? 900 : 600
  const maxH = landscape ? 520 : 820
  const scale = Math.min(maxW / m.width, maxH / m.height, 1.4)
  return [new Paragraph({
    children: [new ImageRun({ type: 'png', data: fs.readFileSync(png), transformation: { width: Math.round(m.width * scale), height: Math.round(m.height * scale) } })],
    alignment: AlignmentType.CENTER, spacing: { before: 120, after: 60 }, keepNext: true,
  })]
}

function isWide(base) {
  const m = meta[base]
  // only diagrams that would shrink below ~30% in portrait get a landscape page
  return m && m.width > 1900 && m.width / m.height > 2
}

function listBlock(tok, depth = 0) {
  const out = []
  for (const item of tok.items) {
    const inline = []
    const nested = []
    for (const t of item.tokens || []) {
      if (t.type === 'list') nested.push(t)
      else if (t.type === 'text' || t.type === 'paragraph') inline.push(...(t.tokens || [{ type: 'text', text: t.text }]))
    }
    out.push(new Paragraph({
      children: runs(inline),
      numbering: { reference: tok.ordered ? 'num' : 'bullet', level: depth },
      spacing: { after: 60 },
    }))
    for (const n of nested) out.push(...listBlock(n, depth + 1))
  }
  return out
}

// Converts one Markdown file into section fragments: [{landscape, children}]
function convert(file) {
  const { content } = matter(fs.readFileSync(file, 'utf8'))
  const tokens = marked.lexer(content)
  const frags = [{ landscape: false, children: [] }]
  const cur = () => frags[frags.length - 1]
  let firstH1 = true
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i]
    switch (t.type) {
      case 'heading': {
        const level = [HeadingLevel.HEADING_1, HeadingLevel.HEADING_2, HeadingLevel.HEADING_3, HeadingLevel.HEADING_4][Math.min(t.depth, 4) - 1]
        cur().children.push(new Paragraph({ heading: level, children: runs(t.tokens), keepNext: true }))
        if (t.depth === 1) firstH1 = false
        break
      }
      case 'paragraph': {
        const cap = t.raw.trim().match(CAPTION_RE)
        if (cap) {
          cur().children.push(new Paragraph({ children: [new TextRun({ text: `รูปที่ ${cap[1]} — ${cap[2]}`, italics: true, size: 18, color: '374151' })], alignment: AlignmentType.CENTER, spacing: { after: 200 } }))
        } else {
          cur().children.push(new Paragraph({ children: runs(t.tokens), spacing: { after: 120, line: 300 } }))
        }
        break
      }
      case 'code': {
        if (t.lang === 'mermaid') {
          const base = diagramBySource.get(norm(t.text))
          if (base && isWide(base)) {
            // a wide diagram gets its own landscape section, caption included
            frags.push({ landscape: true, children: image(base, true) })
            const next = tokens[i + 1]?.type === 'space' ? tokens[i + 2] : tokens[i + 1]
            const cap = next?.type === 'paragraph' && next.raw.trim().match(CAPTION_RE)
            if (cap) {
              cur().children.push(new Paragraph({ children: [new TextRun({ text: `รูปที่ ${cap[1]} — ${cap[2]}`, italics: true, size: 18 })], alignment: AlignmentType.CENTER }))
              i += tokens[i + 1]?.type === 'space' ? 2 : 1
            }
            frags.push({ landscape: false, children: [] })
          } else if (base) {
            cur().children.push(...image(base, false))
          } else {
            cur().children.push(...codeBlock(t.text))
          }
        } else {
          cur().children.push(...codeBlock(t.text))
        }
        break
      }
      case 'table': cur().children.push(...table(t)); break
      case 'list': cur().children.push(...listBlock(t)); break
      case 'blockquote': {
        const inner = (t.tokens || []).flatMap((b) => (b.tokens ? b.tokens : [{ type: 'text', text: b.text || '' }]))
        cur().children.push(new Paragraph({
          children: runs(inner),
          shading: { type: ShadingType.CLEAR, fill: 'FFF8E6', color: 'auto' },
          border: { left: { style: BorderStyle.SINGLE, size: 24, color: 'F59E0B', space: 8 } },
          spacing: { before: 120, after: 160, line: 300 },
        }))
        break
      }
      default: break
    }
  }
  return frags.filter((f) => f.children.length)
}

// ---- document ------------------------------------------------------------
const header = () => ({ default: new Header({ children: [new Paragraph({ children: [new TextRun({ text: `WAF + CDN Security Platform — คู่มือระบบ v${VERSION}`, size: 16, color: '6B7280' })], alignment: AlignmentType.RIGHT })] }) })
const footer = () => ({ default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ children: ['หน้า ', PageNumber.CURRENT, ' / ', PageNumber.TOTAL_PAGES], size: 16, color: '6B7280' })] })] }) })
const page = (landscape) => ({
  size: { width: 11906, height: 16838, orientation: landscape ? PageOrientation.LANDSCAPE : PageOrientation.PORTRAIT },
  margin: { top: 1300, bottom: 1200, left: 1300, right: 1300, header: 600, footer: 600 },
})

const cover = [
  new Paragraph({ spacing: { before: 3000 } }),
  new Paragraph({ children: [new TextRun({ text: 'WAF + CDN Security Platform', bold: true, size: 56, color: '1F2937' })], alignment: AlignmentType.CENTER }),
  new Paragraph({ children: [new TextRun({ text: 'คู่มือระบบ (System Manual)', size: 36, color: '374151' })], alignment: AlignmentType.CENTER, spacing: { before: 200, after: 1200 } }),
  new Paragraph({ children: [new TextRun({ text: `เวอร์ชันเอกสาร ${VERSION}  ·  ${DATE}`, size: 24 })], alignment: AlignmentType.CENTER }),
  new Paragraph({ children: [new TextRun({ text: `อ้างอิงระบบจริง ณ commit ${COMMIT} (branch Backend)`, size: 22, color: '4B5563' })], alignment: AlignmentType.CENTER, spacing: { before: 120 } }),
  new Paragraph({ children: [new TextRun({ text: 'สถานะข้อมูล: VERIFIED / PARTIAL / PLANNED / UNKNOWN / DEPRECATED', size: 20, color: '4B5563' })], alignment: AlignmentType.CENTER, spacing: { before: 120 } }),
  new Paragraph({ children: [new TextRun({ text: 'เอกสารภายใน — ไม่มีรหัสผ่าน คีย์ หรือ token ใดๆ', size: 20, color: 'B42318' })], alignment: AlignmentType.CENTER, spacing: { before: 2400 } }),
]

const revHead = ['เวอร์ชัน', 'วันที่', 'รายละเอียด', 'ผู้จัดทำ']
const revRows = [[VERSION, DATE, 'ฉบับแรก: reverse-engineer จากระบบจริง (3 VM, 13 containers), 51 บท + Data flows + ภาคผนวก', 'ทีมพัฒนา + Claude']]
const revTable = new Table({
  width: { size: 100, type: WidthType.PERCENTAGE },
  rows: [revHead, ...revRows].map((r, i) => new TableRow({ children: r.map((c) => new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: c, bold: i === 0 })] })], shading: i === 0 ? { type: ShadingType.CLEAR, fill: 'E8EEF7', color: 'auto' } : undefined, margins: { top: 60, bottom: 60, left: 80, right: 80 } })) })),
})

const front = [
  new Paragraph({ children: [new TextRun({ text: 'ประวัติการแก้ไข (Revision History)', bold: true, size: 30 })], pageBreakBefore: true, spacing: { after: 200 } }),
  revTable,
  new Paragraph({ children: [new TextRun({ text: 'สารบัญ (Table of Contents)', bold: true, size: 30 })], pageBreakBefore: true, spacing: { after: 200 } }),
  new TableOfContents('สารบัญ', { hyperlink: true, headingStyleRange: '1-2' }),
  new Paragraph({ children: [new TextRun({ text: 'หากสารบัญว่าง: ใน Word กด F9 (หรือ คลิกขวา > Update Field) เพื่ออัปเดต', italics: true, size: 16, color: '6B7280' })] }),
]

const sections = [{ properties: { page: page(false), titlePage: true }, children: cover }]
sections.push({ properties: { page: page(false) }, headers: header(), footers: footer(), children: front })

let chapters = 0
for (const [partName, entries] of PARTS) {
  const partPage = [
    new Paragraph({ spacing: { before: 4000 } }),
    new Paragraph({ children: [new TextRun({ text: partName, bold: true, size: 48, color: '1F3A8A' })], alignment: AlignmentType.CENTER }),
  ]
  sections.push({ properties: { page: page(false) }, headers: header(), footers: footer(), children: partPage })
  for (const f of filesFor(entries)) {
    chapters += 1
    for (const frag of convert(f)) {
      sections.push({ properties: { page: page(frag.landscape) }, headers: header(), footers: footer(), children: frag.children })
    }
  }
}

const doc = new Document({
  creator: 'WAF Platform team',
  title: 'WAF + CDN Security Platform — System Manual',
  description: `System manual v${VERSION} (${COMMIT})`,
  features: { updateFields: true },
  styles: {
    default: { document: { run: { font: FONT, size: 20 }, paragraph: { spacing: { line: 300 } } } },
    paragraphStyles: [
      { id: 'Heading1', name: 'Heading 1', basedOn: 'Normal', next: 'Normal', quickFormat: true, run: { font: FONT, size: 36, bold: true, color: '1F3A8A' }, paragraph: { spacing: { before: 240, after: 240 } } },
      { id: 'Heading2', name: 'Heading 2', basedOn: 'Normal', next: 'Normal', quickFormat: true, run: { font: FONT, size: 28, bold: true, color: '1F2937' }, paragraph: { spacing: { before: 320, after: 120 } } },
      { id: 'Heading3', name: 'Heading 3', basedOn: 'Normal', next: 'Normal', quickFormat: true, run: { font: FONT, size: 24, bold: true, color: '374151' }, paragraph: { spacing: { before: 240, after: 100 } } },
      { id: 'Heading4', name: 'Heading 4', basedOn: 'Normal', next: 'Normal', quickFormat: true, run: { font: FONT, size: 22, bold: true }, paragraph: { spacing: { before: 200, after: 80 } } },
    ],
  },
  numbering: {
    config: [
      { reference: 'bullet', levels: [0, 1, 2].map((l) => ({ level: l, format: LevelFormat.BULLET, text: ['•', '◦', '▪'][l], alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 540 + l * 360, hanging: 260 } } } })) },
      { reference: 'num', levels: [0, 1, 2].map((l) => ({ level: l, format: LevelFormat.DECIMAL, text: `%${l + 1}.`, alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 540 + l * 360, hanging: 300 } } } })) },
    ],
  },
  sections,
})

const out = path.join(OUT_DIR, `WAF-CDN-System-Manual-v${VERSION}.docx`)
fs.writeFileSync(out, await Packer.toBuffer(doc))
console.log(`wrote ${out}  (${chapters} source files, ${sections.length} sections, ${tableNo} tables)`)
