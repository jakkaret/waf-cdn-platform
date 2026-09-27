// Markdown hygiene for the VitePress/Vue build (run before building):
//  1. inside table rows, a "|" within `inline code` must be escaped as "\|"
//     or GFM splits the cell there;
//  2. a <placeholder> outside code is parsed by Vue as an HTML element, so
//     it is escaped as &lt;placeholder&gt;.
// --check only reports; without it the files are fixed in place.
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
const DOCS = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const check = process.argv.includes('--check')
const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => e.isDirectory() ? (['site', 'dist', 'diagrams', 'node_modules'].includes(e.name) ? [] : walk(path.join(d, e.name))) : e.name.endsWith('.md') ? [path.join(d, e.name)] : [])
let issues = 0
for (const f of walk(DOCS)) {
  const lines = fs.readFileSync(f, 'utf8').split('\n')
  let fence = false, changed = false
  const out = lines.map((line, i) => {
    if (/^\s*```/.test(line)) { fence = !fence; return line }
    if (fence) return line
    const parts = line.split(/(`[^`]*`)/)
    const fixed = parts.map((p) => {
      if (p.startsWith('`') && p.endsWith('`') && p.length > 1) {
        return line.trimStart().startsWith('|') ? p.replace(/(?<!\\)\|/g, '\\|') : p
      }
      return p.replace(/<(?!\/?(br|b|i|em|strong|sup|sub|span|div|a|code)\b)([A-Za-z_][^<>]*)>/g, '&lt;$2&gt;')
    }).join('')
    if (fixed !== line) { issues++; changed = true; if (check) console.log(`${path.relative(DOCS, f)}:${i + 1}: ${line.trim().slice(0, 90)}`) }
    return fixed
  })
  if (changed && !check) fs.writeFileSync(f, out.join('\n'))
}
console.log(`${issues} line(s) ${check ? 'need fixing' : 'fixed'}`)
process.exit(check && issues ? 1 : 0)
