// Keep every ```mermaid block in the chapters identical to its source in
// docs/diagrams/NN-*.mmd. A block is identified by the caption that follows
// it ("*รูปที่ NN — ...*"), so edits are made once, in the .mmd file.
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
const DOCS = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const DIAG = path.join(DOCS, 'diagrams')
const byNo = Object.fromEntries(fs.readdirSync(DIAG).filter((f) => f.endsWith('.mmd')).map((f) => [String(parseInt(f, 10)), fs.readFileSync(path.join(DIAG, f), 'utf8').trimEnd()]))
const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => e.isDirectory() ? (['site', 'dist', 'diagrams', 'node_modules'].includes(e.name) ? [] : walk(path.join(d, e.name))) : e.name.endsWith('.md') ? [path.join(d, e.name)] : [])
let changed = 0
for (const f of walk(DOCS)) {
  const s = fs.readFileSync(f, 'utf8')
  const out = s.replace(/```mermaid\n[\s\S]*?```\n\n\*รูปที่ (\d+) —/g, (m, no) => byNo[no] ? '```mermaid\n' + byNo[no] + '\n```\n\n*รูปที่ ' + no + ' —' : m)
  if (out !== s) { fs.writeFileSync(f, out); changed++ ; console.log('synced', path.relative(DOCS, f)) }
}
console.log(`${changed} file(s) updated`)
