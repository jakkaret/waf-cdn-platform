import { defineConfig } from 'vitepress'
import { withMermaid } from 'vitepress-plugin-mermaid'
import fs from 'node:fs'
import path from 'node:path'
import matter from 'gray-matter'

// The Markdown in docs/ is the single source. The site reads it in place
// (srcDir '..'); nothing is copied or duplicated.
const DOCS = path.resolve(__dirname, '../..')

function items(dir: string) {
  return fs.readdirSync(path.join(DOCS, dir))
    .filter((f) => f.endsWith('.md'))
    .sort()
    .map((f) => {
      const fm = matter(fs.readFileSync(path.join(DOCS, dir, f), 'utf8')).data
      return { text: String(fm.title || f).replace(/^บทที่ (\d+) — /, '$1. '), link: `/${dir}/${f.replace(/\.md$/, '')}` }
    })
}

export default withMermaid(defineConfig({
  srcDir: '..',
  srcExclude: [
    'site/**', '_evidence/TEAM_BRIEF.md', '_traceability/**', '_facts/**', 'dist/**',
    'AGENT-OWNERSHIP-MAP.md', 'ARCHITECTURE.md', 'E2E-USER-JOURNEY-MATRIX.md', 'IMPLEMENTATION-ROADMAP.md',
    'KNOWN_ISSUES.md', 'OPERATIONS.md', 'PROJECT-DISCOVERY.md', 'PROJECT_IMPLEMENTATION_REPORT.md',
    'UI_REDESIGN_BACKUP.md', 'UI_REDESIGN_PLAN.md', 'UX_AUDIT.md',
  ],
  rewrites: { 'README.md': 'index.md' },
  lang: 'th-TH',
  title: 'WAF + CDN Platform',
  description: 'คู่มือระบบ WAF + CDN Security Platform',
  cleanUrls: true,
  lastUpdated: false,
  markdown: {
    lineNumbers: false,
    // Commands in the docs contain Go-template text such as {{.Names}} in
    // inline code. Vue would parse that as an interpolation and fail the
    // build; v-pre makes Vue leave inline code alone (fenced blocks already are).
    config: (md) => {
      const render = md.renderer.rules.code_inline!
      md.renderer.rules.code_inline = (...args) => render(...args).replace('<code', '<code v-pre')
    },
  },
  themeConfig: {
    search: { provider: 'local' },
    outline: { level: [2, 3], label: 'ในหน้านี้' },
    docFooter: { prev: 'ก่อนหน้า', next: 'ถัดไป' },
    nav: [
      { text: 'ภาพรวม', link: '/' },
      { text: 'System Facts', link: '/SYSTEM_FACTS' },
      { text: 'API', link: '/reference/api-reference' },
      { text: 'Status', link: '/IMPLEMENTATION_STATUS' },
    ],
    sidebar: [
      { text: 'เริ่มต้น', items: [
        { text: 'หน้าแรก', link: '/' },
        { text: 'System Facts', link: '/SYSTEM_FACTS' },
        { text: 'Implementation Status', link: '/IMPLEMENTATION_STATUS' },
      ] },
      { text: 'Part I — Introduction', collapsed: false, items: items('book') },
      { text: 'Part II — Infrastructure', collapsed: true, items: items('infrastructure') },
      { text: 'Part III — Backend', collapsed: true, items: items('backend') },
      { text: 'Part IV — WAF', collapsed: true, items: items('waf') },
      { text: 'Part V — CDN', collapsed: true, items: items('cdn') },
      { text: 'Part VI — Frontend', collapsed: true, items: items('frontend') },
      { text: 'Part VII — Data Flows', collapsed: true, items: items('workflows') },
      { text: 'Part VIII — Operations', collapsed: true, items: items('operations') },
      { text: 'Part IX — Testing', collapsed: true, items: items('testing') },
      { text: 'Reference', collapsed: true, items: [
        ...items('reference'),
        { text: 'Traceability', link: '/DOCUMENTATION_TRACEABILITY' },
        { text: 'QA Report', link: '/DOCUMENTATION_QA_REPORT' },
        { text: 'Runtime evidence', link: '/_evidence/runtime-2026-09-27' },
      ] },
    ],
  },
  mermaid: { securityLevel: 'strict' },
}))
