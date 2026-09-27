# Documentation site and manual builder

The Markdown in `docs/` is the only source. This package turns it into:

| Output | Command | Location |
|---|---|---|
| Diagrams (SVG/PNG, also a Mermaid syntax check) | `npm run diagrams` | `docs/diagrams/rendered/` |
| Website (VitePress: sidebar, local search, outline, Mermaid, copy buttons) | `npm run build` / `npm run dev` | `docs/site/.vitepress/dist/` |
| DOCX manual (cover, revision history, TOC field, headers/footers, page numbers, captions, landscape pages for wide diagrams) | `npm run docx` | `docs/dist/*.docx` |
| PDF manual (print CSS, headless Chrome) | `npm run pdf` | `docs/dist/*.pdf` |
| Everything, with checks first | `npm run all` | – |

```bash
cd docs/site
npm install          # also links docs/node_modules -> site/node_modules (VitePress needs it: pages live in docs/)
npm run all
```

Checks run by `npm run all` before building:
- `sync` copies each `docs/diagrams/NN-*.mmd` into the chapter block captioned "รูปที่ NN" (edit diagrams in the `.mmd` file only);
- `lint` fails on `|` inside inline code in tables and on raw `<placeholder>` text (both break the Vue build).

Rendering uses the system Google Chrome (`PW_CHANNEL=chrome`); set `PW_CHANNEL=chromium` after `npx playwright install chromium` on a machine without Chrome.

When opening the DOCX in Word, accept the prompt to update fields (or press F9) so the table of contents gets its page numbers.
