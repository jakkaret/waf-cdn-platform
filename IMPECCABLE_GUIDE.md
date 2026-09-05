# คู่มือการใช้งาน Impeccable Slash Commands (AI Design Director)

เอกสารสรุปคำสั่ง, หน้าที่การทำงาน และขอบเขตการใช้งานของ **Impeccable** (`/impeccable`) สำหรับ AI Coding Agents (เช่น Claude Code, Cursor, Copilot, Antigravity)

---

## 📌 สารบัญ (Table of Contents)
1. [Impeccable คืออะไร?](#1-impeccable-คืออะไร)
2. [ขอบเขตการทำงาน (Frontend vs Backend)](#2-ขอบเขตการทำงาน-frontend-vs-backend)
3. [หมวดหมู่และรายการคำสั่งทั้งหมด (Command Reference)](#3-หมวดหมู่และรายการคำสั่งทั้งหมด-command-reference)
   - [หมวด 1: ตรวจสอบและประเมินคุณภาพ (Evaluation & QA)](#หมวด-1-ตรวจสอบและประเมินคุณภาพ-evaluation--qa)
   - [หมวด 2: ขัดเกลาและเตรียมความพร้อม (Refinement & Production-ready)](#หมวด-2-ขัดเกลาและเตรียมความพร้อม-refinement--production-ready)
   - [หมวด 3: ปรับโทนและความจัดจ้าน (Tone & Aesthetic Control)](#หมวด-3-ปรับโทนและความจัดจ้าน-tone--aesthetic-control)
   - [หมวด 4: โครงสร้างและการเคลื่อนไหว (Structure & Motion)](#หมวด-4-โครงสร้างและการเคลื่อนไหว-structure--motion)
   - [หมวด 5: สถาปัตยกรรมระบบดีไซน์ (Design System & Setup)](#หมวด-5-สถาปัตยกรรมระบบดีไซน์-design-system--setup)
4. [ลำดับขั้นตอนการทำงานที่แนะนำ (Recommended Workflow)](#4-ลำดับขั้นตอนการทำงานที่แนะนำ-recommended-workflow)
5. [การติดตั้งและเริ่มต้นใช้งาน (Getting Started)](#5-การติดตั้งและเริ่มต้นใช้งาน-getting-started)

---

## 1. Impeccable คืออะไร?

**Impeccable** (พัฒนาโดย Paul Bakaus) เป็นเครื่องมือและชุดทักษะ (Skill) สำหรับ AI Coding Assistant ที่ถูกออกแบบมาเพื่อทำหน้าที่เป็น **"AI Design Director"** โดยมีเป้าหมายหลักคือ:
* **ขจัดปัญหา "AI Slop":** ป้องกันการสร้างดีไซน์ซ้ำซาก ขาดเอกลักษณ์ (เช่น สี Gradient ม่วง-ฟ้า, การ์ดซ้อนการ์ด, ฟอนต์จืดๆ)
* **สร้าง Shared Design Vocabulary:** ทำให้ผู้พัฒนากับ AI สื่อสารทิศทางงานดีไซน์ด้วยคำสั่งที่มีความหมายชัดเจน
* **ใช้ Deterministic Rules:** ตรวจสอบโค้ด UI ด้วยกฎกว่า 50+ ข้อ เพื่อคุมมาตรฐานก่อนนำขึ้น Production

---

## 2. ขอบเขตการทำงาน (Frontend vs Backend)

> **⚠️ Frontend / UI / UX เท่านั้น (100%) ไม่ยุ่งกับ Backend เลย**

| ส่วนงาน | สถานะ | รายละเอียด |
| :--- | :---: | :--- |
| **Frontend / Web UI** | ✅ รองรับ | HTML, CSS, SCSS, Tailwind CSS, Component Frameworks (React, Vue, Svelte, Next.js, ฯลฯ) |
| **Mobile / Native UI** | ✅ รองรับ | SwiftUI, Jetpack Compose, React Native |
| **Design System & Tokens** | ✅ รองรับ | Color Palettes, Typography Scale, Spacing Grid, Dark/Light Themes, Icons |
| **UX & Accessibility** | ✅ รองรับ | WCAG Contrast, Responsive Breakpoints, Layout Shift, Micro-interactions |
| **Backend & Databases** | ❌ **ไม่รองรับ** | API Logic, Database Queries, Server Routing, Authentication Flow, Backend Config |

*อ้างอิงจากข้อกำหนดหลัก: "Not for backend-only or non-UI tasks."*

---

## 3. หมวดหมู่และรายการคำสั่งทั้งหมด (Command Reference)

รูปแบบการเรียกใช้ทั่วไป:
```text
/impeccable <command> [target]
```
*(หากตั้ง Shortcut shims ไว้ สามารถเรียกสั้นๆ เช่น `/polish` หรือ `/audit` ได้)*

---

### หมวด 1: ตรวจสอบและประเมินคุณภาพ (Evaluation & QA)

| คำสั่ง | พารามิเตอร์ | หน้าที่และการทำงาน |
| :--- | :--- | :--- |
| `/impeccable audit` | `[target]` | **Technical Quality Audit:** ตรวจสอบความถูกต้องเชิงเทคนิค เช่น Accessibility (WCAG), Responsive layout, Performance, Contrast ratio และตรวจจับ AI Anti-patterns |
| `/impeccable critique` | `[target]` | **Design & UX Review:** วิจารณ์หน้าจอในมุมมอง Design Director ประเมิน Visual Hierarchy, Cognitive Load, Spacing, Information Architecture |
| `/impeccable suggest` | `[target]` | **Actionable Suggestions:** ให้ AI เสนอแนะจุดที่ควรปรับปรุงในขั้นตอนต่อไปตามลำดับความสำคัญ |

---

### หมวด 2: ขัดเกลาและเตรียมความพร้อม (Refinement & Production-ready)

| คำสั่ง | พารามิเตอร์ | หน้าที่และการทำงาน |
| :--- | :--- | :--- |
| `/impeccable polish` | `[target]` | **Final Polish:** เก็บรายละเอียดรอบสุดท้าย (Pixel-perfect) ปรับ Spacing, Alignment, Consistency ก่อนส่งมอบงาน โดยไม่แก้ Concept หลัก |
| `/impeccable distill` | `[target]` | **Ruthless Subtraction:** ลดทอนความรก ตัด Card ซ้อน Card, ขอบเส้น หรือสิ่งที่ไม่จำเป็น ให้เหลือเฉพาะแก่นหลักที่ Clean และสบายตา |
| `/impeccable harden` | `[target]` | **Production Hardening:** เพิ่มความทนทานให้ UI จัดการ Error states, Empty states, Loading skeletons, Text overflow (ข้อความยาวเกิน), และ i18n |
| `/impeccable normalize` | `[target]` | **Token Normalization:** ปรับโค้ด CSS/Tailwind ให้ใช้ค่าตัวแปรจาก Design Tokens กลาง แทนการ Hardcode ค่าแปลกๆ |

---

### หมวด 3: ปรับโทนและความจัดจ้าน (Tone & Aesthetic Control)

| คำสั่ง | พารามิเตอร์ | หน้าที่และการทำงาน |
| :--- | :--- | :--- |
| `/impeccable bolder` | `[target]` | **Amplify Impact:** เพิ่มความโดดเด่น จัดจ้าน และเอกลักษณ์ สำหรับหน้าที่ดูเรียบ จืดชืด หรือ "ปลอดภัยเกินไป" |
| `/impeccable quieter` | `[target]` | **Tone Down Noise:** ลดทอนความจัดจ้านและ Visual Noise สำหรับหน้าที่ดูรก ลายตา หรือสีสันแย่งซีนกัน |
| `/impeccable colorize` | `[target]` | **Color Refinement:** จัดการ Palette สี, Contrast, ระบบสี OKLCH, Semantic Colors และการสลับ Light/Dark Mode |
| `/impeccable typeset` | `[target]` | **Typography Tuning:** ปรับแต่งคู่ฟอนต์, Type Scale, Line-height, Letter-spacing และลำดับขั้น Heading/Body |

---

### หมวด 4: โครงสร้างและการเคลื่อนไหว (Structure & Motion)

| คำสั่ง | พารามิเตอร์ | หน้าที่และการทำงาน |
| :--- | :--- | :--- |
| `/impeccable layout` | `[target]` | **Layout Structure:** ปรับโครงสร้าง Flexbox, Grid, Margin/Padding, Alignment และ Whitespace |
| `/impeccable animate` | `[target]` | **Motion & Interaction:** ใส่ Animation, Transitions, Micro-interactions ที่มีความหมายและส่งเสริม UX |
| `/impeccable adapt` | `[target]` | **Responsive & Multi-platform:** ปรับ Layout ให้เข้ากับ Mobile, Tablet, Desktop หรือแปลงให้เหมาะกับ Native Platform |
| `/impeccable shape` | `[target]` | **Component Prototyping:** ขึ้นโครงสร้างและจัดวางองค์ประกอบของคอมโพเนนต์ใหม่ |

---

### หมวด 5: สถาปัตยกรรมระบบดีไซน์ (Design System & Setup)

| คำสั่ง | พารามิเตอร์ | หน้าที่และการทำงาน |
| :--- | :--- | :--- |
| `/impeccable init` | - | **Initialize Context:** สแกนโค้ดในโปรเจกต์และสร้างไฟล์ `PRODUCT.md` กับ `DESIGN.md` เพื่อเป็นแนวทางกลางของแบรนด์ |
| `/impeccable extract` | `[target]` | **Extract Design Tokens:** สกัด Styles หรือชิ้นส่วนที่ใช้ซ้ำออกมาเป็น Token หรือ Reusable Component |
| `/impeccable doctor` | - | **Diagnostics:** ตรวจสอบความถูกต้องของการติดตั้งและสภาพแวดล้อมของ Impeccable Skill |

---

## 4. ลำดับขั้นตอนการทำงานที่แนะนำ (Recommended Workflow)

```mermaid
graph TD
    A[1. ติดตั้ง & กำหนดบริบท: /impeccable init] --> B[2. สร้างหน้า UI / คอมโพเนนต์]
    B --> C{ตรวจสอบ & ปรับแต่ง}
    C -->|ต้องการทิศทาง| D[/impeccable critique หรือ /impeccable suggest]
    C -->|จืดไป/รกไป| E[/impeccable bolder หรือ /impeccable quieter]
    C -->|ปรับสไตล์เจาะจง| F[/impeccable typeset, colorize, layout, animate]
    D & E & F --> G[3. ตรวจสอบข้อผิดพลาด: /impeccable audit]
    G --> H[4. รองรับ Edge Case: /impeccable harden]
    H --> I[5. เก็บงานรอบสุดท้าย: /impeccable polish]
    I --> J[🚀 พร้อมส่งงาน / Deploy]
```

1. **Setup Phase:** รัน `/impeccable init` ครั้งแรกเพื่อสร้าง `PRODUCT.md` และ `DESIGN.md`
2. **Drafting Phase:** สร้าง UI ขึ้นมาตามปกติ
3. **Iteration Phase:** ปรับแต่งอารมณ์ด้วย `/impeccable bolder`, `/impeccable typeset`, `/impeccable colorize`
4. **Simplification:** หากดูซับซ้อนไป ให้รัน `/impeccable distill`
5. **Quality Assurance:** รัน `/impeccable audit` เพื่อเช็ค Accessibility และข้อบกพร่อง
6. **Ship:** รัน `/impeccable polish` เพื่อสรุปงานขั้นสุดท้าย

---

## 5. การติดตั้งและเริ่มต้นใช้งาน (Getting Started)

### ติดตั้งผ่าน npx:
```bash
npx impeccable install
```

### สแกนหา Anti-patterns ในโปรเจกต์:
```bash
npx impeccable detect src/
```

### ไฟล์เอกสารสำคัญที่ Impeccable สร้าง:
* `PRODUCT.md`: ระบุกลุ่มเป้าหมาย, Voice & Tone, และ Core Value ของแอปพลิเคชัน
* `DESIGN.md`: ระบุระบบสี, ฟอนต์, ระยะ Spacing, ไอคอน, และแนวทางการดีไซน์ที่ห้ามละเมิด
