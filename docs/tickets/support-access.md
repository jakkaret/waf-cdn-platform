# Ticket: ระบบแจ้งปัญหา (Support ticket) และให้สิทธิ์ทีม support เข้า origin ชั่วคราว

สถานะ: ทำแล้ว (2026-10-17) · คู่มือใช้งาน: [docs/manual/support-tickets.md](../manual/support-tickets.md)

## ปัญหา
- admin ของแพลตฟอร์มเปิดหน้าตั้งค่าของ origin ที่ไม่ใช่ของตัวเองไม่ได้ (rbac ไม่มีทางลัดให้ admin) ซึ่งถูกต้องเรื่องความเป็นส่วนตัว แต่ทำให้ทีม support ช่วยลูกค้าไม่ได้
- ทางที่ไม่ควรทำ: สร้าง user ใหม่ให้ทุก ticket จะได้บัญชีกับรหัสผ่านงอกเรื่อย ๆ ไม่รู้ว่าใครถือรหัส ลืมลบได้ง่าย และตรวจย้อนหลังยาก

## สิ่งที่ทำ
1. **Ticket**
   - admin ของ origin เปิด ticket ผูกกับ origin นั้น และคุยกับทีม support ในข้อความของ ticket
   - ปิด ticket ได้ทั้งสองฝั่ง
2. **Support grant**
   - เจ้าของ (admin ของ origin) กดอนุญาตให้ทีม support (คือ admin ของแพลตฟอร์ม) เข้า origin นั้นได้ชั่วคราว
   - สิทธิ์ผูกกับบัญชีพนักงานจริงของแต่ละคน ไม่มีการสร้างบัญชีใหม่
   - ระดับ `viewer` (ค่าเริ่มต้น) ดูอย่างเดียว
   - ระดับ `editor` แก้ไขได้ ต้องติ๊กยืนยันเพิ่ม
   - อายุ 1-72 ชั่วโมง หมดแล้วสิทธิ์หายเอง
   - ปิด ticket หรือเจ้าของกดถอน สิทธิ์หายทันที
   - grant ไม่ให้สิทธิ์ระดับ ownership เด็ดขาด เช่น ลบ/กู้ origin จัดการสมาชิก ออก token tunnel
3. **Audit log**
   - ทุกครั้งที่ support ใช้ grant ระบบจะบันทึกว่าใคร ระดับไหน เมื่อไร
   - เจ้าของเห็นบันทึกนี้ในหน้า ticket

4. **log / alert / analytics ของ tenant**
   - admin ของแพลตฟอร์มเห็นข้อมูลเหล่านี้ของ tenant เฉพาะตอนที่ origin นั้นมี grant ใช้งานอยู่
   - traffic ที่ไม่ใช่ของ tenant ไหน (โดเมนของแพลตฟอร์มเอง, Host ที่ไม่รู้จัก "-") admin ยังเห็นตามปกติ
   - ตัวกรองกลาง: `tenant_service.build_tenant_origin_filter` (admin → `_admin_filter`) ใช้กับ logs, analytics, copilot, ai summary, cdn stats/logs
   - alert: `ai_summary._visible_alerts_for_user` ใช้กับ feed และหน้า Alerts
   - ถ้าตรวจขอบเขตไม่ได้ (DB ล่ม) จะ fail closed คือ admin ไม่เห็นข้อมูลของ tenant เลย
   - ข้อยกเว้นที่ตั้งใจไว้: งานปรับกฎ WAF ของแพลตฟอร์มยังดู traffic ทุก origin เพราะกฎมีผลกับทุก origin
     - rule backtest คืนแค่จำนวนครั้งที่ตรงและตัวอย่าง path (ไม่มี host หรือ query)
     - threshold proposals ดูแค่ยอดรวมต่อ origin

## ข้อมูล (migration 0009_support_tickets.sql)
| ตาราง | หน้าที่ |
|---|---|
| `waf.support_tickets` | ticket: origin, ผู้เปิด, หัวข้อ, สถานะ open/closed |
| `waf.support_ticket_messages` | ข้อความใน ticket |
| `waf.support_grants` | สิทธิ์ชั่วคราว: ระดับ, หมดอายุ, ถอนเมื่อไร/โดยใคร |
| `waf.support_access_log` | บันทึกการเข้าใช้ grant ของ support |

## API (`/api/support`)
| method | path | ใครเรียกได้ |
|---|---|---|
| GET | `/origins` | ผู้ใช้ (ได้รายชื่อ origin ที่ตัวเองเป็น admin) |
| POST | `/tickets` | admin ของ origin นั้น |
| GET | `/tickets` | ผู้ใช้เห็น ticket ของ origin ที่ตัวเองเป็น admin, admin แพลตฟอร์มเห็นทั้งหมด |
| GET | `/tickets/{id}` | เจ้าของ ticket (admin ของ origin) หรือ admin แพลตฟอร์ม |
| POST | `/tickets/{id}/messages` | เหมือนข้างบน (ticket ต้องยังเปิด) |
| POST | `/tickets/{id}/close` | เหมือนข้างบน (ถอน grant ที่ยังใช้อยู่ด้วย) |
| POST | `/tickets/{id}/grant` | admin ของ origin เท่านั้น |
| DELETE | `/tickets/{id}/grant` | admin ของ origin เท่านั้น |

## การตรวจสิทธิ์ (services/rbac.py)
- `verify_origin_access` (อ่าน): ผ่านสำหรับ admin แพลตฟอร์มที่ origin มี grant ใช้งานอยู่ (ระดับใดก็ได้)
- `verify_origin_edit_access` (แก้ไข): ผ่านเฉพาะเมื่อ grant ระดับ `editor`
- `verify_origin_ownership`: ไม่เปลี่ยน grant ใช้ไม่ได้

## เทส
`dashboard/backend/tests/test_support_tickets.py` ครอบคลุม:
- สิทธิ์ในการเปิดและดู ticket
- ระดับ viewer/editor ของ grant
- การหมดอายุ การถอน และการปิด ticket แล้วสิทธิ์หาย
- grant ใช้กับงานระดับ ownership ไม่ได้
- grant ใช้ข้าม origin ไม่ได้
- มีบันทึก audit

`tests/test_admin_log_scope_support.py`: admin เห็น log และ alert ของ tenant เฉพาะเมื่อมี grant, เห็น host ที่ไม่ใช่ของ tenant ได้, fail closed

## ยังไม่ทำ (ต่อได้ภายหลัง)
- 2FA สำหรับบัญชี support ควรทำก่อนเปิดใช้ระดับ editor กับลูกค้าจริง
- แจ้งเตือนทางอีเมลหรือ Telegram เมื่อมีข้อความใหม่
