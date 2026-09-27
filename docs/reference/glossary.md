---
title: "อภิธานศัพท์ (Glossary)"
part: "Reference"
status: VERIFIED
---

# อภิธานศัพท์ (Glossary)

| คำ | ความหมาย |
|---|---|
| WAF (Web Application Firewall) | ไฟร์วอลล์ที่ตรวจคำขอ HTTP ระดับแอปพลิเคชัน |
| ModSecurity | engine WAF แบบ open source ที่ใช้ในระบบ (v3) |
| OWASP CRS | ชุดกฎมาตรฐานของ ModSecurity |
| Anomaly score | คะแนนสะสมจากกฎ CRS ที่ match ถ้าเกิน threshold จะบล็อก |
| Paranoia level (PL) | ระดับความเข้มงวดของ CRS (1–4) |
| Edge | เครื่องปลายทางแรกที่ผู้ใช้เชื่อมต่อ ทำ TLS/WAF/cache |
| Main | เครื่องศูนย์กลาง WAF ชั้นใน backend และฐานข้อมูล |
| Origin | เซิร์ฟเวอร์เว็บของลูกค้า |
| Tenant | ผู้ใช้/องค์กรที่เป็นเจ้าของ origin |
| Tunnel | การเชื่อมต่อขาออกจาก origin มายัง Main (FRP, CloudWAF tunnel) |
| On-demand TLS | Caddy ออกใบรับรองเมื่อมีการเชื่อมต่อครั้งแรกของโดเมน |
| Challenge | หน้า captcha/OTP ก่อนอนุญาตคำขอ |
| Deception | การตอบข้อมูลสังเคราะห์แทนการบล็อก |
| Bundle | ไฟล์ tar.gz ของกฎที่ control-api แจกให้ edge |
| Blast radius | การประเมินว่ากฎใหม่จะกระทบ traffic จริงเท่าใด |
| BOLA | Broken Object Level Authorization (ช่องโหว่ API ที่เข้าถึง object ของผู้อื่น) |
| Fail closed | เมื่อไม่แน่ใจให้ปฏิเสธ/ไม่แสดงข้อมูล แทนการอนุญาตทั้งหมด |
| Bind mount | การ mount ไฟล์/โฟลเดอร์จาก host เข้า container |
| TTL | อายุข้อมูล (cache หรือฐานข้อมูล) |
| Status labels | VERIFIED / PARTIAL / PLANNED / UNKNOWN / DEPRECATED ตามนิยามใน SYSTEM_FACTS |
