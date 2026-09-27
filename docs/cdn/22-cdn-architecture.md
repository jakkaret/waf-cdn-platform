---
title: "บทที่ 22 — สถาปัตยกรรม CDN"
chapter: 22
part: "Part V — CDN"
status: PARTIAL
---

# บทที่ 22 — สถาปัตยกรรม CDN

## 22.1 สิ่งที่มีจริง

| องค์ประกอบ | สถานะ | หมายเหตุ |
|---|---|---|
| Edge 2 โหนด (edge-th, edge-asia) บน VM แยกกัน | VERIFIED | ชุด container เหมือนกัน |
| DNS สาธารณะชี้ `cdn.waf-it-kku.online` → edge-th | VERIFIED | ผู้ใช้ทั้งหมดเข้า edge-th |
| การกระจาย traffic ไป edge-asia อัตโนมัติ | PARTIAL | GeoDNS บน Main มีตรรกะ (ไทย → edge-th, อื่นๆ → edge-asia, failover ตาม `/healthz`) แต่ไม่ได้เป็น authoritative DNS |
| Rule sync จากศูนย์กลาง | VERIFIED | edge ดึง bundle จาก `control-api /api/sync/bundle` ทุก 5 วินาที |
| Log กลับศูนย์กลาง | VERIFIED | `cdn-log-forwarder` → `/api/cdn/logs/ingest` |
| ชุด CDN จำลองในเครื่องเดียว (`cdn/docker-compose-cdn.yml`, SG/JP/TH, purge-api, stats) | DEPRECATED | ไม่พบ container เหล่านี้รันอยู่ |

## 22.2 โครงสร้าง

```text
Client → DNS (Hostinger) → Edge Caddy (TLS) → Edge nginx (WAF + cache) → Main waf-nginx :8080 → Origin
                                          ↘ log-forwarder → Main :8000
                         control-api :8070 → bundle → Edge /opt/custom-rules
```

ดูภาพรวมใน [รูปที่ 2](../infrastructure/04-infrastructure-overview.md) และ [รูปที่ 5](../infrastructure/07-network-architecture.md)

## 22.3 ความต่างจาก CDN เชิงพาณิชย์

- ไม่มี anycast: ผู้ใช้เข้า edge ตาม DNS record เดียว
- cache อยู่ที่ edge เท่านั้น ไม่มีชั้น shield cache
- Main เป็นจุดเดียวที่เข้าถึง origin

## แหล่งอ้างอิง (Evidence)
- `dig`, `docker ps` บน edge ทั้งสอง, `cdn/geodns/server.py`, `cdn/edge/entrypoint.d/99-rulesync.sh`
