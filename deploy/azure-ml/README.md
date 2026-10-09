# แยก ML ไปรันบนเครื่อง Azure (ONNX) แล้วเชื่อมกับ VPS หลัก

คู่มือนี้ย้ายเฉพาะ ML API (`ml/ml_api.py`) ไปรันบน VM แยก ตามที่อาจารย์ให้แยก ML ออกจาก main WAF
ตัวโมเดลรันด้วย **onnxruntime** (ไม่ต้องมี LightGBM บนเครื่อง ML) ส่วน VPS หลักยังรัน nginx, ModSecurity, backend และ dashboard เหมือนเดิม

> ⚠️ ทุกขั้นที่แตะ **VPS production** (ขั้น 6–8) ต้องได้รับอนุมัติก่อนตาม `WORKING_RULES.md`
> ขั้น 1–5 ทำบนเครื่อง Azure อย่างเดียว ไม่กระทบระบบจริง

## 1. ภาพรวม

```
ผู้ใช้ ─▶ Caddy ─▶ nginx + ModSecurity (VPS) ── mirror / shadow hook ──▶ backend :8000 (VPS)
                                                                              │ ML_SERVICE_URL + token
                                                        WireGuard (เข้ารหัส)  ▼
                                                   ML host (Azure) 10.77.0.2:5000
                                                   uvicorn ml_api (ONNX: RF + Gen 3)
log analyzer (VPS) ── ML_API_URL + token ──────────────────────────────────▶ ↑
```

- nginx **ไม่ต้องแก้** เพราะ nginx คุยกับ backend (`/api/ml/...`) เสมอ แล้ว backend เป็นตัวส่งต่อไปที่ ML
  จุดที่ต้องสลับไป Azure มี 2 จุด คือ `ML_SERVICE_URL` (backend) และ `ML_API_URL` (log analyzer)
- เรียกผ่าน WireGuard อย่างเดียว: ML API ไม่เปิดสู่ internet และใช้ token เป็นชั้นที่สอง
- **Fail-open**: ถ้า Azure ล่มหรือช้าเกิน `ML_FAST_TIMEOUT` เว็บยังใช้งานได้ปกติ (ML เป็น shadow อยู่แล้ว เพราะ `ml_enforcement_enabled = false`)

Endpoint ที่ VPS เรียก มีครบบนเครื่อง ML:

| Endpoint | ผู้เรียก | หมายเหตุ |
| :--- | :--- | :--- |
| `/predict-fast` | backend `/api/ml/shadow/decision` (nginx shadow hook) | ONNX; เลือกเอนจินด้วย `WAF_FAST_ENGINE` = `rf` หรือ `gen3` |
| `/capture` | backend `/api/ml/capture` (nginx mirror) | ปิดไว้เป็นค่าเริ่มต้น (ดูหัวข้อ 9) |
| `/predict` | dashboard ML Analyst, log analyzer | RandomForest + attribution (sklearn) |
| `/generate-rule` | dashboard, log analyzer | สร้าง pattern ส่งกลับไปให้ backend (ไม่เขียนไฟล์บนเครื่อง ML) |
| `/health`, `/predict-gen3` | ตรวจสอบ / demo | `/predict-gen3` เป็น shadow |

## 2. เลือกเครื่องและคุมค่าใช้จ่าย (Azure for Students $100)

- **Image**: Ubuntu Server 24.04 LTS (Python 3.12)
- **ขนาด**: `Standard_B1ms` (1 vCPU, 2 GB) พอสำหรับ 1 worker (process ใช้ RAM ~250 MB ต่อ worker และใช้ CPU ~0.3 ms ต่อ request)
  ถ้าต้องการ 2 worker ใช้ `Standard_B2s` หรือ `Standard_B2als_v2` (4 GB)
  ถ้าบัญชีมี free service `B1s` (1 GB) ใช้ได้ แต่ควรเพิ่ม swap 1–2 GB ก่อนติดตั้ง
- **Region**: เลือกให้ใกล้ VPS ที่สุด เพราะ shadow hook มีงบเวลา `ML_FAST_TIMEOUT` = 0.5 วินาที
  VPS หลักอยู่ Hetzner Nuremberg (เยอรมนี) → เลือก **Germany West Central** ก่อน ถ้าบัญชีเลือกไม่ได้ใช้ West Europe ไม่ควรเลือก region ในเอเชีย
  หลังติดตั้ง `smoke_test.sh` จะบอก round trip จริง
  บัญชีนักศึกษาอาจเลือกได้บาง region เท่านั้น
- **Disk**: Standard SSD 30 GB พอ
- **Public IP**: Standard, static (WireGuard ต้องใช้ IP คงที่)
- **คุมเงิน**:
  - Cost Management → Budgets: ตั้งงบ $100 และแจ้งเตือนที่ 25% / 50% / 80%
  - ช่วงพัฒนาให้ตั้ง Auto-shutdown ตอนกลางคืน (ปิดเครื่องแล้ว ML กลายเป็น "unavailable" ส่วนเว็บยังผ่านตามปกติ)
  - ไม่ใช้เครื่องเมื่อไหร่ให้ **Stop (deallocate)** จะไม่เสียค่า compute (ยังเสียค่า disk กับ IP นิดหน่อย)
  - ไม่ต้องใช้ Azure Bastion, Load Balancer หรือ NAT Gateway (มีค่าใช้จ่ายเพิ่ม)

สร้างด้วย Azure CLI (หรือใช้ Portal ด้วยค่าเดียวกัน):

```bash
RG=waf-ml-rg; LOC=<region>; MYIP=$(curl -s https://api.ipify.org)
az group create -n $RG -l $LOC
az vm create -g $RG -n waf-ml --image Ubuntu2404 --size Standard_B1ms \
  --admin-username azureuser --generate-ssh-keys --public-ip-sku Standard --nsg-rule NONE
NSG=$(az network nsg list -g $RG --query "[0].name" -o tsv)
az network nsg rule create -g $RG --nsg-name $NSG -n ssh-from-me --priority 100 \
  --protocol Tcp --destination-port-ranges 22 --source-address-prefixes $MYIP/32 --access Allow
az network nsg rule create -g $RG --nsg-name $NSG -n wireguard-from-vps --priority 110 \
  --protocol Udp --destination-port-ranges 51820 --source-address-prefixes 178.104.53.123/32 --access Allow
az vm auto-shutdown -g $RG -n waf-ml --time 1700      # 17:00 UTC = 00:00 เวลาไทย; เอาออกช่วง demo
```

NSG เปิดแค่ 2 ช่อง: SSH จาก IP ของคุณ และ WireGuard (UDP 51820) จาก VPS เท่านั้น **ห้ามเปิด port 5000**

## 3. ติดตั้ง ML API บนเครื่อง Azure

```bash
ssh azureuser@<ML_HOST_PUBLIC_IP>
git clone https://github.com/jakkaret/waf-cdn-platform.git ~/waf-cdn-platform
sudo bash ~/waf-cdn-platform/deploy/azure-ml/install.sh
```

`install.sh` ทำสิ่งต่อไปนี้ (รันซ้ำได้ ใช้ตอนอัปเดตโค้ดด้วย):

1. ติดตั้ง python3-venv, build-essential และ wireguard
2. สร้าง user `wafml` (ไม่มี shell)
3. clone โค้ด (repo public `waf-cdn-platform` branch `main` ไม่ต้องใช้ token) ไปที่ `/opt/waf_project`
4. สร้าง venv จาก `ml/requirements-serve.txt` (ไม่มี LightGBM)
5. สร้าง `random_forest_waf.onnx` จาก joblib ใน repo
6. สร้าง `/etc/waf-ml/waf-ml.env` พร้อม token แบบสุ่ม
7. ติดตั้ง `waf-ml.service` (systemd แบบ hardening: โค้ดอ่านอย่างเดียว เขียนได้เฉพาะ `ml/telemetry`)

ตอนแรก service จะ listen ที่ `127.0.0.1` เท่านั้น ยังไม่มีใครจากภายนอกเข้าถึงได้

## 4. นำโมเดล Gen 3 (ONNX) ขึ้นเครื่อง

`ml/train_final_gen3.py` (Colab: `RUN_FINAL_MODEL = True`) สร้าง `gen3_f_model.onnx` ให้อัตโนมัติ เก็บไว้ที่ `MyDrive/waf_ml/models/gen3-final-f-<เวลา>/`
ไฟล์นี้จะถูกเขียนก็ต่อเมื่อผลของ ONNX ตรงกับ LightGBM (ต่างกันน้อยกว่า 1e-5)
ถ้ามีแค่ `.joblib` จากรอบเก่า ให้แปลงเองด้วย:
`PYTHONPATH=. python ml/export_gen3_onnx.py <path>/gen3_f_model.joblib`

รุ่นที่ใช้ตอนนี้คือ F-noopenappsec (`ml/models/gen3/gen3_f_noopenappsec.onnx`, เทรนจาก CSIC + SR-BH เท่านั้น) อยู่ใน repo แล้ว
ถ้าเทรนรุ่นใหม่ ให้วางทับด้วยชื่อเดียวกัน:

```bash
scp gen3_f_model.onnx azureuser@<ML_HOST_PUBLIC_IP>:/tmp/
ssh azureuser@<ML_HOST_PUBLIC_IP> 'sudo install -m 644 /tmp/gen3_f_model.onnx /opt/waf_project/ml/models/gen3/gen3_f_noopenappsec.onnx && sudo systemctl restart waf-ml'
```

ตรวจสอบ: `/health` → `"gen3_shadow": {"loaded": true, "runtime": "onnx", ...}`
ไฟล์ `.onnx` เป็นข้อมูลล้วน (ไม่ใช่ pickle) และเก็บ threshold, รายชื่อฟีเจอร์ และ model card ไว้ในตัวไฟล์
ตัว loader จะปฏิเสธไฟล์ที่ฟีเจอร์ไม่ตรงกับโค้ด หรือไฟล์ที่ไม่ผ่าน parity check

## 5. WireGuard (ฝั่ง Azure)

```bash
sudo -i
cd /etc/wireguard && umask 077 && wg genkey | tee mlhost.key | wg pubkey > mlhost.pub
cp /opt/waf_project/deploy/azure-ml/wireguard/wg0-mlhost.conf.example wg0.conf   # ใส่ key ของเครื่องนี้ + public key ของ VPS
systemctl enable --now wg-quick@wg0
ufw allow 22/tcp && ufw allow 51820/udp && ufw allow in on wg0 from 10.77.0.1 to any port 5000 proto tcp && ufw --force enable
sed -i 's/^WAF_ML_BIND=.*/WAF_ML_BIND=10.77.0.2/' /etc/waf-ml/waf-ml.env && systemctl restart waf-ml
```

## 6. WireGuard (ฝั่ง VPS) — ต้องได้รับอนุมัติก่อน

VPS เป็นฝ่ายเชื่อมออกไปหา Azure จึง**ไม่ต้องเปิด port ขาเข้าเพิ่ม** บน VPS

```bash
apt-get install -y wireguard-tools
cd /etc/wireguard && umask 077 && wg genkey | tee vps.key | wg pubkey > vps.pub
cp /root/waf_project/deploy/azure-ml/wireguard/wg0-vps.conf.example wg0.conf   # ใส่ key + public IP ของ Azure
systemctl enable --now wg-quick@wg0
ping -c3 10.77.0.2
```

ช่วง `10.77.0.0/24` ไม่ชนกับ network ของ Docker (172.16–31.x) และ VNet ของ Azure (10.0.x)

## 7. ทดสอบจาก VPS ก่อนสลับจริง (ยังไม่เปลี่ยนการทำงานของระบบ)

```bash
ML_URL=http://10.77.0.2:5000 ML_TOKEN=<token> bash /root/waf_project/deploy/azure-ml/smoke_test.sh
```

ต้องได้ `ALL PASS` และค่า p50 ของ round trip ต่ำกว่า `ML_FAST_TIMEOUT / 3`
ถ้าเกิน ให้เพิ่ม `ML_FAST_TIMEOUT` หรือเลือก region ที่ใกล้กว่า

## 8. สลับ VPS ไปใช้ ML บน Azure — ต้องได้รับอนุมัติก่อน

ต้องมีก่อน: VPS ต้องรันโค้ด backend ที่อ่าน `ML_SERVICE_URL` / `ML_SERVICE_TOKEN` จาก env ได้แล้ว
(`dashboard/backend/api/ml.py` และ `ml/async_log_analyzer.py` ใน `main` ของ waf-cdn-platform)
VPS ตาม `origin/main` อยู่แล้ว จึงต้อง `git pull` ใน `/root/waf_project` ก่อน
ถ้ามี `ml/benchmark_real_holdout.py` แบบ untracked บน VPS ให้ลบก่อน pull (เนื้อหาเดียวกับไฟล์ใน repo) ไม่อย่างนั้น git จะไม่ยอม pull
หลัง pull แล้วถ้ายังไม่ได้วาง drop-in ด้านล่าง ระบบยังเรียก `127.0.0.1:5000` เหมือนเดิม

```bash
install -m 600 /root/waf_project/deploy/azure-ml/vps-ml-client.env.example /etc/waf-ml-client.env   # ใส่ token จริง
cp -r /root/waf_project/deploy/azure-ml/vps-systemd/waf-dashboard.service.d /etc/systemd/system/
cp -r /root/waf_project/deploy/azure-ml/vps-systemd/waf-log-analyzer.service.d /etc/systemd/system/
systemctl daemon-reload && systemctl restart waf-dashboard waf-log-analyzer
```

ตรวจสอบ:

- `journalctl -u waf-log-analyzer -n 5` ต้องเห็น `Target ML Microservice: http://10.77.0.2:5000/predict`
- เปิดหน้า ML Analyst ใน dashboard แล้วลองทำนาย 1 ครั้ง
- ค่า env จาก systemd มีผลเหนือ `.env` เพราะ `load_dotenv` ไม่เขียนทับตัวแปรที่มีอยู่แล้ว
- ใช้ `systemctl cat waf-dashboard` ตรวจว่าชื่อ unit ของ backend ตรงกับที่ใช้ข้างบน

## 9. ข้อมูล traffic จริง (`/capture`)

`/capture` เก็บตัวอย่าง request จริงไว้ใช้เทรน ถ้าย้ายไป Azure ข้อมูล production จะออกจาก VPS
ค่าเริ่มต้นจึง**ปิด**ไว้ทั้ง 2 ฝั่ง (`ML_CAPTURE_URL=` ว่าง และ `WAF_CONTROLLED_CAPTURE_ENABLED=false`)
ถ้าจะเปิดต้องได้รับอนุมัติจากอาจารย์ก่อน ส่วนข้อมูลเดิมใน `ml/telemetry` ของ VPS ยังอยู่ที่เดิม

## 10. ย้อนกลับ (rollback)

```bash
rm /etc/systemd/system/waf-dashboard.service.d/ml-remote.conf /etc/systemd/system/waf-log-analyzer.service.d/ml-remote.conf
systemctl daemon-reload && systemctl restart waf-dashboard waf-log-analyzer
```

ระบบจะกลับไปเรียก `127.0.0.1:5000` บน VPS
ตรวจเมื่อ 9 ต.ค. 2569: venv ของ `waf-ml` บน VPS (`dashboard/backend/.venv`, Python 3.14) มี scikit-learn 1.9.0, numpy และ onnxruntime ครบ
`/health` โหลด RF ได้ จึงย้อนกลับมาใช้ ML บน VPS ได้ (ไม่มี libinjection จึงไม่มี Gen 3 บน VPS ซึ่งไม่กระทบ RF)

## 11. ดูแลรักษา

| งาน | คำสั่ง (เครื่อง Azure) |
| :--- | :--- |
| อัปเดตโค้ด | `sudo bash /opt/waf_project/deploy/azure-ml/install.sh` |
| log | `journalctl -u waf-ml -f` |
| เปลี่ยน token | แก้ `WAF_ML_API_TOKEN` ใน `/etc/waf-ml/waf-ml.env` และ `ML_SERVICE_TOKEN` บน VPS แล้ว restart ทั้ง 2 ฝั่ง |
| ให้ shadow hook ใช้ Gen 3 | `WAF_FAST_ENGINE=gen3` แล้ว restart (ยังเป็น shadow จนกว่าจะผ่าน promotion gate 3.1-G.0) |

## 12. Checklist ความปลอดภัย

- [ ] NSG เปิดแค่ SSH (จาก IP ของคุณ) และ UDP 51820 (จาก VPS) ไม่เปิด 5000
- [ ] `WAF_ML_BIND` เป็น `10.77.0.2` (ไม่ใช่ `0.0.0.0`)
- [ ] `curl http://<public-ip>:5000/health` จากภายนอกต้อง timeout
- [ ] Token ยาว 64 hex และไม่อยู่ใน git (`/etc/waf-ml/waf-ml.env` เป็น 640, `/etc/waf-ml-client.env` เป็น 600)
- [ ] ไม่มี private key ของ WireGuard หรือ token อยู่ใน repo
- [ ] ตั้ง budget alert แล้ว
