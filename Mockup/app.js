/* ============================================================
   WAF & CDN Interactive Deployment Guide - JavaScript Logic
   ============================================================ */

// Data Store for Deployment Methods & Interactive Tutorial
const methodsData = {
    'vps-tutorial': {
        isTutorial: true,
        title: '🎓 คู่มือจับมือทำทีละขั้นตอน (Zero-to-Hero VPS Tutorial)',
        subtitle: 'เริ่มต้นตั้งแต่ VPS เครื่องเปล่าๆ (root@ubuntu:~#) ก๊อปปี้คำสั่งรันตามทีละขั้น พร้อมตัวอย่างผลลัพธ์หน้าจอที่ถูกต้องในการตรวจสอบ!',
        steps: [
            {
                stepNum: 1,
                id: 'step-1',
                title: 'ขั้นตอนที่ 1: ติดตั้ง Docker & Docker Compose Plugin',
                reason: '💡 <strong>เหตุผลที่ต้องทำ:</strong> VPS ของคุณตอนนี้เป็นเครื่องว่างเปล่า การติดตั้ง Docker จะเปรียบเหมือนการวางรากฐาน เพื่อให้ Container ทั้งหมด (WAF, Dashboard, ClickHouse, Redis, Caddy) สามารถรันทำงานได้โดยไม่ต้องไปเซ็ตโปรแกรมทีละตัวในระบบปฏิบัติการ',
                code: `# 1. รันสคริปต์ติดตั้ง Docker (มี get-docker.sh อยู่ในเครื่องแล้ว)
sh get-docker.sh

# 2. เปิดใช้งาน Docker Service ให้ทำงานอัตโนมัติเมื่อเปิดเครื่อง
systemctl enable --now docker

# 3. ตรวจสอบว่าติดตั้งเรียบร้อย (ต้องแสดงเวอร์ชันของ Docker & Compose)
docker --version && docker compose version`,
                expectedOutput: `Executing docker install script...
+ sh -c 'apt-get update -qq >/dev/null'
+ sh -c 'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin'
Synchronizing state of docker.service with SysV service script...

root@ubuntu:~# docker --version && docker compose version
Docker version 27.1.1, build 6312585
Docker Compose version v2.29.1`
            },
            {
                stepNum: 2,
                id: 'step-2',
                title: 'ขั้นตอนที่ 2: ติดตั้ง Git, Curl, UFW, Python-Pip และ Node.js 20',
                reason: '💡 <strong>เหตุผลที่ต้องทำ:</strong> ต้องใช้ <code>git</code> สำหรับดึงโค้ดโปรเจกต์จาก GitHub, <code>python3-pip</code> สำหรับรัน FastAPI Backend (Port 8000), <code>ufw</code> สำหรับเปิด Firewall และ <code>node/npm</code> ในการสั่ง Build หน้าเว็บ React Frontend',
                code: `# 1. อัปเดตรายการแพ็กเกจ และติดตั้ง Git, Curl, UFW Firewall, Python3-pip
apt update && apt install -y git curl ufw python3-pip python3-venv

# 2. ติดตั้ง Node.js 20.x (LTS) และ npm
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt install -y nodejs

# 3. ตรวจสอบเวอร์ชัน Node.js & npm
node -v && npm -v`,
                expectedOutput: `Hit:1 http://archive.ubuntu.com/ubuntu noble InRelease
Reading package lists... Done
...
Setting up nodejs (20.16.0-1nodesource1) ...

root@ubuntu:~# node -v && npm -v
v20.16.0
10.8.1`
            },
            {
                stepNum: 3,
                id: 'step-3',
                title: 'ขั้นตอนที่ 3: Clone โปรเจกต์ WAF & สลับไปยัง Branch Backend',
                reason: '💡 <strong>เหตุผลที่ต้องทำ:</strong> เพื่อดึงซอร์สโค้ดล่าสุดของโปรเจกต์จาก GitHub ลงมาไว้ที่เซิร์ฟเวอร์ และสลับไปยังกิ่ง <code>Backend</code> ซึ่งเป็น Branch หลักที่มีโค้ดระบบ WAF & CDN ล่าสุด',
                code: `# 1. Clone โปรเจกต์เข้าโฟลเดอร์ /root/waf_project
git clone https://github.com/jakkaret/waf_project.git

# 2. เข้าโฟลเดอร์โปรเจกต์
cd waf_project

# 3. สลับไปยังกิ่ง Backend
git checkout Backend`,
                expectedOutput: `Cloning into 'waf_project'...
remote: Enumerating objects: 122, done.
remote: Counting objects: 100% (122/122), done.
remote: Compressing objects: 100% (26/26), done.
Receiving objects: 100% (122/122), 82.22 KiB | 2.15 MiB/s, done.
Resolving deltas: 100% (42/42), done.

Branch 'Backend' set up to track remote branch 'Backend' from 'origin'.
Switched to a new branch 'Backend'`
            },
            {
                stepNum: 4,
                id: 'step-4',
                title: 'ขั้นตอนที่ 4: สร้างไฟล์คอนฟิก .env สำหรับ Production',
                reason: '💡 <strong>เหตุผลที่ต้องทำ:</strong> เพื่อกำหนดรหัสผ่านและความปลอดภัยของ ClickHouse Database, Redis, และการเชื่อมต่อ Telegram Bot Alert ไม่ให้ใช้ค่า Default สาธารณะบนคลาวด์',
                code: `# สร้างไฟล์ .env บน VPS เครื่องของคุณ
cat << 'EOF' > .env
PROJECT_NAME="WAF CDN System"
ENVIRONMENT="production"
AWS_REGION="ap-southeast-1"
AWS_ACCESS_KEY_ID="dummy"
AWS_SECRET_ACCESS_KEY="dummy"
CLICKHOUSE_HOST="clickhouse"
CLICKHOUSE_PORT="8123"
CLICKHOUSE_USER="default"
CLICKHOUSE_PASSWORD="***REDACTED***"
REDIS_HOST="redis"
REDIS_PORT="6379"
TELEGRAM_BOT_TOKEN="***REDACTED***"
TELEGRAM_CHAT_ID="your_telegram_chat_id_here"
EOF`,
                expectedOutput: `root@ubuntu:~/waf_project# cat .env
PROJECT_NAME="WAF CDN System"
ENVIRONMENT="production"
CLICKHOUSE_HOST="clickhouse"
CLICKHOUSE_PORT="8123"
CLICKHOUSE_USER="default"
CLICKHOUSE_PASSWORD="***REDACTED***"
REDIS_HOST="redis"
REDIS_PORT="6379"
TELEGRAM_BOT_TOKEN="***REDACTED***"
TELEGRAM_CHAT_ID="your_telegram_chat_id_here"`
            },
            {
                stepNum: 5,
                id: 'step-5',
                title: 'ขั้นตอนที่ 5: Build หน้าจอ React Frontend',
                reason: '💡 <strong>เหตุผลที่ต้องทำ:</strong> โค้ดฝั่ง UI ถูกเขียนด้วย React (JSX/TSX) เบราว์เซอร์ไม่สามารถอ่านได้โดยตรง เราต้องสั่ง <code>npm run build</code> เพื่อคอมไพล์โค้ดเป็นไฟล์ HTML/CSS/JS รวมในโฟลเดอร์ <code>dist/</code> เพื่อให้ FastAPI Backend นำไปเสิร์ฟหน้าจอ Dashboard',
                code: `# 1. ย้ายเข้าโฟลเดอร์ dashboard/frontend
cd dashboard/frontend

# 2. ติดตั้ง Dependencies และสั่ง Build
npm install
npm run build

# 3. ถอยกลับมาที่โฟลเดอร์หลักของโปรเจกต์
cd ../..`,
                expectedOutput: `added 245 packages, and audited 246 packages in 12s

> waf-dashboard-frontend@1.0.0 build
> vite build

transforming (34) index.html...
✓ 142 modules transformed.
dist/index.html                   0.48 kB │ gzip:  0.31 kB
dist/assets/index-B7y9-cZa.css   24.18 kB │ gzip:  4.82 kB
dist/assets/index-Dx0v7-1k.js   342.12 kB │ gzip: 98.45 kB
✓ built in 2.84s`
            },
            {
                stepNum: 6,
                id: 'step-6',
                title: 'ขั้นตอนที่ 6: สตาร์ท Docker Stack & รัน FastAPI Backend (Port 8000)',
                reason: '💡 <strong>สำคัญมาก (แก้ปัญหา 500 & Port 8000):</strong> สตาร์ท Docker Containers และสั่งรัน <code>python3 main.py</code> ในโฟลเดอร์ Backend เพื่อให้พอร์ต 8000 ทำงาน (ซึ่งจะทำให้ WAF พอร์ต 8080 ไม่ติดปัญหา 500 อีกต่อไป!)',
                code: `# 1. สตาร์ท Docker Containers ทั้งหมด
docker compose up -d

# 2. ติดตั้ง Python Dependencies และรัน FastAPI Backend (Port 8000) ในเบื้องหลัง
cd dashboard/backend
pip install -r requirements.txt --break-system-packages
nohup python3 main.py > backend.log 2>&1 &
cd ../..

# 3. ตรวจสอบว่าพอร์ต 8000 ตอบกลับเรียบร้อย
curl -I http://localhost:8000/docs`,
                expectedOutput: `[+] Running 6/6
 ✔ Container dvwa                   Started   0.4s
 ✔ Container waf-redis              Started   0.4s
 ✔ Container waf-clickhouse         Started   0.4s
 ✔ Container waf-nginx              Started   0.8s
 ✔ Container caddy-ssl-termination  Started   1.1s

root@ubuntu:~/waf_project# curl -I http://localhost:8000/docs
HTTP/1.1 200 OK
date: Fri, 07 Aug 2026 11:20:00 GMT
server: uvicorn
content-type: text/html; charset=utf-8`
            },
            {
                stepNum: 7,
                id: 'step-7',
                title: 'ขั้นตอนที่ 7: ตั้งค่า Firewall (UFW) และทดสอบเข้าใช้งาน',
                reason: '💡 <strong>เหตุผลที่ต้องทำ:</strong> เพื่อเปิดพอร์ต 80 (HTTP), 443 (HTTPS), 8000 (Dashboard API), 22 (SSH) และบล็อกพอร์ตอื่น ๆ เพื่อป้องกันแฮกเกอร์โจมตีตรงเข้าฐานข้อมูล ClickHouse',
                code: `# 1. เปิดพอร์ตใช้งานใน Firewall
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 8000/tcp

# 2. เปิดใช้งาน UFW Firewall (พิมพ์ y ยืนยัน)
ufw --force enable

# 3. ทดสอบเช็กพอร์ต 8080 (WAF) และ 8000 (Dashboard):
curl -I http://localhost:8080/
curl -I http://localhost:8000/docs`,
                expectedOutput: `root@ubuntu:~/waf_project# curl -I http://localhost:8080/
HTTP/1.1 302 Found
Server: nginx/1.24.0
Date: Fri, 07 Aug 2026 11:20:10 GMT
Location: login.php

root@ubuntu:~/waf_project# curl -I http://localhost:8000/docs
HTTP/1.1 200 OK
Server: uvicorn`
            }
        ]
    },
    'verification-check': {
        isVerification: true,
        title: '🔍 คำสั่งเช็กระบบ & ผลลัพธ์ที่ถูกต้อง (System Health Check Suite)',
        subtitle: 'รวมคำสั่งตรวจสอบสถานะการทำงานของแต่ละส่วนในระบบ พร้อมตัวอย่างผลลัพธ์ที่ถูกต้อง 100% ในการยืนยันว่าระบบเปิดใช้งานได้จริง',
        checks: [
            {
                num: 1,
                title: 'เช็กสถานะ Docker Containers ทั้งหมด (Container Health Check)',
                purpose: 'เพื่อดูว่า Container ทั้งหมดเปิดทำงานอยู่อย่างปกติหรือไม่',
                cmd: `docker compose ps`,
                expected: `NAME                     STATUS         PORTS
caddy-ssl-termination    Running        0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp
dvwa                     Running        
waf-clickhouse           Running        8123/tcp, 9000/tcp
waf-nginx                Running        0.0.0.0:8080->8080/tcp
waf-redis                Running        6379/tcp`
            },
            {
                num: 2,
                title: 'เช็กว่า FastAPI Backend (Port 8000) ทำงานหรือไม่',
                purpose: 'เพื่อสอบถามสถานะพอร์ต 8000 ของ Dashboard ว่าเปิดใช้งานสำเร็จหรือยัง',
                cmd: `curl -I http://localhost:8000/docs`,
                expected: `HTTP/1.1 200 OK
date: Fri, 07 Aug 2026 10:35:00 GMT
server: uvicorn
content-type: text/html; charset=utf-8`
            },
            {
                num: 3,
                title: 'เช็กว่า ModSecurity WAF Proxy (Port 8080) พร้อมรับ Traffic หรือไม่',
                purpose: 'เพื่อทดสอบพอร์ต 8080 ของ WAF Proxy ว่าหายจากอาการ 500 Error และพร้อมส่งทราฟฟิกหรือยัง',
                cmd: `curl -I http://localhost:8080/`,
                expected: `HTTP/1.1 302 Found
Server: nginx/1.24.0
Date: Fri, 07 Aug 2026 10:35:10 GMT
Location: login.php`
            },
            {
                num: 4,
                title: 'ทดสอบยิง Attack Request ดูว่า WAF บล็อก 403 Forbidden หรือไม่',
                purpose: 'ยิง SQL Injection คำสั่งจำลอง เพื่อดูว่า ModSecurity WAF บล็อกคำสั่งอันตรายสำเร็จหรือไม่',
                cmd: `curl -i "http://localhost:8080/?id=1'%20OR%201=1--"`,
                expected: `HTTP/1.1 403 Forbidden
Server: nginx/1.24.0
Content-Type: text/html

<html>
<head><title>403 Forbidden</title></head>
<body>
<center><h1>403 Forbidden - WAF Protection Triggered</h1></center>
</body>
</html>`
            }
        ]
    }
};

let completedSteps = new Set();
let currentDualEdgeSubMode = '2e-b';

function switchMethod(methodKey) {
    document.querySelectorAll('.method-tabs .tab-btn').forEach(btn => btn.classList.remove('active'));
    if (event && event.currentTarget) {
        event.currentTarget.classList.add('active');
    }

    const data = methodsData[methodKey];
    const container = document.getElementById('method-details-container');

    if (data.isVerification) {
        renderVerificationSection(data, container);
        return;
    }

    if (data.isTutorial) {
        renderTutorialSection(data, container);
        return;
    }

    let prosListHtml = (data.pros || []).map(p => `<li><i class="fa-solid fa-circle-check"></i> ${p}</li>`).join('');
    let consListHtml = (data.cons || []).map(c => `<li><i class="fa-solid fa-circle-xmark"></i> ${c}</li>`).join('');

    let stepsHtml = '';
    if (data.steps && data.steps.length > 0) {
        stepsHtml = `
            <div class="steps-container">
                <h5 style="font-family: var(--font-heading); font-size: 18px; color: #fff; margin-bottom: 16px;">
                    <i class="fa-solid fa-list-check" style="color: var(--primary);"></i> ขั้นตอนการติดตั้งอย่างละเอียด
                </h5>
                ${data.steps.map(s => `
                    <div class="step-item">
                        <div class="step-header">
                            <span class="step-badge">${s.stepNum}</span>
                            <span class="step-title">${s.title}</span>
                        </div>
                        <p style="font-size: 14px; color: var(--text-muted); margin-bottom: 8px;">${s.desc}</p>
                        ${s.code ? `
                            <div class="code-block-wrapper">
                                <div class="code-header">
                                    <span><i class="fa-solid fa-terminal"></i> Terminal Command</span>
                                    <button class="copy-btn" onclick="copyCode(this)"><i class="fa-regular fa-copy"></i> คัดลอก</button>
                                </div>
                                <pre><code>${escapeHtml(s.code)}</code></pre>
                            </div>
                        ` : ''}
                    </div>
                `).join('')}
            </div>
        `;
    }

    container.innerHTML = `
        <div class="details-header">
            <h4>${data.title}</h4>
            <p>${data.subtitle}</p>
        </div>

        <div class="panel-grid-2">
            <div class="card-box pros">
                <h5><i class="fa-solid fa-thumbs-up"></i> ข้อดี (Advantages)</h5>
                <ul class="feature-list pros-list">${prosListHtml}</ul>
            </div>
            <div class="card-box cons">
                <h5><i class="fa-solid fa-thumbs-down"></i> ข้อเสีย / ข้อจำกัด (Limitations)</h5>
                <ul class="feature-list cons-list">${consListHtml}</ul>
            </div>
        </div>

        ${stepsHtml}
    `;
}

function renderVerificationSection(data, container) {
    const checksHtml = data.checks.map(c => `
        <div class="tutorial-step-card" style="border-left: 4px solid var(--accent);">
            <div class="step-card-header">
                <div class="step-title-wrap">
                    <span class="step-num-badge" style="background: var(--accent);">${c.num}</span>
                    <span class="step-card-title">${c.title}</span>
                </div>
            </div>
            <p style="font-size: 13.5px; color: var(--text-muted); margin-bottom: 12px;">${c.purpose}</p>

            <div class="code-block-wrapper">
                <div class="code-header">
                    <span><i class="fa-solid fa-terminal"></i> คำสั่งเช็กบน Terminal</span>
                    <button class="copy-btn" onclick="copyCode(this)"><i class="fa-regular fa-copy"></i> คัดลอกคำสั่งเช็ก</button>
                </div>
                <pre><code>${escapeHtml(c.cmd)}</code></pre>
            </div>

            <div class="output-block-wrapper">
                <div class="output-header">
                    <span><i class="fa-solid fa-square-check"></i> ผลลัพธ์ตัวอย่างที่ถูกต้องเมื่อรันคำสั่งเช็กนี้:</span>
                    <span class="expected-badge"><i class="fa-solid fa-circle-check"></i> Valid Response</span>
                </div>
                <pre><code>${escapeHtml(c.expected)}</code></pre>
            </div>
        </div>
    `).join('');

    container.innerHTML = `
        <div class="details-header">
            <h4>${data.title}</h4>
            <p>${data.subtitle}</p>
        </div>
        ${checksHtml}
    `;
}

function renderTutorialSection(data, container) {
    const stepsHtml = data.steps.map(s => {
        const isDone = completedSteps.has(s.id);
        return `
            <div class="tutorial-step-card ${isDone ? 'completed' : ''}" id="card-${s.id}">
                <div class="step-card-header">
                    <div class="step-title-wrap">
                        <span class="step-num-badge">${s.stepNum}</span>
                        <span class="step-card-title">${s.title}</span>
                    </div>
                    <label class="checkbox-wrap">
                        <input type="checkbox" ${isDone ? 'checked' : ''} onchange="toggleStepProgress('${s.id}')">
                        <span>ทำขั้นนี้เสร็จแล้ว</span>
                    </label>
                </div>
                
                <div class="reason-box">
                    ${s.reason}
                </div>

                <div class="code-block-wrapper">
                    <div class="code-header">
                        <span><i class="fa-solid fa-terminal"></i> คำสั่งบน VPS (root@ubuntu:~#)</span>
                        <button class="copy-btn" onclick="copyCode(this)"><i class="fa-regular fa-copy"></i> คัดลอกสคริปต์</button>
                    </div>
                    <pre><code>${escapeHtml(s.code)}</code></pre>
                </div>

                ${s.expectedOutput ? `
                    <div class="output-block-wrapper">
                        <div class="output-header">
                            <span><i class="fa-solid fa-square-poll-vertical"></i> ผลลัพธ์ตัวอย่างที่ถูกต้องเมื่อพิมพ์คำสั่งนี้ (Expected Output Sample):</span>
                            <span class="expected-badge"><i class="fa-solid fa-check"></i> Output Success</span>
                        </div>
                        <pre><code>${escapeHtml(s.expectedOutput)}</code></pre>
                    </div>
                ` : ''}
            </div>
        `;
    }).join('');

    container.innerHTML = `
        <div class="details-header">
            <h4>${data.title}</h4>
            <p>${data.subtitle}</p>
        </div>
        ${stepsHtml}
    `;
    updateProgressBar();
}

function toggleStepProgress(stepId) {
    if (completedSteps.has(stepId)) {
        completedSteps.delete(stepId);
    } else {
        completedSteps.add(stepId);
    }
    
    const card = document.getElementById(`card-${stepId}`);
    if (card) {
        if (completedSteps.has(stepId)) {
            card.classList.add('completed');
        } else {
            card.classList.remove('completed');
        }
    }

    updateProgressBar();
}

function updateProgressBar() {
    const total = 7;
    const count = completedSteps.size;
    const percent = Math.round((count / total) * 100);

    const fill = document.getElementById('tutorial-progress-fill');
    const text = document.getElementById('tutorial-progress-text');

    if (fill) fill.style.width = `${percent}%`;
    if (text) text.innerText = `${count} / ${total} ขั้นตอน (${percent}%)`;
}

function escapeHtml(text) {
    return text.replace(/&/g, "&amp;")
               .replace(/</g, "&lt;")
               .replace(/>/g, "&gt;");
}

function copyCode(btn) {
    const code = btn.closest('.code-block-wrapper').querySelector('code').innerText;
    navigator.clipboard.writeText(code).then(() => {
        showToast('คัดลอกคำสั่งไปยัง Clipboard แล้ว!');
    });
}

function showToast(msg) {
    const toast = document.getElementById('toast');
    toast.innerHTML = `<i class="fa-solid fa-check"></i> ${msg}`;
    toast.classList.add('show');
    setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
}

function calculateSpec() {
    const traffic = document.getElementById('calc-traffic').value;
    const retention = document.getElementById('calc-retention').value;
    const provider = document.getElementById('calc-provider').value;

    let cpu = "2 vCPU";
    let ram = "4 GB RAM";
    let disk = "50 GB SSD";
    let priceUSD = 12;

    if (traffic === 'low') {
        cpu = "2 vCPU"; ram = "4 GB RAM"; disk = retention === '90' ? "80 GB SSD" : "50 GB SSD";
        priceUSD = provider === 'hetzner' ? 8 : (provider === 'aws' ? 18 : 14);
    } else if (traffic === 'med') {
        cpu = "4 vCPU"; ram = "8 GB RAM"; disk = retention === '90' ? "120 GB SSD" : "80 GB NVMe";
        priceUSD = provider === 'hetzner' ? 14 : (provider === 'aws' ? 36 : 24);
    } else if (traffic === 'high') {
        cpu = "8 vCPU"; ram = "16 GB RAM"; disk = retention === '90' ? "250 GB NVMe" : "160 GB NVMe";
        priceUSD = provider === 'hetzner' ? 32 : (provider === 'aws' ? 72 : 48);
    }

    const priceTHB = Math.round(priceUSD * 35);

    document.getElementById('res-cpu').innerText = cpu;
    document.getElementById('res-ram').innerText = ram;
    document.getElementById('res-disk').innerText = disk;
    document.getElementById('res-price').innerText = `~$${priceUSD}.00 / เดือน (ประมาณ ${priceTHB.toLocaleString()} บาท)`;
}

function openQuickAnswerModal() {
    document.getElementById('quick-modal').classList.add('active');
}

function closeQuickAnswerModal(e) {
    if (!e || e.target.classList.contains('modal-overlay') || e.target.classList.contains('close-btn')) {
        document.getElementById('quick-modal').classList.remove('active');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    switchMethod('vps-tutorial');
    calculateSpec();
});
