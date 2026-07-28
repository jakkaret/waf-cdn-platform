#!/usr/bin/env python3
import os
import sys
import subprocess
import threading
import queue
import time
import argparse
from typing import List, Dict, Any

# Define tests config with highly detailed diagnostic checklists
TESTS = [
    {
        "id": "e2e_flow",
        "name": "E2E Flow Test",
        "category": "Backend",
        "path": "dashboard/backend/test_e2e_flow.py",
        "summary": "ตรวจสอบการลงทะเบียนผู้เช่ารายใหม่, การล็อกอินรับ Token และตรวจสอบสถานะคอมโพเนนต์หลัก",
        "details": (
            "• สมัครสมาชิกผู้เช่ารายใหม่ด้วยข้อมูลแบบสุ่ม\n"
            "• ล็อกอินเข้าระบบเพื่อตรวจสอบความถูกต้องของ JWT Access Token\n"
            "• คิวรี API ข้อมูลสถานะและสุขภาพ (System Health Monitor) ของทั้งระบบ\n"
            "• ตรวจสอบฐานข้อมูล DynamoDB ว่ามีสถานะออนไลน์ (ONLINE)\n"
            "• ตรวจสอบบริการหลังบ้าน (Nginx, DVWA, CDN Control API, GeoDNS, Stats) ว่าทำงานปกติ\n"
            "• ตรวจสอบสถานะการทำงานของ Background Workers (Log Ingestion, CDN Log Sync, DNS Check)"
        )
    },
    {
        "id": "origins_api",
        "name": "Origins API Test",
        "category": "Backend",
        "path": "dashboard/backend/test_origins_api.py",
        "summary": "ทดสอบระบบ CRUD ของ Origin Server และการซิงค์ข้อมูลกับ AWS DynamoDB",
        "details": (
            "• สร้างข้อมูล Origin Server (เป้าหมายทราฟฟิก) ชุดใหม่เข้าระบบ\n"
            "• ตรวจสอบการทำ IP validation และเงื่อนไขข้อจำกัดของฟอร์แมตไอพี\n"
            "• ดึงข้อมูล Origin ทั้งหมดโดยฟิลเตอร์ตาม ID ของผู้ดูแลระบบผู้เช่า\n"
            "• ทดสอบแก้ไขอัปเดตป้ายกำกับ (Label), พอร์ต, และสถานะ\n"
            "• ทดสอบลบข้อมูลพร้อมประเมินผลการบันทึกซิงค์ในฐานข้อมูล DynamoDB"
        )
    },
    {
        "id": "system_status_api",
        "name": "System Status API Test",
        "category": "Backend",
        "path": "dashboard/backend/test_system_status_api.py",
        "summary": "ตรวจสอบทรัพยากรเครื่องเซิร์ฟเวอร์หลักและเปิดเช็คพอร์ตเชื่อมต่อตู้คอนเทนเนอร์",
        "details": (
            "• ตรวจสอบการกรอง Authorization Header บน API บอกสถานะสุขภาพระบบ\n"
            "• ตรวจจับการเปิดพอร์ตหลัก (8080 WAF, 80 Caddy/DVWA, 8070 Control, 9090 Stats)\n"
            "• ตรวจสอบความพร้อมการตอบรับของตู้คอนเทนเนอร์ Docker ต่างๆ\n"
            "• ดึงสถิติปริมาณพื้นที่ดิสก์ที่ใช้และคงเหลือในระบบ (Total, Used, Free GB)\n"
            "• คำนวณค่าภาระการประมวลผล CPU Load Average ย้อนหลัง (1m, 5m, 15m) แบบสด"
        )
    },
    {
        "id": "dns_verification",
        "name": "DNS Verification Test",
        "category": "Integration / WAF",
        "path": "scripts/test_dns_verification.py",
        "summary": "ตรวจสอบระบบ CNAME/TXT DNS query อัตโนมัติและการอนุมัติโดเมน",
        "details": (
            "• จำลองการตรวจสอบประวัติเรคคอร์ด CNAME ชี้ไปยัง Edge Nodes\n"
            "• ตรวจสอบ TXT token ว่ามีค่าตรงกับคีย์ยืนยันตัวตนในระบบ\n"
            "• ตรวจสอบการปรับเปลี่ยนสถานะของโดเมนในฐานข้อมูลจาก pending เป็น dns_verified=True\n"
            "• ทดสอบความถี่รอบเวลาประมวลผลของ Worker ตรวจจับโดเมนที่ยังไม่ยืนยัน"
        )
    },
    {
        "id": "rate_limiter",
        "name": "Rate Limiter Test",
        "category": "Integration / WAF",
        "path": "scripts/test_rate_limiter.py",
        "summary": "ทดสอบระบบสกัดกั้นทราฟฟิกผ่าน Nginx proxy และ Redis sliding-window",
        "details": (
            "• ล้างประวัติจำกัดทราฟฟิกเก่าทั้งหมดบน Redis ก่อนเริ่มทดสอบ\n"
            "• ส่งคำขอ HTTP แบบถี่ปกติ 10 ครั้งภายใน 10 วินาทีเพื่อเช็คการปล่อยผ่าน\n"
            "• ส่งคำขอที่ 11 เพื่อยืนยันว่าการป้องกันตอบกลับด้วย HTTP 429 (Too Many Requests)\n"
            "• ตรวจสอบค่า 'Retry-After' ใน Header การตอบกลับ\n"
            "• รอจนหมดกรอบเวลาจำกัดเพื่อทดสอบการปล่อยกลับมาใช้งานได้ปกติอีกครั้ง"
        )
    },
    {
        "id": "cdn_logs",
        "name": "CDN Logs Test",
        "category": "Integration / WAF",
        "path": "scripts/test_cdn_logs.py",
        "summary": "ทดสอบระบบสืบค้น access logs และดึงค่า Latency Metrics ของโหนด CDN",
        "details": (
            "• คิวรีข้อมูล CDN Access logs ของแต่ละโหนดผ่าน API ล็อก\n"
            "• ตรวจสอบความสมบูรณ์ของโครงสร้าง JSON ที่ได้รับ\n"
            "• ดึงข้อมูลสถิติแนวโน้มความหน่วงเฉลี่ยรายภูมิภาค (SG, JP, TH)\n"
            "• ประเมินความเร็วในการคิวรีข้อมูลดัชนี (Index Query) บนฐานข้อมูล"
        )
    },
    {
        "id": "clickhouse_analytics",
        "name": "ClickHouse Analytics Test",
        "category": "Integration / WAF",
        "path": "scripts/test_clickhouse_analytics.py",
        "summary": "ตรวจสอบระบบรวมล็อก ModSecurity, การเขียนข้อมูลเข้า ClickHouse และระบบสรุปภัยคุกคามด้วย AI",
        "details": (
            "• จำลองยิงทราฟฟิกปกติ 3 คำขอ และพยายามยิงเจาะระบบผ่าน SQL Injection 1 คำขอ\n"
            "• ทดสอบการรวม Nginx Access Log คู่กับ ModSecurity Audit Log ด้วยคีย์ Transaction ID\n"
            "• ตรวจจับการนำส่งล็อกที่รวมแล้วไปเขียนบันทึกลงตารางฐานข้อมูล ClickHouse\n"
            "• เรียกใช้งาน API สรุปภัยคุกคาม WAF ด้วยปัญญาประดิษฐ์ (AI Summary) เพื่อรับข้อความอธิบายเป็นภาษาธรรมชาติ"
        )
    },
    {
        "id": "integration",
        "name": "Integration Test",
        "category": "Integration / WAF",
        "path": "scripts/test_integration.py",
        "summary": "ทดสอบยิงเจาะระบบ WAF และตรวจสอบการควบคุมความถี่ด้วย slowapi",
        "details": (
            "• ทดสอบความสมบูรณ์ของการสมัครสมาชิกและการแกะโทเคน JWT\n"
            "• เรียกใช้งาน API ส่วนตัวที่ถูกป้องกันไว้ด้วย Authorization Token\n"
            "• ส่งคำขอเข้าสู่ระบบถี่เกินโควตาเพื่อทดสอบความแม่นยำของ slowapi rate limits (5 ครั้งต่อนาที)"
        )
    },
    {
        "id": "tunnel_flow",
        "name": "Tunnel Flow Test",
        "category": "Integration / WAF",
        "path": "scripts/test_tunnel_flow.py",
        "summary": "ทดสอบการจัดตั้ง Zero-Trust Outbound Tunnel ระหว่างเอเจนต์กับเซิร์ฟเวอร์เพื่อเชื่อมต่อทราฟฟิก",
        "details": (
            "• บันทึกข้อมูลเป้าหมายเว็บจำลอง (Origin Target) ในฐานข้อมูล\n"
            "• สตาร์ทบริการเซิร์ฟเวอร์อุโมงค์ WAF Tunnel Server บนพอร์ต 8050\n"
            "• สตาร์ทฝั่งเอเจนต์ลูกค้า Tunnel Agent เพื่อเชื่อมต่อส่งสัญญารับส่ง Token ผ่านอุโมงค์\n"
            "• ยิงทราฟฟิกผ่านอุโมงค์สำเร็จโดยไม่ต้องเปิดพอร์ตไฟร์วอลล์ฝั่งลูกค้าขาเข้า (Inbound Firewall)\n"
            "• ยืนยันการเชื่อมโยงระบบปลายทางว่าสามารถตอบกลับ HTTP 200 OK ได้อย่างปลอดภัย"
        )
    },
    {
        "id": "cdn_failover",
        "name": "CDN Failover Test",
        "category": "CDN Edge",
        "path": "cdn/scripts/test_failover.py",
        "summary": "ตรวจสอบระบบตรวจสอบสุขภาพของ GeoDNS และระบบจำลองโหนดย้ายสายการใช้งานอัตโนมัติ",
        "details": (
            "• ตรวจคิวรีสถานะเซิร์ฟเวอร์ภูมิภาคผ่าน GeoDNS status API\n"
            "• คิวรีคำขอผ่าน GeoDNS Resolver บนพอร์ต 5533 ด้วยไอพีจำลองของฝั่งผู้เข้าใช้งาน\n"
            "• ตรวจเช็คว่าผู้ใช้ถูกนำเส้นทางไปยังโหนด Edge ที่ใกล้ที่สุด (TH/SG/JP) อย่างถูกต้อง\n"
            "• จำลองสถานการณ์โหนดล่ม (Downtime) เพื่อยืนยันว่าการกระจายทราฟฟิกเปลี่ยนเส้นทางไปหาโหนดอื่นได้อัตโนมัติ"
        )
    },
    {
        "id": "cdn_rate_limit",
        "name": "CDN Rate Limit Test",
        "category": "CDN Edge",
        "path": "cdn/scripts/test_rate_limit.py",
        "summary": "จำลองยิงทราฟฟิกเพื่อทดสอบการจำกัดความถี่และค่า burst บนเซิร์ฟเวอร์ขอบสนามของแต่ละภูมิภาค",
        "details": (
            "• สั่งการส่งคำขอแบบขนานพร้อมกันปริมาณสูง (Multithreaded) ไปยังขอบสนามแต่ละโหนด (พอร์ต 8081, 8082, 8086)\n"
            "• ตรวจสอบจุดเปลี่ยนเมื่อจำนวนคำขอเกินจุด Burst (SG/JP burst=60, TH burst=100)\n"
            "• เช็คว่าการสกัดกั้นตอบกลับด้วยรหัส 429 Too Many Requests ทำงานสอดคล้องกับการตั้งค่าตัวกรองความถี่"
        )
    },
    {
        "id": "cdn_routing",
        "name": "CDN Routing Test",
        "category": "CDN Edge",
        "path": "cdn/scripts/test_routing.py",
        "summary": "ตรวจสอบนโยบาย Cache-Control Header ของคำขอแบบ Dynamic และ Static ในแต่ละภูมิภาค",
        "details": (
            "• ยิงคำขอไปยังเส้นทางไดนามิก และตรวจสอบนโยบาย Cache-Control public max-age=600\n"
            "• ยิงคำขอไปยังไฟล์จำลองคงที่ และตรวจสอบนโยบาย Cache-Control max-age=3600 (immutable)\n"
            "• ยืนยันการตั้งค่าความปลอดภัย X-Content-Type-Options: nosniff\n"
            "• ตรวจสอบให้แน่ใจว่าตัวควบคุมความถี่ (Rate limit) ของเนื้อหาแบบ Static แยกอิสระจาก Dynamic"
        )
    },
    {
        "id": "cdn_tls_edge",
        "name": "CDN TLS Edge Test",
        "category": "CDN Edge",
        "path": "cdn/scripts/test_tls_edge.py",
        "summary": "ตรวจสอบความปลอดภัยการทำ HTTPS Handshake และไฟล์ใบรับรอง SSL ใบรับรองบนขอบสนาม",
        "details": (
            "• ตรวจสอบกระบวนการทำ SSL/TLS Handshake กับ Edge SG, JP, และ TH\n"
            "• ตรวจสอบว่าโหนดส่งคืนสถานะ 200 OK ผ่าน HTTPS พอร์ต 8441, 8442, และ 8446 ได้อย่างถูกต้อง\n"
            "• ตรวจจับการเปิดบริการใบรับรอง (Self-signed certificate) ของแต่ละภูมิภาค"
        )
    },
    {
        "id": "cdn_phase4a",
        "name": "CDN Phase 4a Test",
        "category": "CDN Edge",
        "path": "cdn/scripts/test_phase4a.py",
        "summary": "จำลองคำขอบริการเว็บขอบสนามเพื่อตรวจสอบความพร้อมการบันทึกล็อกเข้าสู่ CDN access logs",
        "details": (
            "• ส่งคำขอทดสอบไปยัง CDN Edges ภูมิภาคต่างๆ เพื่อให้เกิดการบันทึกล็อกจริงบนเซิร์ฟเวอร์\n"
            "• จำลองเงื่อนไขที่ส่งผลให้เกิดการแคช Hits, Cache Misses, และ Cache Bypass ในระบบ\n"
            "• ตรวจสอบความถูกต้องของการแปลงล็อกดิบลงสู่ไฟล์ access.json เพื่อส่งข้อมูลต่อไปยัง Forwarder"
        )
    }
]

# Project Root directory
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Log state store
test_status = {t["id"]: "idle" for t in TESTS}  # idle, running, passed, failed

# CLI Interactive Mode
def run_cli_mode():
    print("=" * 70)
    print("🛡️  WAF PROJECT — CONSOLIDATED TEST RUNNER UTILITY (CLI MODE)")
    print("=" * 70)
    
    while True:
        print("\nAvailable Categories:")
        categories = ["All"] + sorted(list(set(t["category"] for t in TESTS)))
        for idx, cat in enumerate(categories):
            print(f"  [{idx + 1}] {cat}")
            
        print("\nActions:")
        print("  [A] Run All Tests sequentially")
        print("  [Q] Quit Diagnostic Suite")
        
        choice = input("\nSelect a category [1-4], action [A/Q], or type index of a specific test: ").strip().lower()
        
        if choice == 'q':
            print("Exiting. Goodbye!")
            break
        elif choice == 'a':
            run_multiple_tests(TESTS)
        elif choice.isdigit():
            c_idx = int(choice) - 1
            if 0 <= c_idx < len(categories):
                # Show tests under category
                cat_name = categories[c_idx]
                cat_tests = TESTS if cat_name == "All" else [t for t in TESTS if t["category"] == cat_name]
                print(f"\n--- Diagnostic Tests in '{cat_name}' ---")
                for t_idx, t in enumerate(cat_tests):
                    status_symbol = "⚪ Idle"
                    if test_status[t["id"]] == "passed": status_symbol = "🟢 Passed"
                    elif test_status[t["id"]] == "failed": status_symbol = "🔴 Failed"
                    elif test_status[t["id"]] == "running": status_symbol = "🟡 Running"
                    print(f"  {t_idx + 1}. [{status_symbol}] {t['name']}")
                    print(f"      Scope: {t['summary']}")
                    
                sub_choice = input("\nEnter test index to Execute (or Enter to go back): ").strip()
                if sub_choice.isdigit():
                    t_sub = int(sub_choice) - 1
                    if 0 <= t_sub < len(cat_tests):
                        run_single_test(cat_tests[t_sub])
            else:
                print("⚠️ Invalid menu index choice.")
        else:
            print("⚠️ Unknown action. Please try again.")

def run_single_test(test_dict: Dict[str, Any]):
    test_id = test_dict["id"]
    test_name = test_dict["name"]
    script_path = os.path.join(ROOT_DIR, test_dict["path"])
    
    print("\n" + "=" * 60)
    print(f"🚀 Running: {test_name}")
    print(f"📂 Script : {test_dict['path']}")
    print(f"🔬 Scope  : {test_dict['summary']}")
    print("=" * 60 + "\n")
    
    test_status[test_id] = "running"
    
    try:
        process = subprocess.Popen(
            [sys.executable, script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=ROOT_DIR,
            bufsize=1
        )
        
        for line in process.stdout:
            print(line, end="")
            
        process.wait()
        
        if process.returncode == 0:
            print(f"\n🟢 PASSED: {test_name} completed successfully.\n")
            test_status[test_id] = "passed"
        else:
            print(f"\n🔴 FAILED: {test_name} exited with code {process.returncode}.\n")
            test_status[test_id] = "failed"
            
    except Exception as e:
        print(f"\n💥 ERROR: Execution crashed: {e}\n")
        test_status[test_id] = "failed"

def run_multiple_tests(tests_list: List[Dict[str, Any]]):
    passed = 0
    failed = 0
    total = len(tests_list)
    
    print(f"\n🏃 Running batch process for {total} tests...\n")
    for t in tests_list:
        run_single_test(t)
        if test_status[t["id"]] == "passed":
            passed += 1
        else:
            failed += 1
            
    print("=" * 60)
    print("📊 BATCH PROCESS SUMMARY")
    print(f"   Total executed: {total} | 🟢 Passed: {passed} | 🔴 Failed: {failed}")
    print("=" * 60)


# Check for Tkinter availability conditionally
try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False


if TKINTER_AVAILABLE:
    # Custom Tkinter Flat Button to bypass macOS native styling limitations
    class FlatButton(tk.Label):
        def __init__(self, parent, text, command, bg, fg, hover_bg, font, padx=12, pady=6, state="normal", **kwargs):
            self.command = command
            self.normal_bg = bg
            self.hover_bg = hover_bg
            self.normal_fg = fg
            self.state = state
            
            # Setup defaults that can be overridden by kwargs
            kwargs.setdefault("bg", bg if state == "normal" else "#1e293b")
            kwargs.setdefault("fg", fg if state == "normal" else "#475569")
            kwargs.setdefault("cursor", "hand2" if state == "normal" else "arrow")
            kwargs.setdefault("relief", "flat")
            kwargs.setdefault("bd", 0)
            
            super().__init__(
                parent,
                text=text,
                font=font,
                padx=padx,
                pady=pady,
                **kwargs
            )
            
            self.bind("<Button-1>", self._on_click)
            self.bind("<Enter>", self._on_enter)
            self.bind("<Leave>", self._on_leave)
            
        def _on_click(self, event):
            if self.state == "normal" and self.command:
                self.command()
                
        def _on_enter(self, event):
            if self.state == "normal":
                self.config(bg=self.hover_bg)
                
        def _on_leave(self, event):
            if self.state == "normal":
                self.config(bg=self.normal_bg)
                
        def config_state(self, state):
            self.state = state
            if state == "disabled":
                self.config(bg="#1e293b", fg="#475569", cursor="arrow") # Slate panel color, dark gray text
            else:
                self.config(bg=self.normal_bg, fg=self.normal_fg, cursor="hand2")

    # GUI Mode Implementation using clean, modern slate theme
    class WafTestRunnerGUI:
        def __init__(self, root):
            self.root = root
            self.root.title("WAF Diagnostic & Test Runner Suite")
            self.root.geometry("1100x720")
            
            # Soft Slate colors palette
            self.colors = {
                "bg": "#0f172a",          # slate-900 (deep background)
                "sidebar_bg": "#1e293b",  # slate-800 (dark panels)
                "card_bg": "#334155",     # slate-700 (light panels/cards)
                "text_primary": "#f8fafc", # slate-50 (bright text)
                "text_secondary": "#94a3b8", # slate-400 (muted text)
                "blue": "#3b82f6",        # blue-500 (action)
                "blue_hover": "#2563eb",  # blue-600
                "green": "#10b981",       # emerald-500 (passed)
                "red": "#ef4444",         # red-500 (failed)
                "yellow": "#f59e0b",      # amber-500 (running)
                "terminal_bg": "#020617", # slate-950 (terminal frame)
                "terminal_fg": "#e2e8f0"  # slate-200 (terminal text)
            }
            
            self.root.configure(bg=self.colors["bg"])
            
            # Grid weighting for responsiveness
            self.root.columnconfigure(0, weight=1)
            self.root.columnconfigure(1, weight=3)
            self.root.rowconfigure(0, weight=1)
            
            self.active_category = "All"
            self.selected_test = None
            self.run_queue = queue.Queue()
            self.active_thread = None
            self.is_running_batch = False
            
            # Tkinter font selections
            self.fonts = {
                "title": ("Helvetica", 14, "bold"),
                "header": ("Helvetica", 16, "bold"),
                "normal": ("Helvetica", 10),
                "normal_bold": ("Helvetica", 10, "bold"),
                "muted": ("Helvetica", 10),
                "terminal": ("Courier New", 10)
            }
            
            # Build UI layout elements
            self.create_widgets()
            
            # Queue listener loop
            self.root.after(50, self.update_console_logs)
            
        def create_widgets(self):
            # Setup modern ttk styles for Treeview and scrollbars
            self.style = ttk.Style()
            self.style.theme_use("clam")
            
            # Treeview styling
            self.style.configure(
                "Treeview",
                background=self.colors["sidebar_bg"],
                foreground=self.colors["text_primary"],
                rowheight=32,
                fieldbackground=self.colors["sidebar_bg"],
                font=self.fonts["normal"],
                bd=0,
                highlightthickness=0
            )
            self.style.map(
                "Treeview",
                background=[("selected", self.colors["blue"])],
                foreground=[("selected", self.colors["text_primary"])]
            )
            
            # Treeview Headers styling
            self.style.configure(
                "Treeview.Heading",
                background=self.colors["card_bg"],
                foreground=self.colors["text_primary"],
                font=self.fonts["normal_bold"],
                bd=0,
                relief="flat",
                padding=8
            )
            self.style.map(
                "Treeview.Heading",
                background=[("active", self.colors["card_bg"])],
                foreground=[("active", self.colors["text_primary"])]
            )
            
            # 1. Left Sidebar Filter Pane
            self.sidebar = tk.Frame(self.root, bg=self.colors["sidebar_bg"], width=240)
            self.sidebar.grid(row=0, column=0, sticky="nsew", padx=(0, 2), pady=0)
            self.sidebar.columnconfigure(0, weight=1)
            self.sidebar.rowconfigure(2, weight=1)
            
            # Logo frame
            logo_frame = tk.Frame(self.sidebar, bg=self.colors["sidebar_bg"], pady=20)
            logo_frame.grid(row=0, column=0, sticky="ew")
            
            logo_icon = tk.Label(logo_frame, text="🛡️", font=("Helvetica", 24), bg=self.colors["sidebar_bg"])
            logo_icon.pack()
            
            logo_lbl = tk.Label(
                logo_frame, 
                text="WAF Diagnostic Suite", 
                font=self.fonts["title"], 
                bg=self.colors["sidebar_bg"], 
                fg=self.colors["text_primary"]
            )
            logo_lbl.pack(pady=(5, 0))
            
            # Modern Flat Category Tabs
            self.cat_frame = tk.Frame(self.sidebar, bg=self.colors["sidebar_bg"], padx=15)
            self.cat_frame.grid(row=1, column=0, sticky="ew", pady=(10, 20))
            self.cat_frame.columnconfigure(0, weight=1)
            
            tk.Label(
                self.cat_frame, 
                text="SCOPE FILTERS", 
                font=("Helvetica", 9, "bold"), 
                bg=self.colors["sidebar_bg"], 
                fg=self.colors["text_secondary"]
            ).grid(row=0, column=0, sticky="w", pady=(0, 5))
            
            self.cat_buttons = {}
            categories = ["All", "Backend", "Integration / WAF", "CDN Edge"]
            for idx, cat in enumerate(categories):
                btn = FlatButton(
                    self.cat_frame,
                    text=f"  {cat}  ",
                    command=lambda c=cat: self.select_category(c),
                    bg=self.colors["blue"] if cat == "All" else self.colors["sidebar_bg"],
                    fg=self.colors["text_primary"],
                    hover_bg=self.colors["blue_hover"] if cat == "All" else self.colors["card_bg"],
                    font=self.fonts["normal_bold"],
                    anchor="w",
                    padx=12,
                    pady=10
                )
                btn.grid(row=idx + 1, column=0, sticky="ew", pady=3)
                self.cat_buttons[cat] = btn

            # Project Details Box inside Sidebar
            details_box = tk.Frame(self.sidebar, bg=self.colors["card_bg"], padx=12, pady=12)
            details_box.grid(row=3, column=0, sticky="ew", padx=15, pady=20)
            details_box.columnconfigure(0, weight=1)
            
            tk.Label(
                details_box,
                text="DIAGNOSTIC SCOPE",
                font=("Helvetica", 9, "bold"),
                bg=self.colors["card_bg"],
                fg=self.colors["text_primary"]
            ).grid(row=0, column=0, sticky="w")
            
            self.sidebar_details_lbl = tk.Label(
                details_box,
                text="Please select an execution script from the list view to audit active validation checks.",
                font=self.fonts["muted"],
                bg=self.colors["card_bg"],
                fg=self.colors["text_secondary"],
                wraplength=180,
                justify="left"
            )
            self.sidebar_details_lbl.grid(row=1, column=0, sticky="w", pady=(8, 0))

            # 2. Main Content Grid (Treeview + terminal console)
            self.main_content = tk.Frame(self.root, bg=self.colors["bg"], padx=15, pady=15)
            self.main_content.grid(row=0, column=1, sticky="nsew")
            self.main_content.columnconfigure(0, weight=1)
            self.main_content.rowconfigure(1, weight=3)  # Treeview
            self.main_content.rowconfigure(3, weight=2)  # Terminal
            
            # Header Label frame
            header_frame = tk.Frame(self.main_content, bg=self.colors["bg"])
            header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
            header_frame.columnconfigure(0, weight=1)
            
            self.header_title = tk.Label(
                header_frame,
                text="WAF System Verification Grid",
                font=self.fonts["header"],
                bg=self.colors["bg"],
                fg=self.colors["text_primary"]
            )
            self.header_title.grid(row=0, column=0, sticky="w")
            
            self.header_desc = tk.Label(
                header_frame,
                text="Run comprehensive unit validation and system checks. Track diagnostic statuses dynamically.",
                font=self.fonts["normal"],
                bg=self.colors["bg"],
                fg=self.colors["text_secondary"]
            )
            self.header_desc.grid(row=1, column=0, sticky="w", pady=2)
            
            # 3. Middle Treeview Table (Test scripts display)
            self.tree_frame = tk.Frame(self.main_content, bg=self.colors["bg"])
            self.tree_frame.grid(row=1, column=0, sticky="nsew", pady=(0, 15))
            self.tree_frame.columnconfigure(0, weight=1)
            self.tree_frame.rowconfigure(0, weight=1)
            
            cols = ("status", "name", "summary", "category")
            self.tree = ttk.Treeview(self.tree_frame, columns=cols, show="headings", style="Treeview")
            self.tree.grid(row=0, column=0, sticky="nsew")
            self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)
            
            self.tree.heading("status", text="Status", anchor="center")
            self.tree.heading("name", text="Diagnostic Test", anchor="w")
            self.tree.heading("summary", text="What It Tests (Scope Summary)", anchor="w")
            self.tree.heading("category", text="Category", anchor="w")
            
            self.tree.column("status", width=70, minwidth=60, stretch=False, anchor="center")
            self.tree.column("name", width=170, minwidth=140, stretch=False, anchor="w")
            self.tree.column("summary", width=420, minwidth=300, stretch=True, anchor="w")
            self.tree.column("category", width=140, minwidth=110, stretch=False, anchor="w")
            
            # Scrollbars for treeview
            tree_scroll = ttk.Scrollbar(self.tree_frame, orient="vertical", command=self.tree.yview)
            tree_scroll.grid(row=0, column=1, sticky="ns")
            self.tree.configure(yscrollcommand=tree_scroll.set)
            
            # Fill tree list initial
            self.populate_tree_table()
            
            # 4. Interactive Action Controls Box
            self.controls_box = tk.Frame(self.main_content, bg=self.colors["bg"])
            self.controls_box.grid(row=2, column=0, sticky="ew", pady=(0, 10))
            
            self.btn_run = FlatButton(
                self.controls_box,
                text=" ▶  Run Selection ",
                command=self.run_selected_tree_test,
                bg=self.colors["blue"],
                fg=self.colors["text_primary"],
                hover_bg=self.colors["blue_hover"],
                font=self.fonts["normal_bold"],
                padx=16,
                pady=8,
                state="disabled"
            )
            self.btn_run.pack(side="left", padx=(0, 10))
            
            self.btn_run_all = FlatButton(
                self.controls_box,
                text=" 🏃  Run Category Group ",
                command=self.run_all_visible_tests,
                bg=self.colors["card_bg"],
                fg=self.colors["text_primary"],
                hover_bg=self.colors["sidebar_bg"],
                font=self.fonts["normal_bold"],
                padx=16,
                pady=8
            )
            self.btn_run_all.pack(side="left", padx=10)
            
            self.btn_clear_logs = FlatButton(
                self.controls_box,
                text=" 🗑️  Clear Logs ",
                command=self.clear_terminal_view,
                bg=self.colors["bg"],
                fg=self.colors["text_secondary"],
                hover_bg=self.colors["sidebar_bg"],
                font=self.fonts["normal"],
                padx=14,
                pady=6,
                bd=1,
                relief="solid",
                highlightthickness=0
            )
            # Custom tk adjustments for border
            self.btn_clear_logs.config(highlightbackground=self.colors["card_bg"], bd=1, relief="groove")
            self.btn_clear_logs.pack(side="left", padx=10)
            
            self.status_lbl = tk.Label(
                self.controls_box,
                text="Status: ⚪ Idle",
                font=self.fonts["normal_bold"],
                bg=self.colors["bg"],
                fg=self.colors["text_primary"],
                padx=15
            )
            self.status_lbl.pack(side="right")
            
            # 5. Live Logs Terminal Frame
            self.terminal_frame = tk.Frame(self.main_content, bg=self.colors["terminal_bg"], bd=1, relief="solid")
            self.terminal_frame.grid(row=3, column=0, sticky="nsew")
            self.terminal_frame.columnconfigure(0, weight=1)
            self.terminal_frame.rowconfigure(0, weight=1)
            
            self.terminal = scrolledtext.ScrolledText(
                self.terminal_frame,
                bg=self.colors["terminal_bg"],
                fg=self.colors["terminal_fg"],
                insertbackground="white",
                font=self.fonts["terminal"],
                wrap="word",
                bd=0,
                padx=10,
                pady=10
            )
            self.terminal.grid(row=0, column=0, sticky="nsew")
            self.terminal.insert("1.0", "--- WAF Diagnostic Console Terminal Logs ---\nReady to evaluate tests outputs.\n")
            self.terminal.configure(state="disabled")

        def select_category(self, category_name: str):
            self.active_category = category_name
            
            # Redraw category tabs visually using config
            for cat, btn in self.cat_buttons.items():
                if cat == category_name:
                    btn.config(bg=self.colors["blue"])
                    btn.normal_bg = self.colors["blue"]
                    btn.hover_bg = self.colors["blue_hover"]
                else:
                    btn.config(bg=self.colors["sidebar_bg"])
                    btn.normal_bg = self.colors["sidebar_bg"]
                    btn.hover_bg = self.colors["card_bg"]
                    
            self.populate_tree_table()
            
            # Reset current selection properties
            self.header_title.config(text=f"Diagnostic Scope: {self.active_category}")
            self.btn_run.config_state("disabled")
            self.selected_test = None
            self.status_lbl.config(text="Status: ⚪ Idle", fg=self.colors["text_primary"])
            self.sidebar_details_lbl.config(
                text=f"Batch diagnostics are available for group '{self.active_category}'. Click Run Group to execute sequentially.",
                fg=self.colors["text_secondary"]
            )

        def populate_tree_table(self):
            # Clear current tree rows
            for item in self.tree.get_children():
                self.tree.delete(item)
                
            # Filter tests list
            self.visible_tests = []
            for t in TESTS:
                if self.active_category == "All" or t["category"] == self.active_category:
                    self.visible_tests.append(t)
                    
                    # State icon/dot
                    status = test_status[t["id"]]
                    symbol = "⚪ Idle"
                    if status == "passed": symbol = "🟢 Passed"
                    elif status == "failed": symbol = "🔴 Failed"
                    elif status == "running": symbol = "🟡 Running"
                    
                    self.tree.insert(
                        "",
                        "end",
                        iid=t["id"],
                        values=(symbol, t["name"], t["summary"], t["category"])
                    )

        def on_tree_select(self, event):
            selected_items = self.tree.selection()
            if not selected_items:
                return
            
            test_id = selected_items[0]
            # Query config dict
            matches = [t for t in TESTS if t["id"] == test_id]
            if matches:
                self.selected_test = matches[0]
                
                # Show details in sidebar panel
                details_text = f"📂 Script: {self.selected_test['path']}\n\n🔬 Diagnostics Coverage:\n{self.selected_test['details']}"
                self.sidebar_details_lbl.config(text=details_text, fg=self.colors["text_primary"])
                
                # Update diagnostic status label
                status = test_status[self.selected_test["id"]]
                status_text = "Idle"
                status_fg = self.colors["text_primary"]
                if status == "passed":
                    status_text = "Passed 🟢"
                    status_fg = self.colors["green"]
                elif status == "failed":
                    status_text = "Failed 🔴"
                    status_fg = self.colors["red"]
                elif status == "running":
                    status_text = "Running 🟡"
                    status_fg = self.colors["yellow"]
                    
                self.status_lbl.config(text=f"Status: {status_text}", fg=status_fg)
                
                # Activate single test button if no active threads running
                if self.active_thread is None:
                    self.btn_run.config_state("normal")

        def run_selected_tree_test(self):
            if not self.selected_test or self.active_thread is not None:
                return
            
            self.clear_terminal_view()
            self.log_to_terminal(f"⏳ Launching single test: {self.selected_test['name']}...\n")
            self.is_running_batch = False
            
            self.disable_all_controls()
            
            test_status[self.selected_test["id"]] = "running"
            self.populate_tree_table()
            
            # Threaded run to keep UI active
            self.active_thread = threading.Thread(target=self.execute_script_process, args=(self.selected_test,))
            self.active_thread.daemon = True
            self.active_thread.start()

        def run_all_visible_tests(self):
            if self.active_thread is not None:
                return
            
            self.clear_terminal_view()
            self.log_to_terminal(f"⏳ Launching batch run for {len(self.visible_tests)} tests under '{self.active_category}' category group...\n")
            self.is_running_batch = True
            
            self.disable_all_controls()
            
            # Threaded run
            self.active_thread = threading.Thread(target=self.execute_batch_process, args=(list(self.visible_tests),))
            self.active_thread.daemon = True
            self.active_thread.start()

        def execute_script_process(self, test_dict: Dict[str, Any]):
            test_id = test_dict["id"]
            script_path = os.path.join(ROOT_DIR, test_dict["path"])
            
            try:
                process = subprocess.Popen(
                    [sys.executable, script_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    cwd=ROOT_DIR,
                    bufsize=1
                )
                
                for line in process.stdout:
                    self.run_queue.put(line)
                    
                process.wait()
                
                if process.returncode == 0:
                    test_status[test_id] = "passed"
                    self.run_queue.put(f"\n[Diagnostic] 🟢 SUCCESS: {test_dict['name']} passed successfully.\n")
                else:
                    test_status[test_id] = "failed"
                    self.run_queue.put(f"\n[Diagnostic] 🔴 FAILED: {test_dict['name']} exited with code {process.returncode}.\n")
                    
            except Exception as e:
                test_status[test_id] = "failed"
                self.run_queue.put(f"\n[Diagnostic] 💥 EXCEPTION: Error starting script: {e}\n")
                
            self.run_queue.put(("DONE", test_id))

        def execute_batch_process(self, tests_list: List[Dict[str, Any]]):
            for idx, t in enumerate(tests_list):
                self.run_queue.put(f"\n" + "=" * 55 + "\n")
                self.run_queue.put(f"🏃 [{idx+1}/{len(tests_list)}] Running: {t['name']}\n")
                self.run_queue.put(f"🔬 Scope: {t['summary']}\n")
                self.run_queue.put("=" * 55 + "\n")
                
                test_status[t["id"]] = "running"
                
                script_path = os.path.join(ROOT_DIR, t["path"])
                try:
                    process = subprocess.Popen(
                        [sys.executable, script_path],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        cwd=ROOT_DIR,
                        bufsize=1
                    )
                    
                    for line in process.stdout:
                        self.run_queue.put(line)
                        
                    process.wait()
                    
                    if process.returncode == 0:
                        test_status[t["id"]] = "passed"
                        self.run_queue.put(f"\n🟢 {t['name']}: PASSED.\n")
                    else:
                        test_status[t["id"]] = "failed"
                        self.run_queue.put(f"\n🔴 {t['name']}: FAILED (code {process.returncode}).\n")
                except Exception as e:
                    test_status[t["id"]] = "failed"
                    self.run_queue.put(f"\n💥 Execution error: {e}\n")
                    
                self.run_queue.put(("REDRAW", None))
                time.sleep(0.5)  # cool down period
                
            self.run_queue.put(("DONE_BATCH", None))

        def update_console_logs(self):
            while not self.run_queue.empty():
                item = self.run_queue.get()
                
                if isinstance(item, tuple):
                    event_type, event_data = item
                    if event_type == "DONE":
                        self.active_thread = None
                        self.enable_all_controls()
                        self.populate_tree_table()
                        # Keep selected test status synced
                        if self.selected_test and self.selected_test["id"] == event_data:
                            # Re-trigger selection logic to color code the sidebar/details status
                            self.tree.selection_set(event_data)
                            self.on_tree_select(None)
                    elif event_type == "REDRAW":
                        self.populate_tree_table()
                    elif event_type == "DONE_BATCH":
                        self.active_thread = None
                        self.is_running_batch = False
                        self.enable_all_controls()
                        self.populate_tree_table()
                        self.log_to_terminal("\n==================================================\n")
                        self.log_to_terminal("✅ BATCH EXECUTION PROCESS COMPLETED!\n")
                        self.log_to_terminal("==================================================\n")
                else:
                    self.log_to_terminal(item)
                    
            self.root.after(50, self.update_console_logs)

        def disable_all_controls(self):
            self.btn_run.config_state("disabled")
            self.btn_run_all.config_state("disabled")
            for btn in self.cat_buttons.values():
                btn.config_state("disabled")

        def enable_all_controls(self):
            self.btn_run_all.config_state("normal")
            for btn in self.cat_buttons.values():
                btn.config_state("normal")
            if self.selected_test:
                self.btn_run.config_state("normal")

        def log_to_terminal(self, text: str):
            self.terminal.configure(state="normal")
            self.terminal.insert("end", text)
            self.terminal.see("end")
            self.terminal.configure(state="disabled")

        def clear_terminal_view(self):
            self.terminal.configure(state="normal")
            self.terminal.delete("1.0", "end")
            self.terminal.configure(state="disabled")


# Main CLI parser/runner
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Unified WAF Diagnostic Runner Tool")
    parser.add_argument("--cli", action="store_true", help="Force command-line interface mode (Headless / fallback)")
    parser.add_argument("--test", type=str, help="Execute a single diagnostic test ID and return status code")
    args = parser.parse_args()
    
    # 1. Check for single CLI run argument
    if args.test:
        matching = [t for t in TESTS if t["id"] == args.test]
        if matching:
            run_single_test(matching[0])
            sys.exit(0 if test_status[matching[0]["id"]] == "passed" else 1)
        else:
            print(f"❌ Diagnostic test ID '{args.test}' not found.")
            sys.exit(1)
            
    # 2. Check environment display support to run GUI
    use_gui = not args.cli
    if use_gui:
        try:
            import tkinter as tk
            # Open and immediately destroy a dummy window to check X11 display socket on host
            test_win = tk.Tk()
            test_win.destroy()
        except (ImportError, tk.TclError) as err:
            print(f"\n[Notice] GUI window server connection failed: {err}")
            print("🚀 Switched to fallback CLI Menu interactive console...\n")
            use_gui = False
            
    if use_gui:
        root = tk.Tk()
        app = WafTestRunnerGUI(root)
        root.mainloop()
    else:
        run_cli_mode()
