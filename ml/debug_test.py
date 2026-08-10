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
    {"name": "Normal Login Submit", "url": "/login", "method": "POST", "body": "username=john&password=123"},
    {"name": "SQLi Auth", "url": "/login?user=admin' OR '1'='1' --", "method": "GET"},
    {"name": "SQLi UNION", "url": "/products?category=1 UNION SELECT 1,username,password FROM users--", "method": "GET"},
    {"name": "Reflected XSS", "url": "/search?q=<script>alert('XSS')</script>", "method": "GET"},
]

print(f"RF Classes: {rf.classes_}")

for s in test_samples:
    feat = extract_features_from_request(url=s['url'], method=s['method'], body=s.get('body', ''))
    df_feat = pd.DataFrame([feat])[FEATURE_COLUMNS]
    rf_pred = rf.predict(df_feat)[0]
    rf_prob = rf.predict_proba(df_feat)[0]
    iso_score = iso.decision_function(df_feat)[0]
    print(f"{s['name']:<20} | RF Pred: {rf_pred} | Prob: [Norm:{rf_prob[0]:.3f}, Atk:{rf_prob[1]:.3f}] | Iso Score: {iso_score:.4f}")
