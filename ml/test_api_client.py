import requests
import json

BASE_URL = "http://127.0.0.1:5000"

print("--- Checking Previously False Positive URLs on New Model ---")
urls = ["/login.php", "/robots.txt", "/index.html", "/search?q=shoes", "/login?user=admin' OR '1'='1' --"]
for u in urls:
    r = requests.post(f"{BASE_URL}/predict", json={"url": u, "method": "GET"}).json()
    print(f"URL: {u:<45} | Status: {r['status']:<18} | Prob: {r['attack_probability']*100:5.1f}%")
