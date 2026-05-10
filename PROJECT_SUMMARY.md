# Project Summary: CDN System (SG / JP / TH)

## Overview
This project implements a multi-node CDN system integrated with the existing infrastructure. The system includes:
- **GeoDNS** for routing requests to the nearest edge node.
- **Edge Nodes** with Nginx, ModSecurity (WAF), and caching capabilities.
- **Cache Purge API** for managing cached content.

### Architecture
1. **Client Request Flow**:
   `Client -> GeoDNS -> Edge Node -> Origin Server`
2. **Edge Nodes**:
   - SG: Port 8081
   - JP: Port 8082
   - TH: Port 8086
3. **GeoDNS**:
   - Routes requests based on client IP.
   - CIDR mapping:
     - `172.28.11.0/24` -> SG
     - `172.28.22.0/24` -> JP
     - `172.28.33.0/24` -> TH

### Features
- **Caching**:
  - Dynamic content: 10 minutes
  - Static assets: 1 hour
  - Debug headers: `X-Cache-Status`, `X-Edge-Region`
- **Cache Purge**:
  - API: `POST /purge?url=...&region=...`
  - Header: `X-Purge-Token`
- **WAF**:
  - Blocks malicious requests (e.g., SQL Injection).

---

## Usage Guide

### 1. Start Origin Server
```bash
cd /Users/boss/project/waf_project
docker compose up -d dvwa
```

### 2. Start CDN Stack
```bash
cd /Users/boss/project/waf_project/cdn
docker compose -f docker-compose-cdn.yml up -d --build
```

### 3. Check Service Health
```bash
curl http://localhost:8081/healthz
curl http://localhost:8082/healthz
curl http://localhost:8086/healthz
curl http://localhost:8090/healthz
```

### 4. Test Cache and Purge
```bash
./scripts/smoke-test-cdn.sh
./scripts/purge-cache.sh /dvwa/images/login_logo.png ALL
```

### 5. Test GeoDNS Routing
```bash
./scripts/test-geodns-routing.sh
```

---

## Notes
- Default purge token: `cdn-secret-token` (change via `CDN_PURGE_TOKEN`).
- External network: `waf_project_waf-net` (override via `WAF_NETWORK_NAME`).
- Stop old CDN containers if ports conflict:
```bash
docker compose -f docker-compose-cdn.yml down --remove-orphans
```