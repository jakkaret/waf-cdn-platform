#!/bin/bash
# ============================================================
# scripts/purge-cache.sh
# Phase 1 – Cache Purge  (งานบอส แต่ริวทำ helper script)
#
# Usage:
#   ./purge-cache.sh all /images/logo.png       ← purge ทุก node
#   ./purge-cache.sh sg  /images/logo.png       ← purge เฉพาะ SG
#   ./purge-cache.sh all                        ← purge ทุกอย่าง
#
# Requires: curl, docker
# ============================================================

set -e

NODES=(sg jp us de ch)
PORTS=(8081 8082 8083 8084 8085)
CONTAINERS=(cdn-edge-sg cdn-edge-jp cdn-edge-us cdn-edge-de cdn-edge-ch)

TARGET="${1:-all}"    # all | sg | jp | us | de | ch
URI="${2:-/}"         # URI ที่จะ purge

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "================================================"
echo " CDN Cache Purge Tool"
echo " Target: ${TARGET^^}  |  URI: $URI"
echo "================================================"

purge_node() {
    local name="$1"
    local container="$2"

    echo -n "  Purging [$name] ... "

    # สั่ง nginx reload เพื่อ clear cache zone
    # (สำหรับ purge จริงๆ ต้องใช้ ngx_cache_purge module
    #  หรือ ลบไฟล์ cache ตรงๆ ใน volume)
    if docker exec "$container" nginx -s reload 2>/dev/null; then
        echo -e "${GREEN}✓ OK${NC}"
    else
        echo -e "${RED}✗ FAILED (container may be offline)${NC}"
    fi
}

purge_file() {
    local name="$1"
    local container="$2"
    local uri="$3"

    echo -n "  Purging [$name] $uri ... "

    # ลบ cache file ที่ตรงกับ key
    # cache key = scheme + host + uri
    local cache_key="http127.0.0.1${uri}"
    local md5key=$(echo -n "$cache_key" | md5sum | cut -c1-32)
    local d1="${md5key: -1}"
    local d2="${md5key: -3:2}"
    local cache_path="/var/cache/nginx/${d1}/${d2}/${md5key}"

    if docker exec "$container" rm -f "$cache_path" 2>/dev/null; then
        echo -e "${GREEN}✓ Purged${NC}"
    else
        echo -e "${YELLOW}⚠ File not found (may already be expired)${NC}"
    fi
}

# Main logic
if [ "$URI" = "/" ] || [ -z "$URI" ]; then
    echo -e "${YELLOW}⚠ Full cache purge mode (reload nginx)${NC}"
    echo ""
    for i in "${!NODES[@]}"; do
        n="${NODES[$i]}"
        c="${CONTAINERS[$i]}"
        if [ "$TARGET" = "all" ] || [ "$TARGET" = "$n" ]; then
            purge_node "${n^^}" "$c"
        fi
    done
else
    echo "Purging specific URI: $URI"
    echo ""
    for i in "${!NODES[@]}"; do
        n="${NODES[$i]}"
        c="${CONTAINERS[$i]}"
        if [ "$TARGET" = "all" ] || [ "$TARGET" = "$n" ]; then
            purge_file "${n^^}" "$c" "$URI"
        fi
    done
fi

echo ""
echo -e "${GREEN}✓ Purge complete${NC}"
