#!/bin/bash

# Function to run Origin Server
run_origin() {
  echo "กำลังเริ่ม Origin Server..."
  cd /Users/boss/project/waf_project || exit
  docker compose up -d dvwa
  echo "Origin Server เริ่มทำงานแล้ว."
}

# Function to run CDN Stack
run_cdn_stack() {
  echo "กำลังเริ่ม CDN Stack..."
  cd /Users/boss/project/waf_project/cdn || exit
  docker compose -f docker-compose-cdn.yml up -d --build
  echo "CDN Stack เริ่มทำงานแล้ว."
}

# Function to check health of all services
check_health() {
  echo "กำลังตรวจสอบสถานะของบริการ CDN..."
  curl -s http://localhost:8081/healthz && echo "\nEdge SG ทำงานปกติ."
  curl -s http://localhost:8082/healthz && echo "\nEdge JP ทำงานปกติ."
  curl -s http://localhost:8086/healthz && echo "\nEdge TH ทำงานปกติ."
  curl -s http://localhost:8090/healthz && echo "\nPurge API ทำงานปกติ."
}

# Function to test cache and purge
test_cache_purge() {
  echo "กำลังทดสอบ Cache และ Purge..."
  ./scripts/smoke-test-cdn.sh
  ./scripts/purge-cache.sh /dvwa/images/login_logo.png ALL
}

# Function to test GeoDNS routing
test_geodns() {
  echo "กำลังทดสอบ GeoDNS Auto Routing..."
  ./scripts/test-geodns-routing.sh
}

# Main menu
main_menu() {
  echo "เลือกตัวเลือกที่ต้องการ:"
  echo "1) เริ่ม Origin Server"
  echo "2) เริ่ม CDN Stack"
  echo "3) ตรวจสอบสถานะของบริการ"
  echo "4) ทดสอบ Cache และ Purge"
  echo "5) ทดสอบ GeoDNS Routing"
  echo "6) รันทุกขั้นตอน"
  echo "7) ออกจากโปรแกรม"
  read -rp "กรุณาเลือกหมายเลข: " choice

  case $choice in
    1)
      run_origin
      ;;
    2)
      run_cdn_stack
      ;;
    3)
      check_health
      ;;
    4)
      test_cache_purge
      ;;
    5)
      test_geodns
      ;;
    6)
      run_origin
      run_cdn_stack
      check_health
      test_cache_purge
      test_geodns
      ;;
    7)
      echo "กำลังออกจากโปรแกรม..."
      exit 0
      ;;
    *)
      echo "ตัวเลือกไม่ถูกต้อง กรุณาลองใหม่."
      main_menu
      ;;
  esac
}

# Run the main menu
main_menu