#!/bin/bash
set -e

echo "localhost ansible_connection=local" > i
INVENTORY="ini"
TARGET="localhost"

echo "📦 Infra2CSV Ad-Hoc Tester 🔥"
echo "📍 Inventory: $INVENTORY"
echo "📂 Output directory: /tmp"
echo "🔒 Running with sudo (become: yes)"
echo ""

run_test() {
  echo "==> Running: $1"
  ansible $TARGET -i $INVENTORY -b -m "crusty.infra2csv.$2" -a "$3"
  echo "✅ Done: $2"
  echo ""
}

run_test "Hardware Facts" "hardware_csv" \
  "csv_path=/tmp/hardware.csv include_headers=true"

run_test "Network Interfaces" "network_csv" \
  "csv_path=/tmp/network.csv include_headers=true skip_loopback=false"

run_test "Storage Facts (Filesystem)" "storage_csv" \
  "csv_path=/tmp/storage_fs.csv include_headers=true mode=filesystem include_lvm=false"

run_test "Storage Facts (Devices)" "storage_csv" \
  "csv_path=/tmp/storage_dev.csv include_headers=true mode=device"

run_test "Security Baseline" "security_baseline" \
  "csv_path=/tmp/security.csv include_headers=true"

run_test "Filesystem Health" "filesystem_health" \
  "csv_path=/tmp/fshealth.csv include_headers=true"

echo "🎉 All modules flexed. Check your /tmp for fresh CSV drops."

