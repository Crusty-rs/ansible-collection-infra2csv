
#!/bin/bash
set -e

echo "localhost ansible_connection=local" > i
INVENTORY="i"
TARGET="localhost"

echo "📦 Infra2CSV Ad-Hoc Tester 🔥"
echo "📍 Inventory: $INVENTORY"
echo "📂 Output directory: /tmp"
echo "🔒 Running with sudo (become: yes)"
echo ""

run_test() {
  echo "==> Running: $1"
  ansible $TARGET -i $INVENTORY -b -m "$2" -a "$3"
  echo "✅ Done: $2"
  echo ""
}

run_test "Hardware Facts" "crusty_rs.infra2csv.hardware_csv" \
  "csv_path=/tmp/hardware.csv include_headers=true"

run_test "Network Interfaces" "crusty_rs.infra2csv.network_csv" \
  "csv_path=/tmp/network.csv include_headers=true skip_loopback=false"

run_test "Storage Facts (Filesystem)" "crusty_rs.infra2csv.storage_csv" \
  "csv_path=/tmp/storage_fs.csv include_headers=true mode=filesystem include_lvm=false"

run_test "Storage Facts (Devices)" "crusty_rs.infra2csv.storage_csv" \
  "csv_path=/tmp/storage_dev.csv include_headers=true mode=device"

run_test "Security Baseline" "crusty_rs.infra2csv.security_baseline" \
  "csv_path=/tmp/security.csv include_headers=true"

run_test "Filesystem Health" "crusty_rs.infra2csv.filesystem_health" \
  "csv_path=/tmp/fshealth.csv include_headers=true"

echo "🎉 All modules flexed. Check your /tmp for fresh CSV drops."

