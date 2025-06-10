#!/bin/bash
set -e

echo "localhost ansible_connection=local" > i
INVENTORY="i"
TARGET="localhost"

echo "📦 Infra2CSV Ad-Hoc Tester 🧪"
echo "📍 Inventory: $INVENTORY"
echo "📂 Output directory: /tmp + /var/lib/infra2csv"
echo "🔐 Sudo mode: Enabled"
echo ""

run_and_verify() {
  local description=$1
  local module=$2
  local args=$3
  local output_file=$4

  echo "➡️  $description"
  ansible "$TARGET" -i "$INVENTORY" -b -m "$module" -a "$args"

  echo -n "🧾 Verifying $output_file ... "
  if [[ -f "$output_file" ]]; then
    echo "✅ File created"
    echo "📄 Preview:"
    head -n 5 "$output_file"
    echo "🎉 Shi! File looks good."
  else
    echo "❌ File NOT found! 🚨"
    exit 1
  fi
  echo ""
}

# Run all modules (CSV only)

run_and_verify "📋 Hardware CSV Output" \
  "crusty_rs.infra2csv.hardware_csv" \
  "output_path=/tmp/inventory.csv include_headers=true" \
  "/tmp/inventory.csv"

run_and_verify "🌐 Network Interfaces (no lo)" \
  "crusty_rs.infra2csv.network_csv" \
  "output_path=/var/lib/infra2csv/network.csv skip_loopback=true include_headers=true" \
  "/var/lib/infra2csv/network.csv"

run_and_verify "🛡️ Security Baseline Snapshot" \
  "crusty_rs.infra2csv.security_baseline" \
  "output_path=/tmp/security_audit.csv include_headers=true" \
  "/tmp/security_audit.csv"

run_and_verify "💽 Storage (Filesystem Mode)" \
  "crusty_rs.infra2csv.storage_csv" \
  "output_path=/tmp/storage_fs.csv mode=filesystem include_headers=true include_lvm=true" \
  "/tmp/storage_fs.csv"

run_and_verify "📦 Storage (Device Mode)" \
  "crusty_rs.infra2csv.storage_csv" \
  "output_path=/tmp/storage_dev.csv mode=device include_headers=true" \
  "/tmp/storage_dev.csv"

run_and_verify "👥 User Accounts (Regular Users)" \
  "crusty_rs.infra2csv.users_csv" \
  "output_path=/tmp/users.csv include_headers=true include_system_users=false" \
  "/tmp/users.csv"

run_and_verify "💉 Filesystem Health Check" \
  "crusty_rs.infra2csv.filesystem_health" \
  "output_path=/tmp/fs_health.csv include_headers=true" \
  "/tmp/fs_health.csv"

echo "✅ All CSV-based modules tested — mission accomplished. Shi 🤙"

