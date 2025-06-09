# infra2csv - Infrastructure Data Collection to CSV

A minimal, robust Ansible collection for gathering system infrastructure data and exporting it to CSV. Built for automation, audits, and analytics pipelines — from Power BI dashboards to compliance reports.

Created by **Nasi Alsahli**  
🙏 Thanks to Red Hat and AI tech for making this easier.

---

## 🔥 Features

- ✅ **Resilient**: Handles broken commands and distro quirks
- 🛠 **Centralized Utils**: Reusable logic in `module_utils`
- 📋 **Schema Validation**: Uniform CSV structure
- 🔎 **Check Mode**: Preview data without writing
- 📦 **Complete Coverage**: Hardware, network, storage, users, security, fs health
- 📊 **Output Options**: CSV or table format
- 🚀 **Production Ready**: Clean, tested, and structured

---

## 📦 Modules

| Module             | Purpose                                                  |
|--------------------|----------------------------------------------------------|
| `hardware_csv`     | System-level hardware details                            |
| `network_csv`      | Network interfaces, MACs, state, MTU                     |
| `storage_csv`      | Filesystem usage + block devices (dual mode)             |
| `users_csv`        | Users, logins, cron, sudo                                |
| `security_baseline`| SELinux, firewalld, SSH, sudoers                         |
| `filesystem_health`| fsck status and ext/XFS health checks                    |

---

## 📊 Output Formats

| Option   | Description                               | Default |
|----------|-------------------------------------------|---------|
| `csv`    | Structured CSV to the path you set        | ✅      |
| `table`  | Pretty table printed to stdout            |         |

```yaml
- name: Preview hardware info in console
  crusty_rs.infra2csv.hardware_csv:
    output_format: table

## 🧬 CSV Schema Fields

| Module              | Fields |
|---------------------|--------|
| `hardware_csv`      | hostname, ip, os, os_version, arch, cpu, ram_gb, uptime_sec, boot_time, serial_number, model, cpu_cores, cpu_threads, disk_total_gb, user_count, run_by, timestamp |
| `network_csv`       | interface, mac_address, state, speed_mbps, mtu, hostname, run_by, timestamp |
| `storage_csv (fs)`  | mode, device, type, size, used, avail, use_percent, mountpoint, hostname, run_by, timestamp |
| `storage_csv (dev)` | mode, device, size_bytes, type, model, hostname, run_by, timestamp |
| `users_csv`         | hostname, username, uid, gid, home_directory, shell, last_login, schedule, command, source_type, enabled, next_run_time, timestamp, is_privileged |
| `security_baseline` | hostname, selinux_status, firewalld_status, ssh_root_login, password_auth_status, users_with_sudo, timestamp |
| `filesystem_health` | hostname, mountpoint, fsck_required, last_fsck, last_fsck_result, filesystem_type, timestamp |

---

## 📁 Directory Layout

collections/
└── ansible_collections/
└── crusty_rs/
└── infra2csv/
├── plugins/
│ ├── modules/
│ │ └── *.py
│ └── module_utils/
│ └── infra2csv_utils.py
└── README.md

--

## ▶️ Example Usage

```yaml
- name: Collect Infrastructure Data
  hosts: all
  become: true
  tasks:
    - name: Collect hardware info
      crusty_rs.infra2csv.hardware_csv:
        csv_path: /var/lib/infra2csv/hardware.csv

## 🧠 Tips & Best Practices

- Run with `become: true` — most modules need elevated access to gather system-level data.
- Use tools like Power BI or Excel to visualize and explore your infrastructure — great for insights, though adds extra tooling overhead.
- Separate CSV files by data type — easier to manage and analyze, but requires coordination when merging for unified views.
- Schedule periodic runs with `cron` or `systemd` — automates your data pipeline, but adds complexity to your ops stack.
- Rotate or archive old CSV logs — avoids disk bloat, though you’ll need a retention policy and storage strategy.
---

## 🧩 Creator & Thanks

**Creator:** Yasir Hamadi Alsahli  
**Thanks:** Red Hat & open AI tools for dev acceleration

