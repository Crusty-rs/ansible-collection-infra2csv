# infra2csv - Infrastructure Data Collection to CSV

A powerful, minimal, and robust Ansible collection for gathering infrastructure data and exporting it to CSV files. Perfect for analytics, Power BI dashboards, or maintaining infrastructure inventories.

---

## 🔥 Features

- ✅ Robust Error Handling — tolerates command failures and OS quirks
- 🛠 Centralized Utilities — shared logic in `module_utils`
- 📋 Schema Validation — consistent CSV output per module
- 🔎 Check Mode Support — preview data without writing
- 📦 Coverage: hardware, network, storage, users, security, fs health
- 🚀 Production Ready — clean, tested, and structured

---

## 📦 Modules

| Module             | Purpose                                                  |
|--------------------|----------------------------------------------------------|
| `hardware_csv`     | Collects system-level hardware details                   |
| `network_csv`      | Reports network interface states and properties          |
| `storage_csv`      | Filesystem usage + block device inventory (2 modes)      |
| `users_csv`        | User accounts, login, cron jobs, sudo access             |
| `security_baseline`| SELinux, firewall, SSH policy, sudoers                   |
| `filesystem_health`| Fsck status, last run times, ext/XFS support             |

---

## 📁 Directory Layout

collections/
└── ansible_collections/
└── crusty_rs/
└── infra2csv/
├── plugins/
│ ├── modules/
│ │ ├── *.py
│ └── module_utils/
│ └── infra2csv_utils.py
└── README.md

collections/
└── ansible_collections/
└── crusty_rs/
└── infra2csv/
├── plugins/
│ ├── modules/
│ │ ├── *.py
│ └── module_utils/
│ └── infra2csv_utils.py
└── README.md

## ▶️ Usage

- name: Collect Infrastructure Data
  hosts: all
  become: true
  tasks:
    - name: Collect hardware info
      crusty_rs.infra2csv.hardware_csv:
        csv_path: /var/lib/infra2csv/hardware.csv

# All hosts
ansible-playbook -i inventory playbook.yml

# Preview with check mode
ansible-playbook -i inventory playbook.yml --check

# Limit to group
ansible-playbook -i inventory playbook.yml --limit webservers


# 🧪 CSV Output Examples
hostname,ip,os,os_version,arch,cpu,ram_gb,uptime_sec,...
server01,192.168.1.10,Linux,5.15,x86_64,Intel Xeon,32.0,864000,...

hostname,ip,os,os_version,arch,cpu,ram_gb,uptime_sec,...
server01,192.168.1.10,Linux,5.15,x86_64,Intel Xeon,32.0,864000,...


interface,mac_address,state,speed_mbps,mtu,hostname,...
eth0,00:50:56:85:5a:1b,up,10000,1500,server01,...



---

## ✅ `galaxy.yml`

Place this in the root of `crusty_rs-infra2csv/`:

```yaml
namespace: crusty_rs
name: infra2csv
version: 1.0.0
readme: README.md
authors:
  - Crusty RS <you@example.com>
description: >
  Ansible collection to collect and centralize infrastructure data into CSV format,
  suitable for auditing, monitoring, and reporting.
license: MIT
tags:
  - csv
  - audit
  - monitoring
  - inventory
  - infrastructure
  - analytics
dependencies: {}
repository: https://github.com/crusty-rs/ansible-collection-infra2csv





