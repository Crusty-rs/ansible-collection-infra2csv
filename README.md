
# infra2csv - Infrastructure Data Collection to CSV

A minimal, robust Ansible collection for gathering system infrastructure data and exporting it to CSV. Built for automation, audits, and analytics pipelines — from Power BI dashboards to compliance reports.

Created by **Yasir Alsahli**  
🙏 Thanks to Red Hat and Ansible Community

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

| Module              | Purpose                                                  |
|---------------------|----------------------------------------------------------|
| `hardware_csv`      | System-level hardware details                            |
| `network_csv`       | Network interfaces, MACs, state, MTU                     |
| `storage_csv`       | Filesystem usage + block devices (dual mode)             |
| `users_csv`         | Users, logins, cron, sudo                                |
| `security_baseline` | SELinux, firewalld, SSH, sudoers                         |
| `filesystem_health` | `fsck` status and ext/XFS health checks                  |

---

## 📊 Output Formats

| Option   | Description                        | Default |
|----------|------------------------------------|---------|
| `csv`    | Structured CSV to the path you set | ✅      |
| `table`  | Pretty table printed to stdout     |         |

```yaml
- name: Preview hardware info in console
  crusty_rs.infra2csv.hardware_csv:
    output_format: table
```

---

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

```
collections/
└── ansible_collections/
    └── crusty_rs/
        └── infra2csv/
            ├── plugins/
            │   ├── modules/
            │   │   └── *.py
            │   └── module_utils/
            │       └── infra2csv_utils.py
            └── README.md
```

> ℹ️ Supporting files include:  
> - `infra2csv_playbook.yml` — ready-to-run playbook  
> - `test_infra2csv.yml` — test suite  
> - `install_infra2csv.sh` — install helper  
> - `galaxy.yml`, `requirements.yml`, and `CSV_OUTPUT_EXAMPLES.md` — metadata & sample outputs  

---

## ▶️ Example Usage

```yaml
- name: Collect Infrastructure Data
  hosts: all
  become: true
  tasks:
    - name: Collect hardware info
      crusty_rs.infra2csv.hardware_csv:
        csv_path: /var/lib/infra2csv/hardware.csv
```

---

## 🚀 Quick Start

**Step 1: Install**

```bash
bash install_infra2csv.sh
```

**Step 2: Copy Modules**

```bash
cp *.py ~/collections/ansible_collections/crusty_rs/infra2csv/plugins/modules/
cp infra2csv_utils.py ~/collections/.../module_utils/
```

**Step 3: Export Path**

```bash
echo 'export ANSIBLE_COLLECTIONS_PATH=~/collections:$ANSIBLE_COLLECTIONS_PATH' >> ~/.bashrc
source ~/.bashrc
```

**Step 4: Test**

```bash
ansible-doc crusty_rs.infra2csv.hardware_csv
ansible-playbook test_infra2csv.yml
```

**Step 5: Deploy**

```bash
ansible-playbook -i inventory infra2csv_playbook.yml
```

---

## 💪 Key Strengths

### 1. Resilient Design

- Gracefully handles missing commands  
- Multiple fallback methods per module  
- Returns `"N/A"` instead of crashing

### 2. Centralized Architecture

```python
from ansible.module_utils.infra2csv_utils import (
    run_cmd,
    write_csv,
    validate_schema
)
```

### 3. Production-Grade Features

- Check mode support  
- Strong error messages  
- Consistent timestamps  
- No silent failures

### 4. Edge Case Handling

- No `dmidecode` in containers? Covered  
- No `ip` tool? It still runs  
- Works on minimal VMs and weird clouds

---

## 📊 Data Pipeline to Analytics

```text
Linux Hosts → Ansible Modules → CSV Files → Power BI Dashboards
     ↓              ↓               ↓              ↓
   Facts       Validation      Structured     Visualized
                               Consistent       Reports
```

---

## 🔧 Customization Points

### Add Fields

```python
# in infra2csv_utils.py
HARDWARE_FIELDS = [
    # existing fields...
    "your_new_field"
]
```

### Change Output Directory

```yaml
vars:
  csv_base_dir: /your/custom/path
```

### Skip Modules

```yaml
vars:
  collect_users: false
  collect_security: false
```

---

## 🧩 Creator & Thanks

**Creator:** Yasir Hamadi Alsahli  
**Thanks:** Red Hat & Ansible Community

