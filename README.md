
# crusty_rs.infra2csv

**Target-first infrastructure data collection for Ansible.**  
Think roles, not modules.

**Made by:** Yasir Hamadi Alsahli (Jr. Linux Engineer | Rust Dev)  
**Props to:** Ansible & Linux communities

---

## ✦ What It Does

Collects host-level data (hardware, network, users, etc.) into clean CSVs on the controller. Each role handles a single domain. No manual aggregation.

## ✦ Key Features

- Handles odd distros & missing tools gracefully (returns "N/A")
- CSV schema validation ensures consistent outputs
- Check mode support
- Pretty-table or CSV output formats
- Shared utilities via `module_utils`
- Designed for audits, automation, analytics pipelines

## ✦ Core Idea

You work with **roles**, not modules.  
Each role = one domain of system data.

**Included roles:**
- `hardware`: CPU, RAM, uptime
- `network`: interfaces, MACs
- `storage`: filesystems or block devices
- `users`: users, sudo, cron
- `security`: firewall, SSH, SELinux
- `filesystem_health`: fsck, mount health
- `merge_results`: assembles CSVs, cleans up

## ✦ Install

```bash
ansible-galaxy collection install crusty_rs.infra2csv
```

## ✦ Usage

**Full audit:**
```yaml
- hosts: all
  become: true
  roles:
    - crusty_rs.infra2csv.hardware
    - crusty_rs.infra2csv.network
    - crusty_rs.infra2csv.storage
    - crusty_rs.infra2csv.users
    - crusty_rs.infra2csv.security
    - crusty_rs.infra2csv.filesystem_health
    - crusty_rs.infra2csv.merge_results
```

**Selective collection:**
```yaml
- hosts: webservers
  become: true
  roles:
    - crusty_rs.infra2csv.hardware
    - crusty_rs.infra2csv.security
    - crusty_rs.infra2csv.merge_results
```

**CLI:**
```bash
ansible-playbook -i inventory site.yml
ansible-playbook -i inventory site.yml -e "controller_output_path=/opt/audit_data"
ansible-playbook -i inventory site.yml -e "infra_output_path=/var/tmp/collection"
```

## ✦ Output Formats

```yaml
- name: Show hardware table
  crusty_rs.infra2csv.hardware_csv:
    output_format: table
```

## ✦ Directory Structure

```
collections/
└── ansible_collections/
    └── crusty_rs/
        └── infra2csv/
            ├── plugins/
            │   ├── modules/
            │   └── module_utils/
            └── README.md
```

Includes:
- `infra2csv_playbook.yml`, `test_infra2csv.yml`
- `install_infra2csv.sh`, `galaxy.yml`, `requirements.yml`

## ✦ Configuration

**Global vars:**
| Variable               | Default              | Purpose                          |
|------------------------|----------------------|----------------------------------|
| `infra_output_path`    | `$HOME/infra2csv`    | Temp files on targets            |
| `controller_output_path` | `/tmp/infra2csv`   | Final CSVs on controller         |
| `cleanup_target`       | `true`               | Auto-cleanup on target hosts     |

**Example group vars:**
```ini
[databases:vars]
controller_output_path=/data/db_audit
include_system_users=true
```

**Per-role config:**
```yaml
- hosts: all
  become: true
  vars:
    skip_loopback: true
    storage_mode: device
    include_system_users: true
  roles:
    - crusty_rs.infra2csv.network
    - crusty_rs.infra2csv.storage
    - crusty_rs.infra2csv.users
    - crusty_rs.infra2csv.merge_results
```

## ✦ How It Works

- Role runs module → writes to target filesystem (no headers)
- Controller pulls raw CSVs
- `merge_results` adds headers & combines files
- Cleanup removes temp data

## ✦ Output Example

```
/tmp/infra2csv/
├── hardware.csv
├── network.csv
├── storage.csv
├── users.csv
├── security.csv
└── filesystem.csv
```

- Header row + data rows (with hostnames, timestamps)
- Predictable structure every time

## ✦ Analytics Pipeline

```
Linux → Ansible → CSV → Power BI
        ↓         ↓       ↓
     Valid     Clean     Visuals
```

## ✦ Requirements

- Ansible 2.9+
- Python 3.6+ on target hosts
- SSH access & write perms on controller




Work with roles. Let modules handle the details.

