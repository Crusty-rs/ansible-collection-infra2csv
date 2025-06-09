# infra2csv - Infra Data to CSV

A minimal Ansible collection to gather system infrastructure data and export it to CSV. Ideal for automation, audits, and data pipelines.

**Made by:** Yasir Alsahli (Jr. Linux Engineer | Rust Dev)  
**Props to:** Red Hat + Ansible communities

---

## Features

- Handles broken commands, weird distros
- Shared logic via `module_utils`
- Validated CSV schema
- Check mode support
- Collects hardware, net, storage, users, security, FS health
- CSV or pretty table output
- Tested, clean, ready to go

---

## Modules

| Module              | Description                            |
|---------------------|----------------------------------------|
| `hardware_csv`      | CPU, RAM, uptime, etc.                 |
| `network_csv`       | Interfaces, MACs, MTU, speed           |
| `storage_csv`       | FS usage + block device info           |
| `users_csv`         | User accounts, sudo, cron              |
| `security_baseline` | SELinux, firewalld, SSH, sudo config   |
| `filesystem_health` | fsck results and health checks         |

---

## Output Formats

| Format  | Description                |
|---------|----------------------------|
| `csv`   | Structured CSV (default)   |
| `table` | Human-readable output      |

```yaml
- name: Preview hardware info
  crusty_rs.infra2csv.hardware_csv:
    output_format: table
```

---

## CSV Fields

Each module returns a structured list of fields. Example (hardware):

```text
hostname, ip, os, os_version, arch, cpu, ram_gb, uptime_sec, ...
```

Others follow a similar format with their relevant metrics.

---

## Directory Structure

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
- `infra2csv_playbook.yml` – deploy it  
- `test_infra2csv.yml` – run tests  
- `install_infra2csv.sh` – helper installer  
- `galaxy.yml`, `requirements.yml`, etc.

---

## Usage Example

```yaml
- name: Collect Infra
  hosts: all
  become: true
  tasks:
    - name: Get hardware
      crusty_rs.infra2csv.hardware_csv:
        csv_path: /var/lib/infra2csv/hardware.csv
```

---

## Quick Start

```bash
bash install_infra2csv.sh

# Move modules
cp *.py ~/collections/.../modules/
cp infra2csv_utils.py ~/collections/.../module_utils/

# Export path
echo 'export ANSIBLE_COLLECTIONS_PATH=~/collections:$ANSIBLE_COLLECTIONS_PATH' >> ~/.bashrc
source ~/.bashrc

# Test + Deploy
ansible-doc crusty_rs.infra2csv.hardware_csv
ansible-playbook test_infra2csv.yml
ansible-playbook -i inventory infra2csv_playbook.yml
```

---

## Highlights

### Resilient

- Gracefully handles missing tools
- Fallbacks for most cases
- Doesn’t crash – returns `"N/A"`

### Clean Core

```python
from ansible.module_utils.infra2csv_utils import (
    run_cmd, write_csv, validate_schema
)
```

### Reliable

- Check mode support
- Helpful errors
- Always timestamps

### Works Anywhere

- Runs on VMs, containers, cloudy stuff
- No `dmidecode`? No problem.

---

## Analytics Pipeline Flow

```
Linux → Ansible → CSV → Power BI
        ↓         ↓       ↓
     Valid     Clean     Visuals
```

---

## Customization

Add fields:

```python
HARDWARE_FIELDS = ["...", "your_field"]
```

Change output dir:

```yaml
vars:
  csv_base_dir: /custom/path
```

Skip modules:

```yaml
vars:
  collect_users: false
  collect_security: false
```

