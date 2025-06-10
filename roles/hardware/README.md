
# infra2csv: Role-Based Infra Collector 📦

Minimal, clean Ansible roles to collect system info and merge into CSVs.

## 📁 Role Layout
- `hardware/` → CPU, RAM, disks, uptime
- `network/` → Interfaces, MACs, speeds
- `storage/` → Filesystems, devices
- `users/` → Accounts, cron jobs
- `security/` → SELinux, firewall, SSH
- `filesystem_health/` → fsck checks
- `merge_results/` → Add headers on controller

## 🚀 Usage

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

### Collect All
```bash
ansible-playbook -i inventory/production.ini playbooks/collect_all.yml
```

### Custom Output
```bash
ansible-playbook -i inventory playbooks/collect_all.yml -e "controller_output_path=/opt/infra_data"
```

### Selected Roles
```bash
ansible-playbook -i inventory playbooks/collect_selective.yml --tags "hardware,security"
```

## 🎛️ Vars

| Variable               | Default             | Description                            |
|------------------------|---------------------|----------------------------------------|
| `infra_output_path`    | `$HOME/infra2csv`   | Target save path                       |
| `controller_output_path` | `/tmp/infra2csv` | Merged CSV location                    |
| `cleanup_target`       | `true`              | Auto-delete target files post-fetch    |

### Role-Specific
- `skip_loopback` (network) → false
- `storage_mode` (storage) → filesystem | device
- `include_lvm` (storage) → false
- `include_system_users` (users) → false

## 🛠️ Output
After run, get:
```
controller_output_path/
├── hardware.csv
├── network.csv
├── storage.csv
├── users.csv
├── security.csv
└── filesystem.csv
```

## 💡 Tips
- Override by group or host
- Set paths per group
- Supports Ansible 2.9+ & Python 3.6+

