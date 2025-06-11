#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, yasir hamadi alsahli <crusty.rusty.engine@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: security_baseline
short_description: Collect security baseline information from target systems
description:
    - Gathers security configuration and writes to target host
    - Checks SELinux, firewall, SSH, and sudo configuration  
    - Supports CSV and JSON output based on file extension
    - Enhanced error handling for minimal environments
    - Version 6 with improved compatibility
version_added: "1.0.0"
author:
    - yasir hamadi alsahli (@crusty.rusty.engine)
options:
    output_path:
        description: 
            - Output file path for security data
            - Supports .csv and .json file extensions
        required: true
        type: str
    include_headers:
        description: 
            - Include CSV headers in output
            - Ignored for JSON output format
        required: false
        type: bool
        default: true
requirements:
    - Target systems must be Linux-based
    - Python 3.6+ on target systems
notes:
    - Module runs on target hosts, not controller
    - Handles missing security tools gracefully
    - Compatible with minimal container environments
    - Version 6 with enhanced Rocky/Alma compatibility
seealso:
    - module: ansible.builtin.setup
    - module: crusty_rs.infra2csv.users_csv
'''

EXAMPLES = r'''
# Basic security baseline to CSV
- name: Collect security configuration
  crusty_rs.infra2csv.security_baseline:
    output_path: /tmp/security.csv

# Security baseline with custom path
- name: Security audit to custom location
  crusty_rs.infra2csv.security_baseline:
    output_path: /opt/audit/security_{{ ansible_date_time.date }}.csv
    include_headers: true

# Security baseline to JSON format
- name: Security baseline snapshot
  crusty_rs.infra2csv.security_baseline:
    output_path: /tmp/security.json

# Complete security audit playbook
- name: Infrastructure security audit
  hosts: all
  become: true
  tasks:
    - name: Collect security baseline
      crusty_rs.infra2csv.security_baseline:
        output_path: /tmp/security_{{ inventory_hostname }}.csv
'''

RETURN = r'''
changed:
    description: Whether the module made changes
    type: bool
    returned: always
    sample: true
msg:
    description: Human readable message about the operation
    type: str
    returned: always
    sample: "Security baseline written to /tmp/security.csv"
entries:
    description: Number of data entries written
    type: int
    returned: success
    sample: 1
data:
    description: The security data that was collected
    type: dict
    returned: success
    sample:
        hostname: "server01"
        selinux_status: "enforcing"
        firewalld_status: "firewalld_active"
        ssh_root_login: "no"
        password_auth_status: "yes"
        users_with_sudo: "admin,operator"
        timestamp: "2025-06-11T10:30:45"
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.crusty_rs.infra2csv.plugins.module_utils.infra2csv_utils import (
    run_cmd, get_hostname, get_timestamp, write_csv,
    validate_schema, read_file_safe, SECURITY_FIELDS
)
import os
import re
import json
from pathlib import Path

def write_data_local(module, path, data, include_headers=True, fieldnames=None):
    """Local data writer compatible with existing utils."""
    if not data:
        return 0

    try:
        # Create parent directory if needed
        path_obj = Path(path).resolve()
        path_obj.parent.mkdir(parents=True, exist_ok=True)
        clean_path = str(path_obj)

        # Detect format from extension
        if clean_path.lower().endswith('.json'):
            return write_json_local(module, clean_path, data)
        else:
            # Use existing write_csv function
            return write_csv(module, clean_path, data, include_headers, fieldnames)

    except Exception as e:
        module.fail_json(msg=f"Failed to write data to {path}: {str(e)}")


def write_json_local(module, path, data):
    """Write JSON data with metadata."""
    try:
        # Normalize data to list
        rows = [data] if isinstance(data, dict) else list(data)

        # Add metadata
        output_data = {
            'timestamp': get_timestamp(),
            'hostname': get_hostname(),
            'data_count': len(rows),
            'data': rows
        }

        # Atomic write using temp file
        temp_path = f"{path}.tmp.{os.getpid()}"

        with open(temp_path, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)

        # Atomic move
        os.rename(temp_path, path)

        return len(rows)

    except Exception as e:
        # Clean up temp file if exists
        temp_path = f"{path}.tmp.{os.getpid()}"
        if os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except:
                pass
        raise e


def get_selinux_status(module):
    """SELinux status detection. Multiple methods with better error handling."""
    # Method 1: Check if getenforce exists first
    getenforce_exists = run_cmd(module, "which getenforce", ignore_errors=True)
    if getenforce_exists != "N/A":
        status = run_cmd(module, "getenforce", ignore_errors=True)
        if status != "N/A":
            return status.lower()

    # Method 2: Check if SELinux is installed via file system
    if os.path.exists('/sys/fs/selinux'):
        enforce_file = read_file_safe('/sys/fs/selinux/enforce', '')
        if enforce_file:
            if enforce_file.strip() == '1':
                return 'enforcing'
            elif enforce_file.strip() == '0':
                return 'permissive'

    # Method 3: config file
    selinux_config = read_file_safe("/etc/selinux/config", "")
    if selinux_config:
        match = re.search(r'^SELINUX=(\w+)', selinux_config, re.MULTILINE)
        if match:
            return match.group(1).lower()

    # Method 4: Check if SELinux kernel module is loaded
    modules_output = run_cmd(module, "lsmod | grep selinux", use_shell=True, ignore_errors=True)
    if modules_output != "N/A" and 'selinux' in modules_output:
        return 'unknown_loaded'

    return "not_installed"


def get_firewall_status(module):
    """Comprehensive firewall detection."""
    # Check firewalld
    firewalld_status = run_cmd(module, "systemctl is-active firewalld", ignore_errors=True)
    if firewalld_status == "active":
        return "firewalld_active"
    elif firewalld_status == "inactive":
        return "firewalld_inactive"

    # Check iptables service
    iptables_status = run_cmd(module, "systemctl is-active iptables", ignore_errors=True)
    if iptables_status == "active":
        return "iptables_active"
    elif iptables_status == "inactive":
        return "iptables_inactive"

    # Check for iptables rules (manual setup)
    iptables_rules = run_cmd(
        module,
        "iptables -L -n | grep -c -E 'Chain|target'",
        use_shell=True,
        ignore_errors=True
    )
    if iptables_rules != "N/A":
        try:
            rule_count = int(iptables_rules)
            if rule_count > 3:  # More than default chains
                return "iptables_rules_present"
        except ValueError:
            pass

    # Check ufw (Ubuntu)
    ufw_status = run_cmd(module, "ufw status", ignore_errors=True)
    if ufw_status != "N/A":
        if "active" in ufw_status.lower():
            return "ufw_active"
        elif "inactive" in ufw_status.lower():
            return "ufw_inactive"

    return "no_firewall"


def get_ssh_config(module):
    """SSH daemon security configuration analysis."""
    ssh_config = {
        'ssh_root_login': 'N/A',
        'password_auth_status': 'N/A'
    }

    sshd_config = read_file_safe("/etc/ssh/sshd_config", "")
    if sshd_config:
        # PermitRootLogin
        match = re.search(r'^PermitRootLogin\s+(\S+)', sshd_config, re.MULTILINE | re.IGNORECASE)
        if match:
            value = match.group(1).lower()
            ssh_config['ssh_root_login'] = value
        else:
            ssh_config['ssh_root_login'] = 'default_prohibit-password'

        # PasswordAuthentication
        match = re.search(r'^PasswordAuthentication\s+(\S+)', sshd_config, re.MULTILINE | re.IGNORECASE)
        if match:
            ssh_config['password_auth_status'] = match.group(1).lower()
        else:
            ssh_config['password_auth_status'] = 'default_yes'

    return ssh_config


def get_sudo_users(module):
    """Find all users with sudo privileges - Enhanced error handling."""
    sudo_users = []

    # Parse sudoers file
    sudoers_content = read_file_safe("/etc/sudoers", "")
    if sudoers_content:
        for match in re.finditer(r'^(\w+)\s+ALL=', sudoers_content, re.MULTILINE):
            user = match.group(1)
            if user not in ['root', 'Defaults']:
                sudo_users.append(user)

    # Parse sudoers.d directory
    if os.path.exists('/etc/sudoers.d'):
        try:
            for filename in os.listdir('/etc/sudoers.d'):
                filepath = os.path.join('/etc/sudoers.d', filename)
                if os.path.isfile(filepath):
                    content = read_file_safe(filepath, "")
                    for match in re.finditer(r'^(\w+)\s+ALL=', content, re.MULTILINE):
                        user = match.group(1)
                        if user not in ['root', 'Defaults'] and user not in sudo_users:
                            sudo_users.append(user)
        except Exception:
            pass

    # Check sudo/wheel groups - Enhanced method
    sudo_group_users = []
    
    # Try multiple group names
    for group_name in ['sudo', 'wheel', 'admin']:
        # Method 1: Try getent if available
        getent_exists = run_cmd(module, "which getent", ignore_errors=True)
        if getent_exists != "N/A":
            group_output = run_cmd(module, f"getent group {group_name}", ignore_errors=True)
            if group_output != "N/A":
                parts = group_output.split(':')
                if len(parts) >= 4 and parts[3]:
                    sudo_group_users.extend([u.strip() for u in parts[3].split(',') if u.strip()])
        
        # Method 2: Fallback to /etc/group parsing
        else:
            group_content = read_file_safe('/etc/group', '')
            if group_content:
                for line in group_content.splitlines():
                    if line.startswith(f'{group_name}:'):
                        parts = line.split(':')
                        if len(parts) >= 4 and parts[3]:
                            sudo_group_users.extend([u.strip() for u in parts[3].split(',') if u.strip()])

    # Combine and deduplicate
    all_sudo_users = list(set(sudo_users + sudo_group_users))
    return ','.join(all_sudo_users) if all_sudo_users else 'none'


def collect_security_data(module):
    """Main security baseline collection."""
    hostname = get_hostname()
    timestamp = get_timestamp()

    # Get SSH configuration
    ssh_config = get_ssh_config(module)

    # Build security baseline
    security_data = {
        'hostname': hostname,
        'selinux_status': get_selinux_status(module),
        'firewalld_status': get_firewall_status(module),
        'ssh_root_login': ssh_config['ssh_root_login'],
        'password_auth_status': ssh_config['password_auth_status'],
        'users_with_sudo': get_sudo_users(module),
        'timestamp': timestamp
    }

    return security_data


def main():
    """Main execution. Target-only security collection."""
    module = AnsibleModule(
        argument_spec=dict(
            output_path=dict(type='str', required=True),
            include_headers=dict(type='bool', default=True)
        ),
        supports_check_mode=True
    )

    output_path = module.params['output_path']
    include_headers = module.params['include_headers']

    try:
        # Collect security data
        security_data = collect_security_data(module)

        # Validate schema
        security_data = validate_schema(module, security_data, SECURITY_FIELDS)

        # Check mode
        if module.check_mode:
            module.exit_json(
                changed=False,
                msg="Check mode: data not written",
                data=security_data
            )

        # Write data locally
        entries = write_data_local(
            module,
            output_path,
            security_data,
            include_headers,
            SECURITY_FIELDS
        )

        # Success
        module.exit_json(
            changed=True,
            msg=f"Security baseline written to {output_path}",
            entries=entries,
            data=security_data
        )

    except Exception as e:
        module.fail_json(msg=f"Security collection failed: {str(e)}")


if __name__ == '__main__':
    main()
