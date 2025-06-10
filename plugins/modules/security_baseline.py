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
    - Writes/Gathers security configuration and writes to target host (get collected back & cleaned).
    - Checks SELinux, firewall, SSH, and sudo configuration  
    - Supports CSV and JSON output based on file extension
    - Works with existing write_csv utilities
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
    - Module runs on target hosts, not controller but with roles controller get the needed
    - Handles missing security tools gracefully
    - Compatible with minimal container environments
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

# Complete security audit in playbook
- name: Infrastructure security audit
  hosts: all
  tasks:
    - name: Collect security baseline
      crusty_rs.infra2csv.security_baseline:
        output_path: /tmp/security_{{ inventory_hostname }}.csv
      become: true
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
        timestamp: "2025-01-15T10:30:45"
'''



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


def check_sudo_access(module, username):
    """Check user sudo privileges - Enhanced with better error handling."""
    # Method 1: Check sudoers files directly
    sudoers_patterns = [
        f"^{username}\\s+ALL=",
        f"^%\\w*{username}",
        f"^%sudo.*{username}",
        f"^%wheel.*{username}"
    ]
    
    # Check main sudoers file
    sudoers_content = read_file_safe("/etc/sudoers", "")
    for pattern in sudoers_patterns:
        if re.search(pattern, sudoers_content, re.MULTILINE):
            return "yes"
    
    # Check sudoers.d directory
    if os.path.exists('/etc/sudoers.d'):
        try:
            for filename in os.listdir('/etc/sudoers.d'):
                filepath = os.path.join('/etc/sudoers.d', filename)
                if os.path.isfile(filepath):
                    content = read_file_safe(filepath, "")
                    for pattern in sudoers_patterns:
                        if re.search(pattern, content, re.MULTILINE):
                            return "yes"
        except Exception:
            pass

    # Method 2: Check group membership
    # Try getent first
    getent_exists = run_cmd(module, "which getent", ignore_errors=True)
    if getent_exists != "N/A":
        groups_output = run_cmd(module, f"groups {username}", ignore_errors=True)
        if groups_output != "N/A":
            if any(group in groups_output for group in ['sudo', 'wheel', 'admin']):
                return "yes"
    else:
        # Fallback: check /etc/group directly
        group_content = read_file_safe('/etc/group', '')
        for group_name in ['sudo', 'wheel', 'admin']:
            pattern = f"^{group_name}:.*:.*:.*{username}"
            if re.search(pattern, group_content, re.MULTILINE):
                return "yes"

    # Method 3: Check if user can run sudo (if sudo is installed)
    sudo_exists = run_cmd(module, "which sudo", ignore_errors=True)
    if sudo_exists != "N/A":
        # This is a bit risky, but we can try a non-interactive check
        sudo_test = run_cmd(
            module, 
            f"timeout 2 sudo -n -l -U {username} 2>/dev/null | grep -q 'may run'", 
            use_shell=True, 
            ignore_errors=True
        )
        if sudo_test != "N/A":
            return "yes"

    return "no"


def get_user_cron_jobs(module, username):
    """Get user's cron jobs with better error handling."""
    cron_jobs = []

    # Check if crontab command exists first
    crontab_exists = run_cmd(module, "which crontab", ignore_errors=True)
    if crontab_exists == "N/A":
        # No crontab command available
        return cron_jobs

    # User crontab
    crontab_output = run_cmd(module, f"crontab -l -u {username}", ignore_errors=True)
    if crontab_output != "N/A" and "no crontab" not in crontab_output.lower():
        for line in crontab_output.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Parse cron entry (time + command)
            match = re.match(r'^(@\w+|[\d\-\*/,]+\s+[\d\-\*/,]+\s+[\d\-\*/,]+\s+[\d\-\*/,]+\s+[\d\-\*/,]+)\s+(.+)$', line)
            if match:
                schedule, command = match.groups()
                cron_jobs.append({
                    'schedule': schedule,
                    'command': command[:200],  # Limit for CSV
                    'enabled': 'yes'
                })

    return cron_jobs
