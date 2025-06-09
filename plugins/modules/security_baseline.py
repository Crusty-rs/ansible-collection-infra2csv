#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Security Baseline Collection Module
Copyright (c) 2025 Yasir Hamahdi Alsahli <crusty.rusty.engine@gmail.com>

Security posture snapshot. SELinux, firewall, SSH config, sudo users.
Compliance teams need this. Auditors love this. Keep your systems tight.
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.infra2csv_utils import (
    run_cmd, get_hostname, get_timestamp, write_csv,
    validate_schema, read_file_safe, SECURITY_FIELDS
)
import os
import re

DOCUMENTATION = '''
---
module: security_baseline
short_description: Collect security baseline information
description:
    - Gathers security configuration status including SELinux, firewall, SSH settings
    - Checks for users with sudo access and other security-relevant settings
    - Useful for compliance audits and security monitoring
options:
    csv_path:
        description: Path to the CSV file
        required: true
        type: str
    include_headers:
        description: Whether to include headers in CSV
        required: false
        type: bool
        default: true
author:
    - Yasir Hamahdi Alsahli (@crusty.rusty.engine@gmail.com)
'''

EXAMPLES = '''
# Collect security baseline
- name: Gather security configuration
  security_baseline:
    csv_path: /tmp/security_audit.csv
    include_headers: true

# Append to existing security log
- name: Add security snapshot
  security_baseline:
    csv_path: /var/lib/infra2csv/security.csv
    include_headers: false
'''


def get_selinux_status(module):
    """
    Check SELinux status. Enforcing? Permissive? Disabled?
    Security starts here on RHEL/CentOS systems.
    """
    # Method 1: getenforce command (if available)
    status = run_cmd(module, "getenforce", ignore_errors=True)
    if status and status != "N/A":
        return status.lower()  # enforcing, permissive, disabled
    
    # Method 2: Check config file (fallback)
    selinux_config = read_file_safe("/etc/selinux/config", "")
    if selinux_config:
        match = re.search(r'^SELINUX=(\w+)', selinux_config, re.MULTILINE)
        if match:
            return match.group(1).lower()
    
    return "not_installed"  # No SELinux here (Debian/Ubuntu default)


def get_firewall_status(module):
    """
    Detect and check firewall status.
    Supports firewalld (RHEL/CentOS) and iptables (everyone).
    """
    # Check firewalld first (modern systems)
    firewalld_status = run_cmd(
        module,
        "systemctl is-active firewalld",
        ignore_errors=True
    )
    if firewalld_status and firewalld_status.strip() == "active":
        return "firewalld_active"
    elif firewalld_status and firewalld_status.strip() == "inactive":
        return "firewalld_inactive"
    
    # Check iptables service
    iptables_status = run_cmd(
        module,
        "systemctl is-active iptables",
        ignore_errors=True
    )
    if iptables_status and iptables_status.strip() == "active":
        return "iptables_active"
    elif iptables_status and iptables_status.strip() == "inactive":
        return "iptables_inactive"
    
    # Check if iptables rules exist (manual setup)
    iptables_rules = run_cmd(
        module,
        "iptables -L -n | grep -c -E 'Chain|target'",
        use_shell=True,
        ignore_errors=True
    )
    if iptables_rules and iptables_rules != "N/A":
        try:
            rule_count = int(iptables_rules)
            if rule_count > 3:  # More than default chains
                return "iptables_rules_present"
        except ValueError:
            pass  # Can't parse? Skip
    
    return "no_firewall"  # Living dangerously


def get_ssh_config(module):
    """
    Parse SSH daemon config for security settings.
    Root login allowed? Password auth enabled? We checking.
    """
    ssh_config = {
        'ssh_root_login': 'N/A',
        'password_auth_status': 'N/A'
    }
    
    # Read sshd_config
    sshd_config = read_file_safe("/etc/ssh/sshd_config", "")
    if sshd_config:
        # Check PermitRootLogin setting
        match = re.search(r'^PermitRootLogin\s+(\S+)', sshd_config, re.MULTILINE | re.IGNORECASE)
        if match:
            value = match.group(1).lower()
            # Possible values: yes, no, prohibit-password, without-password, forced-commands-only
            if value in ['yes', 'prohibit-password', 'without-password', 'forced-commands-only']:
                ssh_config['ssh_root_login'] = value
            else:
                ssh_config['ssh_root_login'] = 'no'
        else:
            # Default changed over time, modern default is prohibit-password
            ssh_config['ssh_root_login'] = 'default_prohibit-password'
        
        # Check PasswordAuthentication setting
        match = re.search(r'^PasswordAuthentication\s+(\S+)', sshd_config, re.MULTILINE | re.IGNORECASE)
        if match:
            ssh_config['password_auth_status'] = match.group(1).lower()
        else:
            # Default is usually yes
            ssh_config['password_auth_status'] = 'default_yes'
    
    return ssh_config


def get_sudo_users(module):
    """
    Find all users with sudo privileges.
    Checks sudoers files and sudo/wheel groups. The power users.
    """
    sudo_users = []
    
    # Check sudoers file for direct user entries
    try:
        sudoers_content = read_file_safe("/etc/sudoers", "")
        if sudoers_content:
            # Find user entries (not groups which start with %)
            for match in re.finditer(r'^(\w+)\s+ALL=', sudoers_content, re.MULTILINE):
                user = match.group(1)
                if user not in ['root', 'Defaults']:  # Skip root and Defaults
                    sudo_users.append(user)
        
        # Check sudoers.d directory
        if os.path.exists('/etc/sudoers.d'):
            for filename in os.listdir('/etc/sudoers.d'):
                filepath = os.path.join('/etc/sudoers.d', filename)
                if os.path.isfile(filepath):
                    content = read_file_safe(filepath, "")
                    for match in re.finditer(r'^(\w+)\s+ALL=', content, re.MULTILINE):
                        user = match.group(1)
                        if user not in ['root', 'Defaults'] and user not in sudo_users:
                            sudo_users.append(user)
    except Exception:
        pass  # Sudoers parsing failed? Move to groups
    
    # Check sudo group members
    sudo_group_users = []
    
    # Check 'sudo' group (Debian/Ubuntu style)
    group_output = run_cmd(module, "getent group sudo", ignore_errors=True)
    if group_output and group_output != "N/A":
        parts = group_output.split(':')
        if len(parts) >= 4 and parts[3]:
            sudo_group_users.extend(parts[3].split(','))
    
    # Check 'wheel' group (RHEL/CentOS style)
    group_output = run_cmd(module, "getent group wheel", ignore_errors=True)
    if group_output and group_output != "N/A":
        parts = group_output.split(':')
        if len(parts) >= 4 and parts[3]:
            sudo_group_users.extend(parts[3].split(','))
    
    # Combine and deduplicate
    all_sudo_users = list(set(sudo_users + sudo_group_users))
    
    # Return as comma-separated list or 'none'
    return ','.join(all_sudo_users) if all_sudo_users else 'none'


def check_password_policy(module):
    """
    Check password policy settings from /etc/login.defs.
    Max days, min days, min length. The password rules.
    """
    policy_info = []
    
    # Read login.defs
    login_defs = read_file_safe("/etc/login.defs", "")
    if login_defs:
        # Password max age
        max_days = re.search(r'^PASS_MAX_DAYS\s+(\d+)', login_defs, re.MULTILINE)
        if max_days:
            policy_info.append(f"max_days={max_days.group(1)}")
        
        # Password min age
        min_days = re.search(r'^PASS_MIN_DAYS\s+(\d+)', login_defs, re.MULTILINE)
        if min_days:
            policy_info.append(f"min_days={min_days.group(1)}")
        
        # Password min length
        min_len = re.search(r'^PASS_MIN_LEN\s+(\d+)', login_defs, re.MULTILINE)
        if min_len:
            policy_info.append(f"min_length={min_len.group(1)}")
    
    return ','.join(policy_info) if policy_info else 'default'


def get_security_baseline(module):
    """
    Collect all security settings into one baseline snapshot.
    Everything security teams need to know in one row.
    """
    hostname = get_hostname()
    timestamp = get_timestamp()
    
    # Get SSH security settings
    ssh_config = get_ssh_config(module)
    
    # Build the security baseline data
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
    """Main execution. Security audit starts here."""
    # Define module parameters
    module = AnsibleModule(
        argument_spec=dict(
            csv_path=dict(type='str', required=True),
            include_headers=dict(type='bool', default=True)
        ),
        supports_check_mode=True  # Preview mode supported
    )
    
    # Get parameters
    csv_path = module.params['csv_path']
    include_headers = module.params['include_headers']
    
    try:
        # Gather security baseline data
        security_data = get_security_baseline(module)
        
        # Validate schema - consistency matters
        security_data = validate_schema(module, security_data, SECURITY_FIELDS)
        
        # Check mode - preview only
        if module.check_mode:
            module.exit_json(
                changed=False,
                msg="Check mode: data not written",
                security=security_data
            )
        
        # Write to CSV - document the security state
        entries = write_csv(module, csv_path, security_data, include_headers, SECURITY_FIELDS)
        
        # Success report
        module.exit_json(
            changed=True,
            msg="Security baseline data written successfully",
            entries=entries,
            security=security_data
        )
        
    except Exception as e:
        # Security scan failed? That's concerning
        module.fail_json(msg=f"Failed to collect security baseline: {str(e)}")


if __name__ == '__main__':
    main()
