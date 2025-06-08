#!/usr/bin/python3
# -*- coding: utf-8 -*-

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
'''


def get_selinux_status(module):
    """Get SELinux status"""
    # Try getenforce command first
    status = run_cmd(module, "getenforce", ignore_errors=True)
    if status and status != "N/A":
        return status.lower()
    
    # Fallback to config file
    selinux_config = read_file_safe("/etc/selinux/config", "")
    if selinux_config:
        match = re.search(r'^SELINUX=(\w+)', selinux_config, re.MULTILINE)
        if match:
            return match.group(1).lower()
    
    return "not_installed"


def get_firewall_status(module):
    """Get firewall status (firewalld or iptables)"""
    # Check firewalld first
    firewalld_status = run_cmd(
        module,
        "systemctl is-active firewalld",
        ignore_errors=True
    )
    if firewalld_status and firewalld_status.strip() == "active":
        return "firewalld_active"
    elif firewalld_status and firewalld_status.strip() == "inactive":
        return "firewalld_inactive"
    
    # Check iptables
    iptables_status = run_cmd(
        module,
        "systemctl is-active iptables",
        ignore_errors=True
    )
    if iptables_status and iptables_status.strip() == "active":
        return "iptables_active"
    elif iptables_status and iptables_status.strip() == "inactive":
        return "iptables_inactive"
    
    # Check if iptables rules exist
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
            pass
    
    return "no_firewall"


def get_ssh_config(module):
    """Get SSH security configuration"""
    ssh_config = {
        'ssh_root_login': 'N/A',
        'password_auth_status': 'N/A'
    }
    
    sshd_config = read_file_safe("/etc/ssh/sshd_config", "")
    if sshd_config:
        # Check PermitRootLogin
        match = re.search(r'^PermitRootLogin\s+(\S+)', sshd_config, re.MULTILINE | re.IGNORECASE)
        if match:
            value = match.group(1).lower()
            if value in ['yes', 'prohibit-password', 'without-password', 'forced-commands-only']:
                ssh_config['ssh_root_login'] = value
            else:
                ssh_config['ssh_root_login'] = 'no'
        else:
            # Default is usually prohibit-password in modern systems
            ssh_config['ssh_root_login'] = 'default_prohibit-password'
        
        # Check PasswordAuthentication
        match = re.search(r'^PasswordAuthentication\s+(\S+)', sshd_config, re.MULTILINE | re.IGNORECASE)
        if match:
            ssh_config['password_auth_status'] = match.group(1).lower()
        else:
            # Default is usually yes
            ssh_config['password_auth_status'] = 'default_yes'
    
    return ssh_config


def get_sudo_users(module):
    """Get list of users with sudo access"""
    sudo_users = []
    
    # Check sudoers file
    try:
        # Get users from sudoers
        sudoers_content = read_file_safe("/etc/sudoers", "")
        if sudoers_content:
            # Find user entries (not groups)
            for match in re.finditer(r'^(\w+)\s+ALL=', sudoers_content, re.MULTILINE):
                user = match.group(1)
                if user not in ['root', 'Defaults']:
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
        pass
    
    # Check sudo group members
    sudo_group_users = []
    
    # Check 'sudo' group (Debian/Ubuntu)
    group_output = run_cmd(module, "getent group sudo", ignore_errors=True)
    if group_output and group_output != "N/A":
        parts = group_output.split(':')
        if len(parts) >= 4 and parts[3]:
            sudo_group_users.extend(parts[3].split(','))
    
    # Check 'wheel' group (RHEL/CentOS)
    group_output = run_cmd(module, "getent group wheel", ignore_errors=True)
    if group_output and group_output != "N/A":
        parts = group_output.split(':')
        if len(parts) >= 4 and parts[3]:
            sudo_group_users.extend(parts[3].split(','))
    
    # Combine and deduplicate
    all_sudo_users = list(set(sudo_users + sudo_group_users))
    
    return ','.join(all_sudo_users) if all_sudo_users else 'none'


def check_password_policy(module):
    """Check password policy settings"""
    policy_info = []
    
    # Check /etc/login.defs
    login_defs = read_file_safe("/etc/login.defs", "")
    if login_defs:
        # Password aging
        max_days = re.search(r'^PASS_MAX_DAYS\s+(\d+)', login_defs, re.MULTILINE)
        if max_days:
            policy_info.append(f"max_days={max_days.group(1)}")
        
        min_days = re.search(r'^PASS_MIN_DAYS\s+(\d+)', login_defs, re.MULTILINE)
        if min_days:
            policy_info.append(f"min_days={min_days.group(1)}")
        
        min_len = re.search(r'^PASS_MIN_LEN\s+(\d+)', login_defs, re.MULTILINE)
        if min_len:
            policy_info.append(f"min_length={min_len.group(1)}")
    
    return ','.join(policy_info) if policy_info else 'default'


def get_security_baseline(module):
    """Gather all security baseline information"""
    hostname = get_hostname()
    timestamp = get_timestamp()
    
    # Get SSH configuration
    ssh_config = get_ssh_config(module)
    
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
    module = AnsibleModule(
        argument_spec=dict(
            csv_path=dict(type='str', required=True),
            include_headers=dict(type='bool', default=True)
        ),
        supports_check_mode=True
    )
    
    csv_path = module.params['csv_path']
    include_headers = module.params['include_headers']
    
    try:
        # Gather security baseline data
        security_data = get_security_baseline(module)
        
        # Validate schema
        security_data = validate_schema(module, security_data, SECURITY_FIELDS)
        
        # Check mode
        if module.check_mode:
            module.exit_json(
                changed=False,
                msg="Check mode: data not written",
                security=security_data
            )
        
        # Write to CSV
        entries = write_csv(module, csv_path, security_data, include_headers, SECURITY_FIELDS)
        
        module.exit_json(
            changed=True,
            msg="Security baseline data written successfully",
            entries=entries,
            security=security_data
        )
        
    except Exception as e:
        module.fail_json(msg=f"Failed to collect security baseline: {str(e)}")


if __name__ == '__main__':
    main()
