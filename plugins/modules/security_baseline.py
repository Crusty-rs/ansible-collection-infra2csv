#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Security Baseline Collection Module - Fixed for existing utils
Copyright (c) 2025 Yasir Hamadi Alsahli <crusty.rusty.engine@gmail.com>

Target-only security posture collection. Works with existing write_csv.
SELinux, firewall, SSH, sudo analysis. Compliance snapshot.
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.infra2csv_utils import (
    run_cmd, get_hostname, get_timestamp, write_csv,
    validate_schema, read_file_safe, SECURITY_FIELDS
)
import os
import re
import json
from pathlib import Path

DOCUMENTATION = '''
---
module: security_baseline
short_description: Collect security baseline locally
description:
    - Gathers security configuration and writes to target host
    - Checks SELinux, firewall, SSH, and sudo configuration
    - Supports CSV and JSON output based on file extension
options:
    output_path:
        description: Output file path (.csv or .json)
        required: true
        type: str
    include_headers:
        description: Include CSV headers (ignored for JSON)
        required: false
        type: bool
        default: true
author:
    - Yasir Hamadi Alsahli (@crusty.rusty.engine@gmail.com)
'''

EXAMPLES = '''
# Security baseline to CSV
- name: Security configuration audit
  security_baseline:
    output_path: /tmp/security.csv

# Full baseline to JSON
- name: Security baseline snapshot
  security_baseline:
    output_path: /tmp/security.json
'''


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
    """SELinux status detection. Multiple methods."""
    # Method 1: getenforce command
    status = run_cmd(module, "getenforce", ignore_errors=True)
    if status != "N/A":
        return status.lower()
    
    # Method 2: config file
    selinux_config = read_file_safe("/etc/selinux/config", "")
    if selinux_config:
        match = re.search(r'^SELINUX=(\w+)', selinux_config, re.MULTILINE)
        if match:
            return match.group(1).lower()
    
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
    """Find all users with sudo privileges."""
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
    
    # Check sudo group
    sudo_group_users = []
    for group_name in ['sudo', 'wheel']:
        group_output = run_cmd(module, f"getent group {group_name}", ignore_errors=True)
        if group_output != "N/A":
            parts = group_output.split(':')
            if len(parts) >= 4 and parts[3]:
                sudo_group_users.extend(parts[3].split(','))
    
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
