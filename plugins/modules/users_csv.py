#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
User Facts Collection Module - Fixed for existing utils
Copyright (c) 2025 Yasir Hamadi Alsahli <crusty.rusty.engine@gmail.com>

Target-only user and cron collection. Works with existing write_csv.
Complete user profile with privileges. Zero controller dependencies.
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.infra2csv_utils import (
    run_cmd, get_hostname, get_timestamp, write_csv,
    validate_schema, read_file_safe, USER_FIELDS
)
import pwd
import os
import re
import json
from pathlib import Path

DOCUMENTATION = '''
---
module: users_csv
short_description: Collect user and cron info locally
description:
    - Gathers user accounts and scheduled jobs to target host
    - Includes sudo privileges and cron job details
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
    include_system_users:
        description: Include system users (UID < 1000)
        required: false
        type: bool
        default: false
author:
    - Yasir Hamadi Alsahli (@crusty.rusty.engine@gmail.com)
'''

EXAMPLES = '''
# Regular users only to CSV
- name: User accounts to CSV
  users_csv:
    output_path: /tmp/users.csv
    include_system_users: false

# All users to JSON  
- name: All users and cron jobs
  users_csv:
    output_path: /tmp/users_all.json
    include_system_users: true
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


def check_sudo_access(module, username):
    """Check user sudo privileges. Multiple detection methods."""
    # Check sudoers files
    sudoers_output = run_cmd(
        module,
        f"grep -E '^{username}|^%.*{username}' /etc/sudoers /etc/sudoers.d/* 2>/dev/null",
        use_shell=True,
        ignore_errors=True
    )
    
    if sudoers_output != "N/A" and username in sudoers_output:
        return "yes"
    
    # Check group membership
    groups_output = run_cmd(module, f"groups {username}", ignore_errors=True)
    if groups_output != "N/A":
        if 'sudo' in groups_output or 'wheel' in groups_output:
            return "yes"
    
    return "no"


def get_user_cron_jobs(module, username):
    """Get user's cron jobs. Robust parsing."""
    cron_jobs = []
    
    # User crontab
    crontab_output = run_cmd(module, f"crontab -l -u {username}", ignore_errors=True)
    if crontab_output != "N/A":
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


def get_system_cron_jobs(module):
    """System-wide cron jobs from /etc/crontab and /etc/cron.d/."""
    system_jobs = []
    hostname = get_hostname()
    timestamp = get_timestamp()
    
    # /etc/crontab
    crontab_content = read_file_safe('/etc/crontab', '')
    if crontab_content:
        for line in crontab_content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # System crontab: time user command
            match = re.match(r'^([\d\-\*/,]+\s+[\d\-\*/,]+\s+[\d\-\*/,]+\s+[\d\-\*/,]+\s+[\d\-\*/,]+)\s+(\S+)\s+(.+)$', line)
            if match:
                schedule, username, command = match.groups()
                system_jobs.append({
                    'hostname': hostname,
                    'username': username,
                    'uid': 'N/A',
                    'gid': 'N/A',
                    'home_directory': 'N/A',
                    'shell': 'N/A',
                    'last_login': 'N/A',
                    'schedule': schedule,
                    'command': command[:200],
                    'source_type': 'system_cron',
                    'enabled': 'yes',
                    'next_run_time': 'N/A',
                    'timestamp': timestamp,
                    'is_privileged': 'yes'
                })
    
    # /etc/cron.d/
    if os.path.exists('/etc/cron.d'):
        try:
            for filename in os.listdir('/etc/cron.d'):
                filepath = os.path.join('/etc/cron.d', filename)
                if os.path.isfile(filepath):
                    content = read_file_safe(filepath, '')
                    for line in content.splitlines():
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        
                        match = re.match(r'^([\d\-\*/,]+\s+[\d\-\*/,]+\s+[\d\-\*/,]+\s+[\d\-\*/,]+\s+[\d\-\*/,]+)\s+(\S+)\s+(.+)$', line)
                        if match:
                            schedule, username, command = match.groups()
                            system_jobs.append({
                                'hostname': hostname,
                                'username': username,
                                'uid': 'N/A',
                                'gid': 'N/A', 
                                'home_directory': 'N/A',
                                'shell': 'N/A',
                                'last_login': 'N/A',
                                'schedule': schedule,
                                'command': command[:200],
                                'source_type': f'cron.d/{filename}',
                                'enabled': 'yes',
                                'next_run_time': 'N/A',
                                'timestamp': timestamp,
                                'is_privileged': 'yes'
                            })
        except Exception:
            pass
    
    return system_jobs


def collect_user_data(module, include_system_users=False):
    """Main user data collection. Users + their cron jobs."""
    users_data = []
    timestamp = get_timestamp()
    hostname = get_hostname()
    
    # Enumerate users from passwd
    try:
        for user in pwd.getpwall():
            # Filter system users if requested
            if not include_system_users and user.pw_uid < 1000:
                continue
            
            # Get last login
            last_login = 'N/A'
            lastlog_output = run_cmd(
                module,
                f"lastlog -u {user.pw_name}",
                use_shell=True,
                ignore_errors=True
            )
            if lastlog_output != "N/A":
                lines = lastlog_output.splitlines()
                if len(lines) > 1:
                    match = re.search(r'(\w{3}\s+\w{3}\s+\d+\s+\d+:\d+:\d+)', lines[1])
                    if match:
                        last_login = match.group(1)
            
            # Check privileges
            is_privileged = check_sudo_access(module, user.pw_name)
            
            # Base user entry
            user_info = {
                'hostname': hostname,
                'username': user.pw_name,
                'uid': str(user.pw_uid),
                'gid': str(user.pw_gid),
                'home_directory': user.pw_dir,
                'shell': user.pw_shell,
                'last_login': last_login,
                'schedule': 'N/A',
                'command': 'N/A',
                'source_type': 'user_account',
                'enabled': 'yes',
                'next_run_time': 'N/A',
                'timestamp': timestamp,
                'is_privileged': is_privileged
            }
            
            users_data.append(user_info)
            
            # Add user's cron jobs
            cron_jobs = get_user_cron_jobs(module, user.pw_name)
            for job in cron_jobs:
                job_info = user_info.copy()
                job_info.update({
                    'schedule': job['schedule'],
                    'command': job['command'],
                    'source_type': 'cron',
                    'enabled': job['enabled']
                })
                users_data.append(job_info)
                
    except Exception as e:
        module.warn(f"User enumeration failed: {str(e)}")
    
    # Add system cron jobs
    system_jobs = get_system_cron_jobs(module)
    users_data.extend(system_jobs)
    
    return users_data


def main():
    """Main execution. Target-only user collection."""
    module = AnsibleModule(
        argument_spec=dict(
            output_path=dict(type='str', required=True),
            include_headers=dict(type='bool', default=True),
            include_system_users=dict(type='bool', default=False)
        ),
        supports_check_mode=True
    )
    
    output_path = module.params['output_path']
    include_headers = module.params['include_headers']
    include_system_users = module.params['include_system_users']
    
    try:
        # Collect user data
        users_data = collect_user_data(module, include_system_users)
        
        # Validate schema
        if users_data:
            users_data = validate_schema(module, users_data, USER_FIELDS)
        
        # Check mode
        if module.check_mode:
            module.exit_json(
                changed=False,
                msg="Check mode: data not written",
                data=users_data,
                entries=len(users_data)
            )
        
        # Handle no data
        if not users_data:
            module.exit_json(
                changed=False,
                msg="No user data found",
                entries=0
            )
        
        # Write data locally
        entries = write_data_local(
            module,
            output_path,
            users_data,
            include_headers,
            USER_FIELDS
        )
        
        # Success
        module.exit_json(
            changed=True,
            msg=f"User data written to {output_path}",
            entries=entries,
            data=users_data
        )
        
    except Exception as e:
        module.fail_json(msg=f"User collection failed: {str(e)}")


if __name__ == '__main__':
    main()
