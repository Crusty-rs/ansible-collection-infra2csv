#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, yasir hamadi alsahli <crusty.rusty.engine@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: users_csv
short_description: Collect user account and cron job information from target systems
description:
    - Gathers user accounts and scheduled jobs to target host
    - Includes sudo privileges and cron job details
    - Supports CSV and JSON output based on file extension
    - Enhanced error handling for minimal environments
    - Version 6 with improved compatibility
version_added: "1.0.0"
author:
    - yasir hamadi alsahli (@crusty.rusty.engine)
options:
    output_path:
        description: 
            - Output file path for user data
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
    include_system_users:
        description: 
            - Include system users with UID less than 1000
            - When false, only regular user accounts are included
        required: false
        type: bool
        default: false
requirements:
    - Target systems must be Linux-based
    - Python 3.6+ on target systems
    - Access to /etc/passwd for user enumeration
notes:
    - Module runs on target hosts, not controller
    - Handles missing crontab command gracefully
    - Compatible with minimal container environments
    - Version 6 with enhanced Rocky/Alma compatibility
seealso:
    - module: ansible.builtin.user
    - module: crusty_rs.infra2csv.security_baseline
'''

EXAMPLES = r'''
# Regular users only to CSV
- name: Collect user accounts
  crusty_rs.infra2csv.users_csv:
    output_path: /tmp/users.csv
    include_system_users: false

# All users including system accounts
- name: Complete user audit
  crusty_rs.infra2csv.users_csv:
    output_path: /tmp/all_users.csv
    include_system_users: true
    include_headers: true

# Users and cron jobs to JSON
- name: User data to JSON format
  crusty_rs.infra2csv.users_csv:
    output_path: /tmp/users_{{ ansible_date_time.date }}.json
    include_system_users: true

# Complete user collection playbook
- name: Infrastructure user audit
  hosts: all
  become: true
  tasks:
    - name: Collect user information
      crusty_rs.infra2csv.users_csv:
        output_path: /tmp/users_{{ inventory_hostname }}.csv
        include_system_users: false
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
    sample: "User data written to /tmp/users.csv"
entries:
    description: Number of data entries written
    type: int
    returned: success
    sample: 15
data:
    description: The user data that was collected
    type: list
    returned: success
    sample:
        - hostname: "server01"
          username: "admin"
          uid: "1000"
          gid: "1000"
          home_directory: "/home/admin"
          shell: "/bin/bash"
          last_login: "Mon Jun 11 10:30:45"
          is_privileged: "yes"
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.crusty_rs.infra2csv.plugins.module_utils.infra2csv_utils import (
    run_cmd, get_hostname, get_timestamp, write_csv,
    validate_schema, read_file_safe, USER_FIELDS
)
import pwd
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


def check_sudo_access(module, username):
    """Check user sudo privileges - Enhanced with better error handling."""
    # Method 1: Check sudoers files directly (most reliable)
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

    # Method 2: Check group membership - Enhanced approach
    # Try getent first (if available)
    getent_exists = run_cmd(module, "which getent", ignore_errors=True)
    if getent_exists != "N/A":
        groups_output = run_cmd(module, f"groups {username}", ignore_errors=True)
        if groups_output != "N/A":
            if any(group in groups_output for group in ['sudo', 'wheel', 'admin']):
                return "yes"
    else:
        # Fallback: Parse /etc/group directly
        group_content = read_file_safe('/etc/group', '')
        for group_name in ['sudo', 'wheel', 'admin']:
            # Look for username in group members
            pattern = f"^{group_name}:.*:.*:.*\\b{username}\\b"
            if re.search(pattern, group_content, re.MULTILINE):
                return "yes"

    # Method 3: Check user's primary group
    try:
        user_info = pwd.getpwnam(username)
        import grp
        primary_group = grp.getgrgid(user_info.pw_gid)
        if primary_group.gr_name in ['sudo', 'wheel', 'admin']:
            return "yes"
    except Exception:
        pass

    return "no"


def get_user_cron_jobs(module, username):
    """Get user's cron jobs with enhanced error handling."""
    cron_jobs = []

    # Check if crontab command exists first
    crontab_exists = run_cmd(module, "which crontab", ignore_errors=True)
    if crontab_exists == "N/A":
        # No crontab command available - check alternative locations
        return check_alternative_cron_sources(module, username)

    # Try to get user crontab
    try:
        crontab_output = run_cmd(module, f"crontab -l -u {username}", ignore_errors=True)
        
        # Handle common crontab error messages
        if crontab_output == "N/A" or any(msg in crontab_output.lower() for msg in [
            'no crontab', 'cannot open', 'permission denied', 'no such file'
        ]):
            return cron_jobs
        
        # Parse crontab output
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

    except Exception as e:
        # Log warning but don't fail
        module.warn(f"Could not retrieve crontab for user {username}: {str(e)}")

    return cron_jobs


def check_alternative_cron_sources(module, username):
    """Check alternative cron sources when crontab command is not available."""
    cron_jobs = []
    
    # Check user's crontab file directly (if accessible)
    possible_cron_paths = [
        f"/var/spool/cron/crontabs/{username}",
        f"/var/spool/cron/{username}",
        f"/var/cron/tabs/{username}"
    ]
    
    for cron_path in possible_cron_paths:
        cron_content = read_file_safe(cron_path, "")
        if cron_content:
            for line in cron_content.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                match = re.match(r'^(@\w+|[\d\-\*/,]+\s+[\d\-\*/,]+\s+[\d\-\*/,]+\s+[\d\-\*/,]+\s+[\d\-\*/,]+)\s+(.+)$', line)
                if match:
                    schedule, command = match.groups()
                    cron_jobs.append({
                        'schedule': schedule,
                        'command': command[:200],
                        'enabled': 'yes'
                    })
            break  # Found crontab file, no need to check others
    
    return cron_jobs


def get_user_last_login(module, username):
    """Get user's last login with multiple methods."""
    # Method 1: lastlog command
    lastlog_output = run_cmd(module, f"lastlog -u {username}", ignore_errors=True)
    if lastlog_output != "N/A" and "Never logged in" not in lastlog_output:
        lines = lastlog_output.splitlines()
        if len(lines) > 1:
            match = re.search(r'(\w{3}\s+\w{3}\s+\d+\s+\d+:\d+:\d+)', lines[1])
            if match:
                return match.group(1)
    
    # Method 2: last command
    last_output = run_cmd(module, f"last -n 1 {username}", ignore_errors=True)
    if last_output != "N/A":
        lines = last_output.splitlines()
        for line in lines:
            if username in line and "wtmp begins" not in line:
                match = re.search(r'(\w{3}\s+\w{3}\s+\d+\s+\d+:\d+)', line)
                if match:
                    return match.group(1)
    
    # Method 3: who command for currently logged in users
    who_output = run_cmd(module, "who", ignore_errors=True)
    if who_output != "N/A":
        for line in who_output.splitlines():
            if line.startswith(username + " "):
                return "Currently logged in"
    
    return "N/A"


def get_system_cron_jobs(module):
    """System-wide cron jobs - Enhanced error handling."""
    system_jobs = []
    hostname = get_hostname()
    timestamp = get_timestamp()

    # /etc/crontab - Enhanced parsing
    crontab_content = read_file_safe('/etc/crontab', '')
    if crontab_content:
        for line_num, line in enumerate(crontab_content.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('SHELL=') or line.startswith('PATH='):
                continue

            # System crontab: time user command
            match = re.match(r'^([@\d\-\*/,\s]+)\s+(\S+)\s+(.+)$', line)
            if match:
                schedule_part, username, command = match.groups()
                
                # Validate schedule format
                if re.match(r'^(@\w+|[\d\-\*/,]+\s+[\d\-\*/,]+\s+[\d\-\*/,]+\s+[\d\-\*/,]+\s+[\d\-\*/,]+)$', schedule_part.strip()):
                    system_jobs.append({
                        'hostname': hostname,
                        'username': username,
                        'uid': 'N/A',
                        'gid': 'N/A',
                        'home_directory': 'N/A',
                        'shell': 'N/A',
                        'last_login': 'N/A',
                        'schedule': schedule_part.strip(),
                        'command': command[:200],
                        'source_type': 'system_cron',
                        'enabled': 'yes',
                        'next_run_time': 'N/A',
                        'timestamp': timestamp,
                        'is_privileged': 'yes'
                    })

    # /etc/cron.d/ - Enhanced parsing
    if os.path.exists('/etc/cron.d'):
        try:
            for filename in os.listdir('/etc/cron.d'):
                filepath = os.path.join('/etc/cron.d', filename)
                if os.path.isfile(filepath) and not filename.startswith('.'):
                    content = read_file_safe(filepath, '')
                    for line in content.splitlines():
                        line = line.strip()
                        if not line or line.startswith('#') or '=' in line:
                            continue

                        match = re.match(r'^([@\d\-\*/,\s]+)\s+(\S+)\s+(.+)$', line)
                        if match:
                            schedule_part, username, command = match.groups()
                            
                            if re.match(r'^(@\w+|[\d\-\*/,]+\s+[\d\-\*/,]+\s+[\d\-\*/,]+\s+[\d\-\*/,]+\s+[\d\-\*/,]+)$', schedule_part.strip()):
                                system_jobs.append({
                                    'hostname': hostname,
                                    'username': username,
                                    'uid': 'N/A',
                                    'gid': 'N/A',
                                    'home_directory': 'N/A',
                                    'shell': 'N/A',
                                    'last_login': 'N/A',
                                    'schedule': schedule_part.strip(),
                                    'command': command[:200],
                                    'source_type': f'cron.d/{filename}',
                                    'enabled': 'yes',
                                    'next_run_time': 'N/A',
                                    'timestamp': timestamp,
                                    'is_privileged': 'yes'
                                })
        except Exception as e:
            module.warn(f"Error reading /etc/cron.d: {str(e)}")

    return system_jobs


def collect_user_data(module, include_system_users=False):
    """Main user data collection - Enhanced error handling."""
    users_data = []
    timestamp = get_timestamp()
    hostname = get_hostname()

    # Enumerate users from passwd with better error handling
    try:
        users_processed = 0
        users_failed = 0
        
        for user in pwd.getpwall():
            try:
                # Filter system users if requested
                if not include_system_users and user.pw_uid < 1000:
                    continue

                # Get last login with multiple methods
                last_login = get_user_last_login(module, user.pw_name)

                # Check privileges (with enhanced error handling)
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
                users_processed += 1

                # Add user's cron jobs (with enhanced error handling)
                try:
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
                    module.warn(f"Failed to get cron jobs for user {user.pw_name}: {str(e)}")
                    users_failed += 1

            except Exception as e:
                module.warn(f"Failed to process user {user.pw_name}: {str(e)}")
                users_failed += 1

        if users_failed > 0:
            module.warn(f"User processing complete: {users_processed} processed, {users_failed} failed")

    except Exception as e:
        module.warn(f"User enumeration failed: {str(e)}")

    # Add system cron jobs (with error handling)
    try:
        system_jobs = get_system_cron_jobs(module)
        users_data.extend(system_jobs)
    except Exception as e:
        module.warn(f"System cron job collection failed: {str(e)}")

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
