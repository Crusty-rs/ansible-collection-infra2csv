#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
User Facts Collection Module  
Copyright (c) 2025 Yasir Hamadi Alsahli <crusty.rusty.engine@gmail.com>

User accounts, cron jobs, sudo access. The who's who of your system.
Tracks scheduled tasks and privilege levels. Security loves this data.
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.infra2csv_utils import (
    run_cmd, get_hostname, get_timestamp, write_csv, 
    validate_schema, read_file_safe, USER_FIELDS
)
import pwd
import os
import re

DOCUMENTATION = '''
---
module: users_csv
short_description: Collect user information and scheduled jobs
description:
    - Gathers user account information and their scheduled jobs
    - Includes cron jobs (user and system) and sudo privileges
    - Can filter system users (UID < 1000)
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
    include_system_users:
        description: Include system users (UID < 1000)
        required: false
        type: bool
        default: false
author:
    - Yasir Hamadi Alsahli (@crusty.rusty.engine@gmail.com)
'''

EXAMPLES = '''
# Collect regular users only
- name: Collect user information
  users_csv:
    csv_path: /tmp/users.csv
    include_headers: true
    include_system_users: false

# Include system users
- name: Collect all users including system accounts
  users_csv:
    csv_path: /var/lib/infra2csv/users_all.csv
    include_system_users: true
'''


def get_user_info(module, include_system_users=False):
    """
    Get user account details and their scheduled jobs.
    Combines passwd info with cron jobs. Full user profile.
    """
    users_data = []
    timestamp = get_timestamp()
    hostname = get_hostname()
    
    # Enumerate all users from passwd database
    try:
        for user in pwd.getpwall():
            # Filter system users if not wanted
            if not include_system_users and user.pw_uid < 1000:
                continue  # System user, skipping
            
            # Get last login info (might not be available)
            last_login = 'N/A'
            lastlog_output = run_cmd(
                module, 
                f"lastlog -u {user.pw_name}", 
                use_shell=True, 
                ignore_errors=True
            )
            if lastlog_output and lastlog_output != "N/A":
                lines = lastlog_output.splitlines()
                if len(lines) > 1:
                    # Parse last login date from output
                    match = re.search(r'(\w{3}\s+\w{3}\s+\d+\s+\d+:\d+:\d+)', lines[1])
                    if match:
                        last_login = match.group(1)
            
            # Check sudo privileges
            is_privileged = check_sudo_access(module, user.pw_name)
            
            # Base user info row
            user_info = {
                'hostname': hostname,
                'username': user.pw_name,
                'uid': str(user.pw_uid),
                'gid': str(user.pw_gid),
                'home_directory': user.pw_dir,
                'shell': user.pw_shell,
                'last_login': last_login,
                'schedule': 'N/A',  # No schedule for base user entry
                'command': 'N/A',
                'source_type': 'user_account',
                'enabled': 'yes',
                'next_run_time': 'N/A',
                'timestamp': timestamp,
                'is_privileged': is_privileged
            }
            
            users_data.append(user_info)
            
            # Get user's cron jobs
            cron_jobs = get_user_cron_jobs(module, user.pw_name)
            for job in cron_jobs:
                # Create new row for each cron job
                job_info = user_info.copy()
                job_info.update({
                    'schedule': job['schedule'],
                    'command': job['command'],
                    'source_type': 'cron',
                    'enabled': job['enabled'],
                    'next_run_time': 'N/A'  # Could calculate but complex
                })
                users_data.append(job_info)
            
    except Exception as e:
        # User enumeration failed? That's bad
        module.warn(f"Failed to enumerate users: {str(e)}")
    
    return users_data


def check_sudo_access(module, username):
    """
    Check if user has sudo privileges.
    Checks sudoers files and sudo/wheel group membership.
    """
    # Check sudoers file and sudoers.d directory
    sudoers_output = run_cmd(
        module,
        f"grep -E '^{username}|^%.*{username}' /etc/sudoers /etc/sudoers.d/* 2>/dev/null",
        use_shell=True,
        ignore_errors=True
    )
    
    if sudoers_output and sudoers_output != "N/A" and username in sudoers_output:
        return "yes"  # Found in sudoers
    
    # Check group membership (sudo or wheel)
    groups_output = run_cmd(
        module,
        f"groups {username}",
        ignore_errors=True
    )
    
    if groups_output and groups_output != "N/A":
        if 'sudo' in groups_output or 'wheel' in groups_output:
            return "yes"  # Member of sudo/wheel group
    
    return "no"  # No sudo access found


def get_user_cron_jobs(module, username):
    """
    Get cron jobs for a specific user.
    Parses crontab -l output. Returns list of jobs.
    """
    cron_jobs = []
    
    # Get user's crontab
    crontab_output = run_cmd(
        module,
        f"crontab -l -u {username}",
        ignore_errors=True
    )
    
    if crontab_output and crontab_output != "N/A":
        for line in crontab_output.splitlines():
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Parse cron entry
            # Format: minute hour day month weekday command
            # Or: @reboot, @daily, etc.
            match = re.match(r'^(@\w+|[\d\-\*/,]+\s+[\d\-\*/,]+\s+[\d\-\*/,]+\s+[\d\-\*/,]+\s+[\d\-\*/,]+)\s+(.+)$', line)
            if match:
                schedule = match.group(1)
                command = match.group(2)
                
                cron_jobs.append({
                    'schedule': schedule,
                    'command': command[:200],  # Limit length for CSV
                    'enabled': 'yes'  # Active cron entries
                })
    
    return cron_jobs


def get_system_cron_jobs(module):
    """
    Get system-wide cron jobs from /etc/crontab and /etc/cron.d/.
    These run as specific users but are centrally managed.
    """
    system_jobs = []
    hostname = get_hostname()
    timestamp = get_timestamp()
    
    # Check /etc/crontab (the main system crontab)
    try:
        if os.path.exists('/etc/crontab'):
            with open('/etc/crontab', 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # System crontab includes username field
                    match = re.match(r'^([\d\-\*/,]+\s+[\d\-\*/,]+\s+[\d\-\*/,]+\s+[\d\-\*/,]+\s+[\d\-\*/,]+)\s+(\S+)\s+(.+)$', line)
                    if match:
                        system_jobs.append({
                            'hostname': hostname,
                            'username': match.group(2),  # User who runs the job
                            'uid': 'N/A',
                            'gid': 'N/A',
                            'home_directory': 'N/A',
                            'shell': 'N/A',
                            'last_login': 'N/A',
                            'schedule': match.group(1),
                            'command': match.group(3)[:200],
                            'source_type': 'system_cron',
                            'enabled': 'yes',
                            'next_run_time': 'N/A',
                            'timestamp': timestamp,
                            'is_privileged': 'yes'  # System cron = privileged
                        })
    except Exception:
        pass  # Can't read /etc/crontab? Moving on
    
    # Check /etc/cron.d/ directory
    try:
        if os.path.exists('/etc/cron.d'):
            for filename in os.listdir('/etc/cron.d'):
                filepath = os.path.join('/etc/cron.d', filename)
                if os.path.isfile(filepath):
                    try:
                        with open(filepath, 'r') as f:
                            for line in f:
                                line = line.strip()
                                if not line or line.startswith('#'):
                                    continue
                                
                                # Same format as /etc/crontab
                                match = re.match(r'^([\d\-\*/,]+\s+[\d\-\*/,]+\s+[\d\-\*/,]+\s+[\d\-\*/,]+\s+[\d\-\*/,]+)\s+(\S+)\s+(.+)$', line)
                                if match:
                                    system_jobs.append({
                                        'hostname': hostname,
                                        'username': match.group(2),
                                        'uid': 'N/A',
                                        'gid': 'N/A',
                                        'home_directory': 'N/A',
                                        'shell': 'N/A',
                                        'last_login': 'N/A',
                                        'schedule': match.group(1),
                                        'command': match.group(3)[:200],
                                        'source_type': f'cron.d/{filename}',
                                        'enabled': 'yes',
                                        'next_run_time': 'N/A',
                                        'timestamp': timestamp,
                                        'is_privileged': 'yes'
                                    })
                    except Exception:
                        pass  # Can't read this cron file? Next
    except Exception:
        pass  # /etc/cron.d issues? It happens
    
    return system_jobs


def main():
    """Main execution. User enumeration begins."""
    # Define module parameters
    module = AnsibleModule(
        argument_spec=dict(
            csv_path=dict(type='str', required=True),
            include_headers=dict(type='bool', default=True),
            include_system_users=dict(type='bool', default=False)
        ),
        supports_check_mode=True  # Support dry runs
    )
    
    # Get parameters
    csv_path = module.params['csv_path']
    include_headers = module.params['include_headers']
    include_system_users = module.params['include_system_users']
    
    try:
        # Gather user account data
        users_data = get_user_info(module, include_system_users)
        
        # Add system cron jobs (always included)
        system_jobs = get_system_cron_jobs(module)
        users_data.extend(system_jobs)
        
        # Validate schema - keep it clean
        if users_data:
            users_data = validate_schema(module, users_data, USER_FIELDS)
        
        # Check mode - preview only
        if module.check_mode:
            module.exit_json(
                changed=False,
                msg="Check mode: data not written",
                users=users_data,
                entries=len(users_data)
            )
        
        # No user data? (shouldn't happen but...)
        if not users_data:
            module.exit_json(
                changed=False,
                msg="No user data found",
                entries=0
            )
        
        # Write to CSV - capture the data
        entries = write_csv(module, csv_path, users_data, include_headers, USER_FIELDS)
        
        # Report success
        module.exit_json(
            changed=True,
            msg="User data written successfully",
            entries=entries
        )
        
    except Exception as e:
        # User collection failed? Report it
        module.fail_json(msg=f"Failed to collect user data: {str(e)}")


if __name__ == '__main__':
    main()
