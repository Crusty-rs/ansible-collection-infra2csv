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
notes:
    - Module runs on target hosts, not controller
    - Handles missing security tools gracefully
    - Compatible with minimal container environments
    - Version 6 with enhanced Rocky/Alma compatibility
seealso:
    - module: ansible.builtin.setup
    - module: crusty_rs.infra2csv.security_baseline
'''

EXAMPLES = r'''
# Basic user collection to CSV
- name: Collect user information
  crusty_rs.infra2csv.users_csv:
    output_path: /tmp/users.csv

# User audit with custom path, including system users
- name: User audit to custom location
  crusty_rs.infra2csv.users_csv:
    output_path: /opt/audit/users_{{ ansible_date_time.date }}.csv
    include_system_users: true

# User data to JSON format
- name: User snapshot
  crusty_rs.infra2csv.users_csv:
    output_path: /tmp/users.json

# Complete user audit playbook
- name: Infrastructure user audit
  hosts: all
  tasks:
    - name: Collect user information
      crusty_rs.infra2csv.users_csv:
        output_path: /tmp/users_{{ inventory_hostname }}.csv
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
    sample: 1
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
          last_login: "2025-06-11T09:00:00"
          schedule: "0 0 * * *"
          command: "/usr/bin/clean.sh"
          source_type: "cron"
          enabled: "True"
          next_run_time: "N/A"
          timestamp: "2025-06-11T10:30:45"
          is_privileged: "True"
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.crusty_rs.infra2csv.plugins.module_utils.infra2csv_utils import (
    run_cmd, get_hostname, get_timestamp, write_csv,
    validate_schema, read_file_safe, USER_FIELDS,
    # Removed the problematic import
    # debug_user_enumeration # This function does not exist in infra2csv_utils.py
)
import os
import re
import json
import pwd # For user enumeration
import grp # For group information (e.g., sudo/wheel groups)
import datetime # For last login timestamp parsing
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
    """
    Checks if a user has sudo privileges without prompting for a password.
    GUIDANCE: This runs a `sudo -l` which can be slow and might require a working sudo setup.
    Consider alternative parsing of `/etc/sudoers` or group memberships for efficiency.
    """
    # This command checks if a user can run sudo without password
    # The output is specific and might vary between systems.
    # It's better to verify this with direct parsing of sudoers files/groups if possible.
    cmd = f"sudo -l -U {username} -n 2>/dev/null | grep -q 'NOPASSWD: ALL'"
    rc, _, _ = module.run_command(cmd, check_rc=False)
    module.debug(f"DEBUG: Sudo check for '{username}' command: '{cmd}', rc: {rc}")
    return "True" if rc == 0 else "False"

def get_user_cron_jobs(module, username):
    """
    Collects cron jobs for a specific user.
    GUIDANCE: Ensure 'crontab -l' works for the user and parsing is robust.
    """
    cron_jobs = []
    # This command typically requires the user to exist and have crontab access.
    # Running 'crontab -l' as root or with sudo for another user might be restricted.
    # Ensure 'become: true' is used in the playbook if non-root crontabs are needed.
    cmd = f"crontab -l -u {username}"
    rc, stdout, stderr = module.run_command(cmd, check_rc=False)
    module.debug(f"DEBUG: Cron jobs for '{username}' stdout: '{stdout}', stderr: '{stderr}', rc: {rc}")

    if rc == 0:
        for line in stdout.splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                # Simple parsing for schedule and command, can be more complex
                match = re.match(r'^(?P<schedule>\S+\s+\S+\s+\S+\s+\S+\s+\S+)\s+(?P<command>.*)$', line)
                if match:
                    cron_jobs.append({
                        'schedule': match.group('schedule'),
                        'command': match.group('command'),
                        'source_type': 'user_cron',
                        'enabled': 'True', # Assuming all listed are enabled
                        'next_run_time': 'N/A' # Requires complex calculation
                    })
                else:
                    cron_jobs.append({
                        'schedule': 'N/A',
                        'command': line,
                        'source_type': 'user_cron',
                        'enabled': 'True',
                        'next_run_time': 'N/A'
                    })
    return cron_jobs


def get_system_cron_jobs(module):
    """
    Collects system-wide cron jobs (e.g., /etc/crontab, /etc/cron.d).
    GUIDANCE: Parsing system cron files can be complex due to varying formats.
    """
    system_cron_jobs = []
    cron_dirs = ['/etc/crontab', '/etc/cron.d', '/etc/cron.hourly', '/etc/cron.daily', '/etc/cron.weekly', '/etc/cron.monthly']

    for path in cron_dirs:
        if os.path.isdir(path):
            try:
                for filename in os.listdir(path):
                    filepath = os.path.join(path, filename)
                    if os.path.isfile(filepath) and not filename.startswith('.'):
                        content = read_file_safe(filepath, "")
                        module.debug(f"DEBUG: System cron file '{filepath}' content:\n{content[:200]}...") # Limit debug output
                        for line in content.splitlines():
                            line = line.strip()
                            if line and not line.startswith('#'):
                                # System cron often includes username
                                match = re.match(r'^(?P<schedule>\S+\s+\S+\s+\S+\s+\S+\s+\S+)\s+(?P<user>\S+)\s+(?P<command>.*)$', line)
                                if match:
                                    system_cron_jobs.append({
                                        'schedule': match.group('schedule'),
                                        'command': match.group('command'),
                                        'source_type': f'system_cron_file:{filename}',
                                        'enabled': 'True',
                                        'next_run_time': 'N/A'
                                    })
                                else: # Fallback for lines without user or other formats
                                    system_cron_jobs.append({
                                        'schedule': 'N/A',
                                        'command': line,
                                        'source_type': f'system_cron_file:{filename}',
                                        'enabled': 'True',
                                        'next_run_time': 'N/A'
                                    })
            except Exception as e:
                module.warn(f"Error reading system cron directory {path}: {str(e)}")
        elif os.path.isfile(path): # For /etc/crontab itself
            content = read_file_safe(path, "")
            module.debug(f"DEBUG: System cron file '{path}' content:\n{content[:200]}...")
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    match = re.match(r'^(?P<schedule>\S+\s+\S+\s+\S+\s+\S+\s+\S+)\s+(?P<user>\S+)\s+(?P<command>.*)$', line)
                    if match:
                        system_cron_jobs.append({
                            'schedule': match.group('schedule'),
                            'command': match.group('command'),
                            'source_type': f'system_crontab:{path}',
                            'enabled': 'True',
                            'next_run_time': 'N/A'
                        })
                    else:
                        system_cron_jobs.append({
                            'schedule': 'N/A',
                            'command': line,
                            'source_type': f'system_crontab:{path}',
                            'enabled': 'True',
                            'next_run_time': 'N/A'
                        })
    return system_cron_jobs


def get_user_last_login(module, username):
    """
    Gets the last login timestamp for a user.
    GUIDANCE: 'lastlog' output format can vary.
    """
    # This might require 'lastlog' command to be available.
    # The output format for 'lastlog' can vary, making parsing tricky.
    lastlog_output = run_cmd(module, f"lastlog -u {username}", ignore_errors=True)
    module.debug(f"DEBUG: Lastlog for '{username}': '{lastlog_output}'")

    if lastlog_output not in ("N/A", ""):
        lines = lastlog_output.splitlines()
        if len(lines) > 1: # Skip header line
            parts = lines[1].strip().split(maxsplit=3)
            # Example: "username Pts/0 192.168.1.1 Thu Dec 25 10:00:00 +0000 2024"
            # This parsing is highly dependent on lastlog output format.
            # A more robust solution might involve parsing '/var/log/wtmp' or using a different tool.
            if len(parts) >= 4:
                # Attempt to parse a common date format, then convert to ISO
                date_str = " ".join(parts[3:]) # Combines the remaining parts as date string
                try:
                    # Example format: 'Thu Dec 25 10:00:00 +0000 2024'
                    # Python's datetime.strptime might need specific format string.
                    # Or try parsing with dateutil if available (not standard on all minimal envs).
                    # For now, a simplified approach assuming a standard date output.
                    # If it's just 'Never logged in', handle that too.
                    if "Never logged in" in date_str:
                        return "Never logged in"
                    
                    # Example conversion (might need adjustment based on real output)
                    # This is a weak point if lastlog output varies
                    # dt_obj = datetime.datetime.strptime(date_str, "%a %b %d %H:%M:%S %z %Y")
                    # return dt_obj.isoformat()
                    return date_str # Return as is for now if full parsing is too complex
                except Exception as e:
                    module.warn(f"Failed to parse last login date for '{username}': {date_str} - {str(e)}")
                    return date_str # Fallback to raw string
    return "N/A"


def collect_user_data(module, include_system_users=False):
    """Main user data collection."""
    users_data = []
    hostname = get_hostname()
    timestamp = get_timestamp()

    # Iterate through all users using pwd module
    # GUIDANCE: Use `module.debug()` inside the loop to see each user being processed.
    for user_entry in pwd.getpwall():
        module.debug(f"DEBUG: Processing user: {user_entry.pw_name} (UID: {user_entry.pw_uid})")

        # Skip system users unless explicitly requested
        if user_entry.pw_uid < 1000 and not include_system_users:
            module.debug(f"DEBUG: Skipping system user: {user_entry.pw_name} (UID < 1000 and include_system_users=False)")
            continue

        username = user_entry.pw_name
        
        # Collect cron jobs for this user
        user_cron_jobs = get_user_cron_jobs(module, username)
        
        # Get last login
        last_login_time = get_user_last_login(module, username)

        # Check sudo access (This can be expensive or trigger prompts if not configured for NOPASSWD)
        is_privileged = check_sudo_access(module, username)
        
        # Create a base user info dictionary
        user_info = {
            'hostname': hostname,
            'username': username,
            'uid': str(user_entry.pw_uid),
            'gid': str(user_entry.pw_gid),
            'home_directory': user_entry.pw_dir,
            'shell': user_entry.pw_shell,
            'last_login': last_login_time,
            'timestamp': timestamp,
            'is_privileged': is_privileged,
            # Placeholder for cron job details if no jobs found
            'schedule': 'N/A',
            'command': 'N/A',
            'source_type': 'N/A',
            'enabled': 'N/A',
            'next_run_time': 'N/A'
        }

        # If user has cron jobs, append them as separate entries or merge carefully
        # For simplicity and to match a flat CSV, each cron job could be a new row,
        # or we concatenate them into a single field for the user.
        # Your USER_FIELDS expect 'schedule', 'command', 'source_type', etc. as single fields per user.
        # This means you should probably flatten the cron jobs into a single string or only take the first one.
        if user_cron_jobs:
            # Taking the first cron job for the main user row for now, or concatenate
            # This logic needs to align with how you want cron jobs represented in the CSV.
            # If you want multiple cron jobs per user, your schema and writing logic needs to handle multiple rows per user.
            first_job = user_cron_jobs[0]
            user_info['schedule'] = first_job.get('schedule', 'N/A')
            user_info['command'] = first_job.get('command', 'N/A')
            user_info['source_type'] = first_job.get('source_type', 'N/A')
            user_info['enabled'] = first_job.get('enabled', 'N/A')
            user_info['next_run_time'] = first_job.get('next_run_time', 'N/A')
            # module.debug(f"DEBUG: User '{username}' has cron jobs. Merging first one.")
        else:
            # module.debug(f"DEBUG: User '{username}' has no cron jobs.")
            pass # Keep default N/A values

        users_data.append(user_info)
        module.debug(f"DEBUG: Appended user '{username}' info: {user_info}")

    # Also collect system cron jobs and append them, if desired, as separate "userless" entries
    # This might require a different schema or a dedicated system cron report.
    # For now, it's not directly integrated into user rows.
    # system_cron_jobs = get_system_cron_jobs(module)
    # for job in system_cron_jobs:
    #     module.debug(f"DEBUG: System cron job: {job}")
    #     # Decide how to represent these if they are to be included in users_csv
    #     # They don't have a 'username' typically, so schema needs adjustment.

    module.debug(f"DEBUG: Final collected users data (count={len(users_data)}): {users_data}")
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

        # Validate schema - this will fill any missing fields with 'N/A'
        users_data = validate_schema(module, users_data, USER_FIELDS)

        # Check mode
        if module.check_mode:
            module.exit_json(
                changed=False,
                msg="Check mode: data not written",
                data=users_data,
                entries=len(users_data)
            )

        # Handle no data after schema validation (if all users filtered or nothing found)
        if not users_data:
            module.exit_json(
                changed=False,
                msg="No user data found to write (possibly all filtered or no users)",
                entries=0,
                data=[]
            )

        # Write data locally
        entries = write_data_local(
            module,
            output_path,
            users_data, # This is now a list of dictionaries
            include_headers,
            USER_FIELDS # Explicitly pass fieldnames for consistent CSV order
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

