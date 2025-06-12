#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, yasir hamadi alsahli <crusty.rusty.engine@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: filesystem_health
short_description: Collect filesystem health and performance metrics
description:
    - Gathers filesystem health information
    - Includes inode usage and performance indicators
    - Supports CSV and JSON output formats
    - Enhanced error handling for minimal environments
author:
    - yasir hamadi alsahli (@crusty.rusty.engine)
options:
    output_path:
        description: 
            - Output file path for filesystem health data
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
    - Handles missing filesystem tools gracefully
    - Compatible with minimal container environments
    - Version 6 with enhanced Rocky/Alma compatibility
seealso:
    - module: ansible.builtin.setup
    - module: crusty_rs.infra2csv.storage_csv
'''

EXAMPLES = r'''
# Basic filesystem health collection to CSV
- name: Collect filesystem health
  crusty_rs.infra2csv.filesystem_health:
    output_path: /tmp/filesystem_health.csv

# Filesystem health audit with custom path
- name: Filesystem health audit
  crusty_rs.infra2csv.filesystem_health:
    output_path: /opt/audit/fs_health_{{ ansible_date_time.date }}.csv
    include_headers: true

# Filesystem health to JSON format
- name: Filesystem health snapshot
  crusty_rs.infra2csv.filesystem_health:
    output_path: /tmp/filesystem_health.json

# Complete filesystem health audit playbook
- name: Infrastructure filesystem health audit
  hosts: all
  tasks:
    - name: Collect filesystem health
      crusty_rs.infra2csv.filesystem_health:
        output_path: /tmp/fs_health_{{ inventory_hostname }}.csv
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
    sample: "Filesystem health data written to /tmp/filesystem_health.csv"
entries:
    description: Number of data entries written
    type: int
    returned: success
    sample: 3
data:
    description: The filesystem health data that was collected
    type: list
    returned: success
    sample:
        - hostname: "server01"
          filesystem: "/dev/sda1"
          mount_point: "/"
          type: "ext4"
          total_inodes: "1310720"
          used_inodes: "98532"
          free_inodes: "1212188"
          inode_usage_percent: "8"
          timestamp: "2025-06-11T10:30:45"
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.crusty_rs.infra2csv.plugins.module_utils.infra2csv_utils import (
    run_cmd, get_hostname, get_timestamp, write_csv,
    validate_schema, read_file_safe, FILESYSTEM_FIELDS,
    safe_int_convert
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


def get_inode_info(module):
    """Get inode usage information using multiple methods."""
    filesystems = []

    # Method 1: df -i command (preferred)
    df_output = run_cmd(module, "df -i", ignore_errors=True)
    if df_output != "N/A":
        filesystems = parse_df_inode_output(df_output)
        if filesystems:
            return filesystems

    # Method 2: /proc/mounts + statvfs fallback
    filesystems = parse_proc_mounts_inodes(module)

    return filesystems


def parse_df_inode_output(output):
    """Parse df -i output for inode information."""
    filesystems = []
    
    for line in output.splitlines()[1:]:  # Skip header
        parts = line.split()
        if len(parts) >= 6:
            filesystem_data = {
                'filesystem': parts[0],
                'total_inodes': parts[1],
                'used_inodes': parts[2],
                'free_inodes': parts[3],
                'inode_usage_percent': parts[4].rstrip('%'),
                'mount_point': parts[5],
                'type': get_filesystem_type_from_mount(parts[5])
            }
            
            # Filter out special filesystems
            if not is_special_filesystem(filesystem_data['filesystem'], filesystem_data['mount_point']):
                filesystems.append(filesystem_data)

    return filesystems


def parse_proc_mounts_inodes(module):
    """Fallback method using /proc/mounts and statvfs."""
    filesystems = []
    
    mounts_content = read_file_safe('/proc/mounts', '')
    if not mounts_content:
        return filesystems

    for line in mounts_content.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            device = parts[0]
            mount_point = parts[1]
            fs_type = parts[2]
            
            # Filter out special filesystems
            if not is_special_filesystem(device, mount_point):
                try:
                    import os
                    stat = os.statvfs(mount_point)
                    total_inodes = stat.f_files
                    free_inodes = stat.f_ffree
                    used_inodes = total_inodes - free_inodes
                    usage_percent = int((used_inodes / total_inodes) * 100) if total_inodes > 0 else 0
                    
                    filesystem_data = {
                        'filesystem': device,
                        'mount_point': mount_point,
                        'type': fs_type,
                        'total_inodes': str(total_inodes),
                        'used_inodes': str(used_inodes),
                        'free_inodes': str(free_inodes),
                        'inode_usage_percent': str(usage_percent)
                    }
                    filesystems.append(filesystem_data)
                except:
                    # If statvfs fails, create entry with N/A values
                    filesystem_data = {
                        'filesystem': device,
                        'mount_point': mount_point,
                        'type': fs_type,
                        'total_inodes': 'N/A',
                        'used_inodes': 'N/A',
                        'free_inodes': 'N/A',
                        'inode_usage_percent': 'N/A'
                    }
                    filesystems.append(filesystem_data)

    return filesystems


def get_filesystem_type_from_mount(mount_point):
    """Get filesystem type for a mount point."""
    # Try to get from /proc/mounts
    mounts_content = read_file_safe('/proc/mounts', '')
    for line in mounts_content.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] == mount_point:
            return parts[2]
    
    return 'N/A'


def is_special_filesystem(device, mount_point):
    """Filter out special/virtual filesystems."""
    special_devices = [
        'tmpfs', 'devtmpfs', 'sysfs', 'proc', 'devpts', 'cgroup',
        'pstore', 'mqueue', 'hugetlbfs', 'debugfs', 'tracefs',
        'securityfs', 'fusectl', 'fuse.gvfsd-fuse'
    ]
    
    special_mount_points = [
        '/dev', '/sys', '/proc', '/run', '/tmp/systemd-private-'
    ]
    
    # Check device type
    for special_dev in special_devices:
        if device.startswith(special_dev):
            return True
    
    # Check mount point
    for special_mount in special_mount_points:
        if mount_point.startswith(special_mount):
            return True
    
    # Skip very small filesystems (likely virtual)
    if device.startswith('/dev/loop') and mount_point.startswith('/snap'):
        return True
    
    return False


def collect_filesystem_health_data(module):
    """Main filesystem health data collection."""
    hostname = get_hostname()
    timestamp = get_timestamp()

    # Get inode information
    filesystems = get_inode_info(module)

    # Build filesystem health data
    health_data = []

    if not filesystems:
        # No filesystems found, create a basic entry
        health_data.append({
            'hostname': hostname,
            'filesystem': 'N/A',
            'mount_point': 'N/A',
            'type': 'N/A',
            'total_inodes': 'N/A',
            'used_inodes': 'N/A',
            'free_inodes': 'N/A',
            'inode_usage_percent': 'N/A',
            'timestamp': timestamp
        })
    else:
        # Process each filesystem
        for filesystem in filesystems:
            health_entry = {
                'hostname': hostname,
                'filesystem': filesystem['filesystem'],
                'mount_point': filesystem['mount_point'],
                'type': filesystem['type'],
                'total_inodes': filesystem['total_inodes'],
                'used_inodes': filesystem['used_inodes'],
                'free_inodes': filesystem['free_inodes'],
                'inode_usage_percent': filesystem['inode_usage_percent'],
                'timestamp': timestamp
            }
            health_data.append(health_entry)

    return health_data


def main():
    """Main execution. Target-only filesystem health collection."""
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
        # Collect filesystem health data
        health_data = collect_filesystem_health_data(module)

        # Validate schema
        if health_data:
            health_data = validate_schema(module, health_data, FILESYSTEM_FIELDS)

        # Check mode
        if module.check_mode:
            module.exit_json(
                changed=False,
                msg="Check mode: data not written",
                data=health_data,
                entries=len(health_data)
            )

        # Handle no data
        if not health_data:
            module.exit_json(
                changed=False,
                msg="No filesystem health data found",
                entries=0
            )

        # Write data locally
        entries = write_data_local(
            module,
            output_path,
            health_data,
            include_headers,
            FILESYSTEM_FIELDS
        )

        # Success
        module.exit_json(
            changed=True,
            msg=f"Filesystem health data written to {output_path}",
            entries=entries,
            data=health_data
        )

    except Exception as e:
        module.fail_json(msg=f"Filesystem health collection failed: {str(e)}")


if __name__ == '__main__':
    main()
