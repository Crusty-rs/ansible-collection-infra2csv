#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, yasir hamadi alsahli <crusty.rusty.engine@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: storage_csv
short_description: Collect storage and filesystem information
description:
    - Gathers disk usage and filesystem details
    - Includes mount points and storage capacity
    - Supports CSV and JSON output formats
    - Enhanced error handling for minimal environments
author:
    - yasir hamadi alsahli (@crusty.rusty.engine)
options:
    output_path:
        description:
            - Output file path for storage data
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
    include_lvm:
        description:
            - Include Logical Volume Management (LVM) details in the collected data.
            - This parameter is added as a fixture to address unsupported parameter errors.
            - Its functionality is currently a placeholder.
        required: false
        type: bool
        default: false
    mode:
        description:
            - A general purpose mode parameter.
            - This parameter is added as a fixture to address unsupported parameter errors.
            - Its specific function is not yet defined in this module version.
        required: false
        type: str
        default: 'default'
requirements:
    - Target systems must be Linux-based
    - Python 3.6+ on target systems
notes:
    - Module runs on target hosts, not controller
    - Handles missing storage tools gracefully
    - Compatible with minimal container environments
    - Version 6 with enhanced Rocky/Alma compatibility
seealso:
    - module: ansible.builtin.setup
    - module: crusty_rs.infra2csv.filesystem_health
'''

EXAMPLES = r'''
# Basic storage collection to CSV
- name: Collect storage information
  crusty_rs.infra2csv.storage_csv:
    output_path: /tmp/storage.csv

# Storage audit with custom path
- name: Storage audit to custom location
  crusty_rs.infra2csv.storage_csv:
    output_path: /opt/audit/storage_{{ ansible_date_time.date }}.csv
    include_headers: true

# Storage data to JSON format
- name: Storage snapshot
  crusty_rs.infra2csv.storage_csv:
    output_path: /tmp/storage.json

# Example with new fixture parameters
- name: Collect storage with LVM fixture and custom mode
  crusty_rs.infra2csv.storage_csv:
    output_path: /tmp/storage_full.csv
    include_lvm: true
    mode: 'detailed'

# Complete storage audit playbook
- name: Infrastructure storage audit
  hosts: all
  tasks:
    - name: Collect storage information
      crusty_rs.infra2csv.storage_csv:
        output_path: /tmp/storage_{{ inventory_hostname }}.csv
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
    sample: "Storage data written to /tmp/storage.csv"
entries:
    description: Number of data entries written
    type: int
    returned: success
    sample: 5
data:
    description: The storage data that was collected
    type: list
    returned: success
    sample:
        - hostname: "server01"
          device: "/dev/sda1"
          mount_point: "/"
          filesystem_type: "ext4"
          total_size_gb: "20.0"
          used_size_gb: "12.5"
          available_size_gb: "7.5"
          usage_percent: "63"
          timestamp: "2025-06-11T10:30:45"
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.crusty_rs.infra2csv.plugins.module_utils.infra2csv_utils import (
    run_cmd, get_hostname, get_timestamp, write_csv,
    validate_schema, read_file_safe, STORAGE_FIELDS,
    bytes_to_gb, safe_float_convert, safe_int_convert, parse_df_output
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


def get_filesystem_info(module):
    """Get filesystem information using multiple methods."""
    filesystems = []

    # Method 1: df command (preferred)
    df_output = run_cmd(module, "df -T", ignore_errors=True)
    if df_output != "N/A":
        filesystems = parse_df_output_extended(df_output)
        if filesystems:
            return filesystems

    # Method 2: df without -T flag (for older systems)
    df_output = run_cmd(module, "df", ignore_errors=True)
    if df_output != "N/A":
        filesystems = parse_df_output_basic(df_output)
        if filesystems:
            return filesystems

    # Method 3: /proc/mounts fallback
    filesystems = parse_proc_mounts(module)

    return filesystems


def parse_df_output_extended(output):
    """Parse df -T output (with filesystem type)."""
    filesystems = []

    for line in output.splitlines()[1:]:  # Skip header
        parts = line.split()
        if len(parts) >= 7:
            filesystem_data = {
                'device': parts[0],
                'filesystem_type': parts[1],
                'total_size_gb': str(bytes_to_gb(safe_int_convert(parts[2]) * 1024)),  # df shows in KB
                'used_size_gb': str(bytes_to_gb(safe_int_convert(parts[3]) * 1024)),
                'available_size_gb': str(bytes_to_gb(safe_int_convert(parts[4]) * 1024)),
                'usage_percent': parts[5].rstrip('%'),
                'mount_point': parts[6]
            }

            # Filter out special filesystems
            if not is_special_filesystem(filesystem_data['device'], filesystem_data['mount_point']):
                filesystems.append(filesystem_data)

    return filesystems


def parse_df_output_basic(output):
    """Parse basic df output (without filesystem type)."""
    filesystems = []

    for line in output.splitlines()[1:]:  # Skip header
        parts = line.split()
        if len(parts) >= 6:
            filesystem_data = {
                'device': parts[0],
                'filesystem_type': get_filesystem_type(parts[0]),
                'total_size_gb': str(bytes_to_gb(safe_int_convert(parts[1]) * 1024)),  # df shows in KB
                'used_size_gb': str(bytes_to_gb(safe_int_convert(parts[2]) * 1024)),
                'available_size_gb': str(bytes_to_gb(safe_int_convert(parts[3]) * 1024)),
                'usage_percent': parts[4].rstrip('%'),
                'mount_point': parts[5]
            }

            # Filter out special filesystems
            if not is_special_filesystem(filesystem_data['device'], filesystem_data['mount_point']):
                filesystems.append(filesystem_data)

    return filesystems


def parse_proc_mounts(module):
    """Fallback method using /proc/mounts."""
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
                # Get size info from statvfs if possible
                try:
                    import os
                    stat = os.statvfs(mount_point)
                    total_bytes = stat.f_blocks * stat.f_frsize
                    free_bytes = stat.f_bavail * stat.f_frsize
                    used_bytes = total_bytes - free_bytes

                    filesystem_data = {
                        'device': device,
                        'filesystem_type': fs_type,
                        'total_size_gb': str(bytes_to_gb(total_bytes)),
                        'used_size_gb': str(bytes_to_gb(used_bytes)),
                        'available_size_gb': str(bytes_to_gb(free_bytes)),
                        'usage_percent': str(int((used_bytes / total_bytes) * 100)) if total_bytes > 0 else '0',
                        'mount_point': mount_point
                    }
                    filesystems.append(filesystem_data)
                except Exception:
                    # If statvfs fails, create entry with N/A values
                    filesystem_data = {
                        'device': device,
                        'filesystem_type': fs_type,
                        'total_size_gb': 'N/A',
                        'used_size_gb': 'N/A',
                        'available_size_gb': 'N/A',
                        'usage_percent': 'N/A',
                        'mount_point': mount_point
                    }
                    filesystems.append(filesystem_data)

    return filesystems


def get_filesystem_type(device):
    """Get filesystem type for a device."""
    # Try to get from /proc/mounts
    mounts_content = read_file_safe('/proc/mounts', '')
    for line in mounts_content.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == device:
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


def collect_storage_data(module, include_lvm=False, mode='default'):
    """Main storage data collection."""
    hostname = get_hostname()
    timestamp = get_timestamp()

    # Get filesystem information
    filesystems = get_filesystem_info(module)

    # Build storage data
    storage_data = []

    if not filesystems:
        # No filesystems found, create a basic entry
        storage_data.append({
            'hostname': hostname,
            'device': 'N/A',
            'mount_point': 'N/A',
            'filesystem_type': 'N/A',
            'total_size_gb': 'N/A',
            'used_size_gb': 'N/A',
            'available_size_gb': 'N/A',
            'usage_percent': 'N/A',
            'timestamp': timestamp
        })
    else:
        # Process each filesystem
        for filesystem in filesystems:
            storage_entry = {
                'hostname': hostname,
                'device': filesystem['device'],
                'mount_point': filesystem['mount_point'],
                'filesystem_type': filesystem['filesystem_type'],
                'total_size_gb': filesystem['total_size_gb'],
                'used_size_gb': filesystem['used_size_gb'],
                'available_size_gb': filesystem['available_size_gb'],
                'usage_percent': filesystem['usage_percent'],
                'timestamp': timestamp
            }
            storage_data.append(storage_entry)

    # Placeholder for LVM integration if include_lvm is True
    if include_lvm:
        # In a real scenario, you would call LVM commands (e.g., 'lvs', 'vgs') here
        # and parse their output to add LVM-specific details to storage_data.
        # For now, this is a fixture to allow the parameter without errors.
        module.log(f"NOTE: 'include_lvm' is true, but LVM data collection is not yet implemented. This is a fixture.")
    if mode != 'default':
        # Similarly, if 'mode' had a specific function, you would implement it here.
        module.log(f"NOTE: 'mode' parameter '{mode}' received, but its functionality is not yet implemented. This is a fixture.")


    return storage_data


def main():
    """Main execution. Target-only storage collection."""
    module = AnsibleModule(
        argument_spec=dict(
            output_path=dict(type='str', required=True),
            include_headers=dict(type='bool', default=True),
            include_lvm=dict(type='bool', default=False), # Added support for include_lvm
            mode=dict(type='str', default='default') # Added support for mode
        ),
        supports_check_mode=True
    )

    output_path = module.params['output_path']
    include_headers = module.params['include_headers']
    include_lvm = module.params['include_lvm'] # Retrieve the new parameter
    mode = module.params['mode'] # Retrieve the new parameter

    try:
        # Collect storage data, passing the new parameters (even if they are fixtures for now)
        storage_data = collect_storage_data(module, include_lvm=include_lvm, mode=mode)

        # Validate schema
        if storage_data:
            storage_data = validate_schema(module, storage_data, STORAGE_FIELDS)

        # Check mode
        if module.check_mode:
            module.exit_json(
                changed=False,
                msg="Check mode: data not written",
                data=storage_data,
                entries=len(storage_data)
            )

        # Handle no data
        if not storage_data:
            module.exit_json(
                changed=False,
                msg="No storage data found",
                entries=0
            )

        # Write data locally
        entries = write_data_local(
            module,
            output_path,
            storage_data,
            include_headers,
            STORAGE_FIELDS
        )

        # Success
        module.exit_json(
            changed=True,
            msg=f"Storage data written to {output_path}",
            entries=entries,
            data=storage_data
        )

    except Exception as e:
        module.fail_json(msg=f"Storage collection failed: {str(e)}")


if __name__ == '__main__':
    main()

