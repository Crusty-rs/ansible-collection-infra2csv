#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Filesystem Health Collection Module - Fixed for existing utils
Copyright (c) 2025 Yasir Hamadi Alsahli <crusty.rusty.engine@gmail.com>

Target-only filesystem health monitoring. Works with existing write_csv.
Tracks fsck status and requirements. Prevents unexpected disk checks.
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.infra2csv_utils import (
    run_cmd, get_hostname, get_timestamp, write_csv,
    validate_schema, read_file_safe, FILESYSTEM_HEALTH_FIELDS
)
import os
import re
import json
from datetime import datetime
from pathlib import Path

DOCUMENTATION = '''
---
module: filesystem_health
short_description: Collect filesystem health locally
description:
    - Gathers filesystem health status and writes to target host
    - Checks fsck requirements for ext2/3/4 and XFS filesystems
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
# Filesystem health to CSV
- name: Check filesystem health
  filesystem_health:
    output_path: /tmp/fs_health.csv

# Health status to JSON
- name: Filesystem health snapshot
  filesystem_health:
    output_path: /tmp/fs_health.json
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


def get_filesystem_list(module):
    """Get real filesystems from /proc/mounts. Filters out virtual ones."""
    filesystems = []
    
    mounts_content = read_file_safe("/proc/mounts", "")
    if mounts_content:
        for line in mounts_content.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                device, mountpoint, fstype = parts[0], parts[1], parts[2]
                
                # Real filesystems only
                if (device.startswith('/dev/') and 
                    fstype not in ['devtmpfs', 'tmpfs', 'sysfs', 'proc', 'devpts']):
                    filesystems.append({
                        'device': device,
                        'mountpoint': mountpoint,
                        'fstype': fstype
                    })
    
    return filesystems


def get_ext_filesystem_info(module, device):
    """Ext2/3/4 filesystem health using tune2fs."""
    info = {
        'last_fsck': 'N/A',
        'fsck_required': 'N/A',
        'last_fsck_result': 'N/A'
    }
    
    tune2fs_output = run_cmd(module, f"tune2fs -l {device}", ignore_errors=True)
    if tune2fs_output != "N/A":
        # Last checked timestamp
        match = re.search(r'Last checked:\s+(.+)', tune2fs_output)
        if match:
            info['last_fsck'] = match.group(1)
        
        # Mount count vs max mount count
        mount_count = 0
        max_mount_count = -1
        
        match = re.search(r'Mount count:\s+(\d+)', tune2fs_output)
        if match:
            mount_count = int(match.group(1))
        
        match = re.search(r'Maximum mount count:\s+(-?\d+)', tune2fs_output)
        if match:
            max_mount_count = int(match.group(1))
        
        # Check interval
        check_interval = 0
        match = re.search(r'Check interval:\s+(\d+)', tune2fs_output)
        if match:
            check_interval = int(match.group(1))
        
        # Determine fsck requirement
        if max_mount_count > 0 and mount_count >= max_mount_count:
            info['fsck_required'] = 'yes_mount_count'
        elif check_interval > 0 and info['last_fsck'] != 'N/A':
            try:
                last_check_date = datetime.strptime(info['last_fsck'], '%c')
                days_since_check = (datetime.now() - last_check_date).days
                if days_since_check > (check_interval / 86400):
                    info['fsck_required'] = 'yes_time_interval'
                else:
                    info['fsck_required'] = 'no'
            except Exception:
                info['fsck_required'] = 'unknown'
        else:
            info['fsck_required'] = 'no'
        
        # Filesystem state
        match = re.search(r'Filesystem state:\s+(\w+)', tune2fs_output)
        if match:
            state = match.group(1)
            info['last_fsck_result'] = 'clean' if state == 'clean' else state
    
    return info


def get_xfs_filesystem_info(module, device):
    """XFS filesystem info. Self-healing, minimal fsck needs."""
    info = {
        'last_fsck': 'N/A',
        'fsck_required': 'no',  # XFS is self-healing
        'last_fsck_result': 'N/A'
    }
    
    xfs_info_output = run_cmd(module, f"xfs_info {device}", ignore_errors=True)
    if xfs_info_output != "N/A":
        info['last_fsck_result'] = 'xfs_self_healing'
    
    return info


def collect_filesystem_health(module):
    """Main filesystem health collection."""
    health_data = []
    hostname = get_hostname()
    timestamp = get_timestamp()
    
    # Get real filesystems
    filesystems = get_filesystem_list(module)
    
    for fs in filesystems:
        # Base health info
        health_info = {
            'hostname': hostname,
            'mountpoint': fs['mountpoint'],
            'filesystem_type': fs['fstype'],
            'timestamp': timestamp
        }
        
        # Filesystem-specific health checks
        if fs['fstype'] in ['ext2', 'ext3', 'ext4']:
            fs_info = get_ext_filesystem_info(module, fs['device'])
            health_info.update(fs_info)
        elif fs['fstype'] == 'xfs':
            fs_info = get_xfs_filesystem_info(module, fs['device'])
            health_info.update(fs_info)
        else:
            # Other filesystems - no specific checks
            health_info.update({
                'fsck_required': 'N/A',
                'last_fsck': 'N/A',
                'last_fsck_result': 'N/A'
            })
        
        health_data.append(health_info)
    
    # Check for /forcefsck file
    if os.path.exists('/forcefsck'):
        module.warn("/forcefsck file exists - fsck will run on next boot")
    
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
        health_data = collect_filesystem_health(module)
        
        # Validate schema
        if health_data:
            health_data = validate_schema(module, health_data, FILESYSTEM_HEALTH_FIELDS)
        
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
            FILESYSTEM_HEALTH_FIELDS
        )
        
        # Success
        module.exit_json(
            changed=True,
            msg=f"Filesystem health written to {output_path}",
            entries=entries,
            data=health_data
        )
        
    except Exception as e:
        module.fail_json(msg=f"Filesystem health collection failed: {str(e)}")


if __name__ == '__main__':
    main()
