#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Filesystem Health Collection Module
Copyright (c) 2025 Yasir Hamadi Alsahli <crusty.rusty.engine@gmail.com>

Filesystem maintenance tracker. When was last fsck? Does it need one?
Prevents those "checking disk" surprises on reboot. Stay proactive.
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.infra2csv_utils import (
    run_cmd, get_hostname, get_timestamp, write_csv,
    validate_schema, read_file_safe, FILESYSTEM_HEALTH_FIELDS
)
import os
import re
from datetime import datetime, timedelta

DOCUMENTATION = '''
---
module: filesystem_health
short_description: Collect filesystem health information
description:
    - Gathers filesystem health status including fsck requirements
    - Checks last filesystem check dates and results
    - Supports ext2/3/4 and XFS filesystems
    - Helps plan maintenance windows
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
    - Yasir Hamadi Alsahli (@crusty.rusty.engine@gmail.com)
'''

EXAMPLES = '''
# Check filesystem health
- name: Collect filesystem health information
  filesystem_health:
    csv_path: /tmp/fs_health.csv
    include_headers: true

# Add to existing health log
- name: Append filesystem health data
  filesystem_health:
    csv_path: /var/lib/infra2csv/fshealth.csv
    include_headers: false
'''


def get_filesystem_list(module):
    """
    Get list of real filesystems (not virtual ones).
    We care about ext4, XFS, etc. Not tmpfs or proc.
    """
    filesystems = []
    
    # Parse /proc/mounts for mounted filesystems
    mounts_content = read_file_safe("/proc/mounts", "")
    if mounts_content:
        for line in mounts_content.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                device = parts[0]
                mountpoint = parts[1]
                fstype = parts[2]
                
                # Filter for real filesystems only
                if (device.startswith('/dev/') and 
                    fstype not in ['devtmpfs', 'tmpfs', 'sysfs', 'proc', 'devpts']):
                    filesystems.append({
                        'device': device,
                        'mountpoint': mountpoint,
                        'fstype': fstype
                    })
    
    return filesystems


def get_ext_filesystem_info(module, device):
    """
    Get ext2/3/4 filesystem health info using tune2fs.
    Shows last check, mount count, time-based checks. The full story.
    """
    info = {
        'last_fsck': 'N/A',
        'fsck_required': 'N/A',
        'last_fsck_result': 'N/A'
    }
    
    # Run tune2fs to get filesystem details
    tune2fs_output = run_cmd(
        module,
        f"tune2fs -l {device}",
        ignore_errors=True
    )
    
    if tune2fs_output and tune2fs_output != "N/A":
        # Parse last checked timestamp
        match = re.search(r'Last checked:\s+(.+)', tune2fs_output)
        if match:
            info['last_fsck'] = match.group(1)
        
        # Parse mount count vs max mount count
        mount_count = 0
        max_mount_count = -1
        
        match = re.search(r'Mount count:\s+(\d+)', tune2fs_output)
        if match:
            mount_count = int(match.group(1))
        
        match = re.search(r'Maximum mount count:\s+(-?\d+)', tune2fs_output)
        if match:
            max_mount_count = int(match.group(1))
        
        # Parse check interval (in seconds)
        check_interval = 0
        match = re.search(r'Check interval:\s+(\d+)', tune2fs_output)
        if match:
            check_interval = int(match.group(1))
        
        # Determine if fsck is required
        if max_mount_count > 0 and mount_count >= max_mount_count:
            info['fsck_required'] = 'yes_mount_count'  # Too many mounts
        elif check_interval > 0 and info['last_fsck'] != 'N/A':
            # Check if time interval exceeded
            try:
                # Parse the date (format varies by locale)
                last_check_date = datetime.strptime(info['last_fsck'], '%c')
                days_since_check = (datetime.now() - last_check_date).days
                if days_since_check > (check_interval / 86400):  # Convert seconds to days
                    info['fsck_required'] = 'yes_time_interval'  # Too much time passed
                else:
                    info['fsck_required'] = 'no'  # All good
            except Exception:
                info['fsck_required'] = 'unknown'  # Can't parse date
        else:
            info['fsck_required'] = 'no'  # No checks configured
        
        # Check filesystem state (clean or needs check)
        match = re.search(r'Filesystem state:\s+(\w+)', tune2fs_output)
        if match:
            state = match.group(1)
            if state == 'clean':
                info['last_fsck_result'] = 'clean'
            else:
                info['last_fsck_result'] = state  # Could be 'not clean', 'errors', etc.
    
    return info


def get_xfs_filesystem_info(module, device):
    """
    Get XFS filesystem info.
    XFS is self-healing, doesn't need periodic fsck. Built different.
    """
    info = {
        'last_fsck': 'N/A',
        'fsck_required': 'no',  # XFS doesn't need scheduled fsck
        'last_fsck_result': 'N/A'
    }
    
    # Try to get XFS info (limited compared to ext4)
    xfs_info_output = run_cmd(
        module,
        f"xfs_info {device}",
        ignore_errors=True
    )
    
    if xfs_info_output and xfs_info_output != "N/A":
        info['last_fsck_result'] = 'xfs_self_healing'  # XFS repairs on mount
    
    return info


def get_filesystem_health(module):
    """
    Main function to check health of all filesystems.
    Different filesystems, different health checks.
    """
    health_data = []
    hostname = get_hostname()
    timestamp = get_timestamp()
    
    # Get list of real filesystems
    filesystems = get_filesystem_list(module)
    
    for fs in filesystems:
        # Base health info
        health_info = {
            'hostname': hostname,
            'mountpoint': fs['mountpoint'],
            'filesystem_type': fs['fstype'],
            'timestamp': timestamp
        }
        
        # Get filesystem-specific health info
        if fs['fstype'] in ['ext2', 'ext3', 'ext4']:
            # Traditional ext filesystems need periodic checks
            fs_info = get_ext_filesystem_info(module, fs['device'])
            health_info.update(fs_info)
        elif fs['fstype'] == 'xfs':
            # XFS is self-maintaining
            fs_info = get_xfs_filesystem_info(module, fs['device'])
            health_info.update(fs_info)
        else:
            # Other filesystems - no specific health checks
            health_info.update({
                'fsck_required': 'N/A',
                'last_fsck': 'N/A',
                'last_fsck_result': 'N/A'
            })
        
        health_data.append(health_info)
    
    # Bonus check: /forcefsck file exists?
    forcefsck_exists = os.path.exists('/forcefsck')
    if forcefsck_exists:
        module.warn("/forcefsck file exists - fsck will run on next boot")
    
    return health_data


def main():
    """Main execution. Filesystem health check begins."""
    # Define module parameters
    module = AnsibleModule(
        argument_spec=dict(
            csv_path=dict(type='str', required=True),
            include_headers=dict(type='bool', default=True)
        ),
        supports_check_mode=True  # Support preview mode
    )
    
    # Get parameters
    csv_path = module.params['csv_path']
    include_headers = module.params['include_headers']
    
    try:
        # Gather filesystem health data
        health_data = get_filesystem_health(module)
        
        # Validate schema - keep it consistent
        if health_data:
            health_data = validate_schema(module, health_data, FILESYSTEM_HEALTH_FIELDS)
        
        # Check mode - preview only
        if module.check_mode:
            module.exit_json(
                changed=False,
                msg="Check mode: data not written",
                filesystem_health=health_data,
                entries=len(health_data)
            )
        
        # No filesystems found? (shouldn't happen)
        if not health_data:
            module.exit_json(
                changed=False,
                msg="No filesystem health data found",
                entries=0
            )
        
        # Write to CSV - document filesystem health
        entries = write_csv(module, csv_path, health_data, include_headers, FILESYSTEM_HEALTH_FIELDS)
        
        # Success report
        module.exit_json(
            changed=True,
            msg="Filesystem health data written successfully",
            entries=entries,
            filesystem_health=health_data
        )
        
    except Exception as e:
        # Health check failed? That's concerning
        module.fail_json(msg=f"Failed to collect filesystem health data: {str(e)}")


if __name__ == '__main__':
    main()
