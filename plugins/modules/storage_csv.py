#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Storage Facts Collection Module
Copyright (c) 2025 Yasir Hamadi Alsahli <crusty.rusty.engine@gmail.com>

Gets storage info two ways: filesystem usage (df) or block devices (lsblk).
Handles LVM, NFS, weird mounts. Always delivers clean data.
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.infra2csv_utils import (
    run_cmd, get_hostname, get_run_user, get_timestamp,
    write_csv, validate_schema, STORAGE_FS_FIELDS, STORAGE_DEVICE_FIELDS
)
import os
import re

DOCUMENTATION = '''
---
module: storage_csv
short_description: Collect storage information and write to CSV
description:
    - Gathers storage information in two modes: filesystem or device
    - Filesystem mode collects mounted filesystem usage
    - Device mode collects block device information
    - Handles various storage types including LVM, NFS, and virtual filesystems
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
    mode:
        description: Collection mode - filesystem or device
        required: false
        type: str
        choices: ['filesystem', 'device']
        default: filesystem
    include_lvm:
        description: Include LVM volumes in filesystem mode
        required: false
        type: bool
        default: false
author:
    - Yasir Hamadi Alsahli (@crusty.rusty.engine@gmail.com)
'''

EXAMPLES = '''
# Collect filesystem usage
- name: Collect filesystem information
  storage_csv:
    csv_path: /tmp/storage_fs.csv
    mode: filesystem
    include_headers: true

# Collect block devices
- name: Collect block device information
  storage_csv:
    csv_path: /tmp/storage_devices.csv
    mode: device
    
# Include LVM volumes
- name: Collect all filesystems including LVM
  storage_csv:
    csv_path: /tmp/storage_all.csv
    mode: filesystem
    include_lvm: true
'''


def parse_df_output(df_line):
    """
    Parse df output line. Handles wrapped lines and weird device names.
    Returns dict with all the storage stats or None if parse fails.
    """
    # df output: device fstype size used avail use% mountpoint
    parts = df_line.split()
    if len(parts) < 7:
        return None  # Incomplete line, skip it
    
    return {
        'device': parts[0],
        'type': parts[1],
        'size': parts[2],
        'used': parts[3],
        'avail': parts[4],
        'use_percent': parts[5],
        'mountpoint': parts[6]
    }


def get_filesystem_info(module, include_lvm=False):
    """
    Get mounted filesystem info using df.
    Filters out pseudo filesystems unless you really want them.
    """
    storage_data = []
    timestamp = get_timestamp()
    hostname = get_hostname()
    user = get_run_user()
    
    # Use the exact df command format requested
    df_cmd = "df -h --output=source,fstype,size,used,avail,pcent,target"
    output = run_cmd(module, df_cmd, use_shell=True, ignore_errors=True)
    
    if output and output != "N/A":
        lines = output.splitlines()
        # Skip header line
        for line in lines[1:]:
            if not line.strip():
                continue  # Empty line? Next!
            
            # Parse the df output
            fs_info = parse_df_output(line)
            if not fs_info:
                continue  # Parse failed? Moving on
            
            # Filter LVM if not requested
            if not include_lvm and fs_info['type'] in ['lvm2_member', 'device-mapper']:
                continue  # Skip LVM volumes
            
            # Filter snap mounts (Ubuntu things)
            if fs_info['type'] in ['tmpfs', 'devtmpfs', 'squashfs'] and '/snap' in fs_info['mountpoint']:
                continue  # Nobody needs snap loop mounts in their data
            
            # Build the CSV row
            storage_data.append({
                'mode': 'filesystem',
                'device': fs_info['device'],
                'type': fs_info['type'],
                'size': fs_info['size'],
                'used': fs_info['used'],
                'avail': fs_info['avail'],
                'use_percent': fs_info['use_percent'],
                'mountpoint': fs_info['mountpoint'],
                'hostname': hostname,
                'run_by': user,
                'timestamp': timestamp
            })
    
    # Fallback: Parse /proc/mounts if df fails (container scenario)
    if not storage_data and os.path.exists('/proc/mounts'):
        try:
            with open('/proc/mounts', 'r') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 3:
                        device = parts[0]
                        mountpoint = parts[1]
                        fstype = parts[2]
                        
                        # Only real filesystems
                        if device.startswith('/dev/') or device in ['tmpfs', 'none']:
                            # Get size info using statvfs
                            try:
                                stat = os.statvfs(mountpoint)
                                total = stat.f_blocks * stat.f_frsize
                                free = stat.f_available * stat.f_frsize
                                used = total - free
                                percent = int((used / total) * 100) if total > 0 else 0
                                
                                storage_data.append({
                                    'mode': 'filesystem',
                                    'device': device,
                                    'type': fstype,
                                    'size': f"{total // (1024**3)}G",  # Bytes to GB
                                    'used': f"{used // (1024**3)}G",
                                    'avail': f"{free // (1024**3)}G",
                                    'use_percent': f"{percent}%",
                                    'mountpoint': mountpoint,
                                    'hostname': hostname,
                                    'run_by': user,
                                    'timestamp': timestamp
                                })
                            except Exception:
                                pass  # Can't stat? Skip it
        except Exception:
            pass  # /proc/mounts issues? We tried
    
    return storage_data


def get_device_info(module):
    """
    Get block device info using lsblk.
    Shows physical disks, sizes, models. The hardware view.
    """
    storage_data = []
    timestamp = get_timestamp()
    hostname = get_hostname()
    user = get_run_user()
    
    # Get block devices with size in bytes
    lsblk_cmd = "lsblk -b -d -n -o NAME,SIZE,TYPE,MODEL"
    output = run_cmd(module, lsblk_cmd, use_shell=True, ignore_errors=True)
    
    if output and output != "N/A":
        for line in output.splitlines():
            if not line.strip():
                continue
            
            # Parse with regex to handle spaces in model names
            match = re.match(r'(\S+)\s+(\d+)\s+(\S+)\s*(.*)', line)
            if match:
                name, size, dtype, model = match.groups()
                storage_data.append({
                    'mode': 'device',
                    'device': f"/dev/{name}",
                    'size_bytes': size,
                    'type': dtype,
                    'model': model.strip() if model else 'N/A',
                    'hostname': hostname,
                    'run_by': user,
                    'timestamp': timestamp
                })
    
    # Fallback: Parse /sys/block if lsblk missing
    if not storage_data and os.path.exists('/sys/block'):
        try:
            for device in os.listdir('/sys/block'):
                # Skip loop and ram devices
                if device.startswith('loop') or device.startswith('ram'):
                    continue
                
                device_path = f"/dev/{device}"
                size_bytes = 'N/A'
                dtype = 'disk'
                model = 'N/A'
                
                # Get size from sysfs
                size_file = f"/sys/block/{device}/size"
                if os.path.exists(size_file):
                    try:
                        with open(size_file, 'r') as f:
                            # Size is in 512-byte sectors
                            sectors = int(f.read().strip())
                            size_bytes = str(sectors * 512)
                    except Exception:
                        pass  # Can't read size? Default to N/A
                
                # Get model from sysfs
                model_file = f"/sys/block/{device}/device/model"
                if os.path.exists(model_file):
                    try:
                        with open(model_file, 'r') as f:
                            model = f.read().strip()
                    except Exception:
                        pass  # No model info available
                
                storage_data.append({
                    'mode': 'device',
                    'device': device_path,
                    'size_bytes': size_bytes,
                    'type': dtype,
                    'model': model,
                    'hostname': hostname,
                    'run_by': user,
                    'timestamp': timestamp
                })
        except Exception:
            pass  # /sys/block issues? Containers be like that
    
    return storage_data


def main():
    """Main execution. Choose your mode: filesystem or device."""
    # Define module parameters
    module = AnsibleModule(
        argument_spec=dict(
            csv_path=dict(type='str', required=True),
            include_headers=dict(type='bool', default=True),
            mode=dict(type='str', choices=['filesystem', 'device'], default='filesystem'),
            include_lvm=dict(type='bool', default=False)
        ),
        supports_check_mode=True  # Dry runs supported
    )
    
    # Get parameters
    csv_path = module.params['csv_path']
    include_headers = module.params['include_headers']
    mode = module.params['mode']
    include_lvm = module.params['include_lvm']
    
    try:
        # Collect storage data based on mode
        if mode == 'filesystem':
            storage_data = get_filesystem_info(module, include_lvm)
            expected_fields = STORAGE_FS_FIELDS
        else:
            storage_data = get_device_info(module)
            expected_fields = STORAGE_DEVICE_FIELDS
        
        # Validate schema - keep data consistent
        if storage_data:
            storage_data = validate_schema(module, storage_data, expected_fields)
        
        # Check mode - preview without writing
        if module.check_mode:
            module.exit_json(
                changed=False,
                msg="Check mode: data not written",
                storage=storage_data,
                entries=len(storage_data),
                mode=mode
            )
        
        # Handle no data scenario
        if not storage_data:
            module.warn(f"No storage data found in {mode} mode")
            module.exit_json(
                changed=False,
                msg=f"No storage data found in {mode} mode",
                entries=0,
                mode=mode
            )
        
        # Write to CSV - the main event
        entries = write_csv(module, csv_path, storage_data, include_headers, expected_fields)
        
        # Report success
        module.exit_json(
            changed=True,
            msg=f"Storage data written successfully ({mode} mode)",
            entries=entries,
            storage=storage_data,
            mode=mode
        )
        
    except Exception as e:
        # Something broke? Be transparent
        module.fail_json(msg=f"Failed to collect storage data: {str(e)}")


if __name__ == '__main__':
    main()
