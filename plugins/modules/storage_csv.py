#!/usr/bin/python3
# -*- coding: utf-8 -*-

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
'''

EXAMPLES = '''
- name: Collect filesystem information
  storage_csv:
    csv_path: /tmp/storage_fs.csv
    mode: filesystem
    include_headers: true

- name: Collect block device information
  storage_csv:
    csv_path: /tmp/storage_devices.csv
    mode: device
'''


def parse_df_output(df_line):
    """Parse a line of df output safely"""
    # Handle long device names that wrap to next line
    parts = df_line.split()
    if len(parts) < 7:
        return None
    
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
    """Get filesystem information with fallback methods"""
    storage_data = []
    timestamp = get_timestamp()
    hostname = get_hostname()
    user = get_run_user()
    
    # Try df first
    df_cmd = "df -h --output=source,fstype,size,used,avail,pcent,target"
    output = run_cmd(module, df_cmd, use_shell=True, ignore_errors=True)
    
    if output and output != "N/A":
        lines = output.splitlines()
        # Skip header
        for line in lines[1:]:
            if not line.strip():
                continue
            
            fs_info = parse_df_output(line)
            if not fs_info:
                continue
            
            # Skip LVM if not requested
            if not include_lvm and fs_info['type'] in ['lvm2_member', 'device-mapper']:
                continue
            
            # Skip pseudo filesystems
            if fs_info['type'] in ['tmpfs', 'devtmpfs', 'squashfs'] and '/snap' in fs_info['mountpoint']:
                continue
            
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
    
    # Fallback: parse /proc/mounts if df fails
    if not storage_data and os.path.exists('/proc/mounts'):
        try:
            with open('/proc/mounts', 'r') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 3:
                        device = parts[0]
                        mountpoint = parts[1]
                        fstype = parts[2]
                        
                        # Skip virtual filesystems
                        if device.startswith('/dev/') or device in ['tmpfs', 'none']:
                            # Try to get size info from statfs
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
                                    'size': f"{total // (1024**3)}G",
                                    'used': f"{used // (1024**3)}G",
                                    'avail': f"{free // (1024**3)}G",
                                    'use_percent': f"{percent}%",
                                    'mountpoint': mountpoint,
                                    'hostname': hostname,
                                    'run_by': user,
                                    'timestamp': timestamp
                                })
                            except Exception:
                                pass
        except Exception:
            pass
    
    return storage_data


def get_device_info(module):
    """Get block device information with fallback methods"""
    storage_data = []
    timestamp = get_timestamp()
    hostname = get_hostname()
    user = get_run_user()
    
    # Try lsblk first
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
    
    # Fallback: parse /sys/block
    if not storage_data and os.path.exists('/sys/block'):
        try:
            for device in os.listdir('/sys/block'):
                if device.startswith('loop') or device.startswith('ram'):
                    continue
                
                device_path = f"/dev/{device}"
                size_bytes = 'N/A'
                dtype = 'disk'
                model = 'N/A'
                
                # Get size
                size_file = f"/sys/block/{device}/size"
                if os.path.exists(size_file):
                    try:
                        with open(size_file, 'r') as f:
                            # Size is in 512-byte sectors
                            sectors = int(f.read().strip())
                            size_bytes = str(sectors * 512)
                    except Exception:
                        pass
                
                # Get model
                model_file = f"/sys/block/{device}/device/model"
                if os.path.exists(model_file):
                    try:
                        with open(model_file, 'r') as f:
                            model = f.read().strip()
                    except Exception:
                        pass
                
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
            pass
    
    return storage_data


def main():
    module = AnsibleModule(
        argument_spec=dict(
            csv_path=dict(type='str', required=True),
            include_headers=dict(type='bool', default=True),
            mode=dict(type='str', choices=['filesystem', 'device'], default='filesystem'),
            include_lvm=dict(type='bool', default=False)
        ),
        supports_check_mode=True
    )
    
    csv_path = module.params['csv_path']
    include_headers = module.params['include_headers']
    mode = module.params['mode']
    include_lvm = module.params['include_lvm']
    
    try:
        # Gather storage data based on mode
        if mode == 'filesystem':
            storage_data = get_filesystem_info(module, include_lvm)
            expected_fields = STORAGE_FS_FIELDS
        else:
            storage_data = get_device_info(module)
            expected_fields = STORAGE_DEVICE_FIELDS
        
        # Validate schema
        if storage_data:
            storage_data = validate_schema(module, storage_data, expected_fields)
        
        # Check mode - return data without writing
        if module.check_mode:
            module.exit_json(
                changed=False,
                msg="Check mode: data not written",
                storage=storage_data,
                entries=len(storage_data),
                mode=mode
            )
        
        # Handle no data found
        if not storage_data:
            module.warn(f"No storage data found in {mode} mode")
            module.exit_json(
                changed=False,
                msg=f"No storage data found in {mode} mode",
                entries=0,
                mode=mode
            )
        
        # Write to CSV
        entries = write_csv(module, csv_path, storage_data, include_headers, expected_fields)
        
        module.exit_json(
            changed=True,
            msg=f"Storage data written successfully ({mode} mode)",
            entries=entries,
            storage=storage_data,
            mode=mode
        )
        
    except Exception as e:
        module.fail_json(msg=f"Failed to collect storage data: {str(e)}")


if __name__ == '__main__':
    main()
