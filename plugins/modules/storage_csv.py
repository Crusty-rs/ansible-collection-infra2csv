#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Storage Facts Collection Module - Fixed for existing utils
Copyright (c) 2025 Yasir Hamadi Alsahli <crusty.rusty.engine@gmail.com>

Target-only storage collection. Works with existing write_csv.
Filesystem or device mode. Bulletproof fallbacks.
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.infra2csv_utils import (
    run_cmd, get_hostname, get_run_user, get_timestamp,
    write_csv, validate_schema, STORAGE_FS_FIELDS, STORAGE_DEVICE_FIELDS
)
import os
import re
import json
from pathlib import Path

DOCUMENTATION = '''
---
module: storage_csv
short_description: Collect storage info locally
description: |
  Gathers storage information and writes to target host.
  Filesystem mode: mounted filesystem usage.
  Device mode: block device information.
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
  mode:
    description: Collection mode
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
# Filesystem usage to CSV
- name: Storage filesystem usage
  storage_csv:
    output_path: /tmp/storage_fs.csv
    mode: filesystem

# Block devices to JSON
- name: Block devices info
  storage_csv:
    output_path: /tmp/storage_devices.json
    mode: device
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


def parse_df_line(line):
    """Parse df output line. Handles various formats."""
    parts = line.split()
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


def collect_filesystem_data(module, include_lvm=False):
    """Filesystem usage collection. Multiple fallback methods."""
    storage_data = []
    timestamp = get_timestamp()
    hostname = get_hostname()
    user = get_run_user()
    
    # Primary method: df with structured output
    df_cmd = "df -h --output=source,fstype,size,used,avail,pcent,target"
    output = run_cmd(module, df_cmd, use_shell=True, ignore_errors=True)
    
    if output != "N/A":
        lines = output.splitlines()
        for line in lines[1:]:  # Skip header
            if not line.strip():
                continue
            
            fs_info = parse_df_line(line)
            if not fs_info:
                continue
            
            # Filter LVM if not requested
            if not include_lvm and fs_info['type'] in ['lvm2_member', 'device-mapper']:
                continue
            
            # Filter unwanted pseudo filesystems
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
    
    # Fallback: /proc/mounts + statvfs
    if not storage_data and os.path.exists('/proc/mounts'):
        try:
            with open('/proc/mounts', 'r') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 3:
                        device, mountpoint, fstype = parts[0], parts[1], parts[2]
                        
                        # Filter real filesystems only
                        if device.startswith('/dev/') or device in ['tmpfs']:
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


def collect_device_data(module):
    """Block device collection. Hardware-level view."""
    storage_data = []
    timestamp = get_timestamp()
    hostname = get_hostname()
    user = get_run_user()
    
    # Primary method: lsblk
    lsblk_cmd = "lsblk -b -d -n -o NAME,SIZE,TYPE,MODEL"
    output = run_cmd(module, lsblk_cmd, use_shell=True, ignore_errors=True)
    
    if output != "N/A":
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
    
    # Fallback: /sys/block
    if not storage_data and os.path.exists('/sys/block'):
        try:
            for device in os.listdir('/sys/block'):
                # Skip virtual devices
                if device.startswith(('loop', 'ram', 'sr')):
                    continue
                
                device_path = f"/dev/{device}"
                size_bytes = 'N/A'
                dtype = 'disk'
                model = 'N/A'
                
                # Get size from sysfs (in 512-byte sectors)
                size_file = f"/sys/block/{device}/size"
                if os.path.exists(size_file):
                    try:
                        with open(size_file, 'r') as f:
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
    """Main execution. Target-only storage collection."""
    module = AnsibleModule(
        argument_spec=dict(
            output_path=dict(type='str', required=True),
            include_headers=dict(type='bool', default=True),
            mode=dict(type='str', choices=['filesystem', 'device'], default='filesystem'),
            include_lvm=dict(type='bool', default=False)
        ),
        supports_check_mode=True
    )
    
    output_path = module.params['output_path']
    include_headers = module.params['include_headers']
    mode = module.params['mode']
    include_lvm = module.params['include_lvm']
    
    try:
        # Collect storage data based on mode
        if mode == 'filesystem':
            storage_data = collect_filesystem_data(module, include_lvm)
            expected_fields = STORAGE_FS_FIELDS
        else:
            storage_data = collect_device_data(module)
            expected_fields = STORAGE_DEVICE_FIELDS
        
        # Validate schema
        if storage_data:
            storage_data = validate_schema(module, storage_data, expected_fields)
        
        # Check mode
        if module.check_mode:
            module.exit_json(
                changed=False,
                msg="Check mode: data not written",
                data=storage_data,
                entries=len(storage_data),
                mode=mode
            )
        
        # Handle no data
        if not storage_data:
            module.exit_json(
                changed=False,
                msg=f"No storage data found in {mode} mode",
                entries=0,
                mode=mode
            )
        
        # Write data locally
        entries = write_data_local(
            module,
            output_path,
            storage_data,
            include_headers,
            expected_fields
        )
        
        # Success
        module.exit_json(
            changed=True,
            msg=f"Storage data written to {output_path} ({mode} mode)",
            entries=entries,
            data=storage_data,
            mode=mode
        )
        
    except Exception as e:
        module.fail_json(msg=f"Storage collection failed: {str(e)}")


if __name__ == '__main__':
    main()
