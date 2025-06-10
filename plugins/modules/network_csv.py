#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Network Facts Collection Module - Fixed for existing utils
Copyright (c) 2025 Yasir Hamadi Alsahli <crusty.rusty.engine@gmail.com>

Target-only network interface collection. Works with existing write_csv.
Supports CSV and JSON output. Zero external dependencies.
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.infra2csv_utils import (
    run_cmd, get_hostname, get_run_user, get_timestamp,
    write_csv, validate_schema, read_file_safe, NIC_FIELDS
)
import os
import re
import json
from pathlib import Path

DOCUMENTATION = '''
---
module: network_csv
short_description: Collect network interface info locally
description:
    - Writes/Gathers network interface details and writes to target host (get collected back & cleaned).
    - Supports CSV and JSON output based on file extension
    - Uses sysfs fallbacks when ip command unavailable
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
    skip_loopback:
        description: Skip loopback interface (lo)
        required: false
        type: bool
        default: false
author:
    - Yasir Hamadi Alsahli (@crusty.rusty.engine@gmail.com)
'''

EXAMPLES = '''
# Collect all interfaces to CSV
- name: Network interfaces to CSV
  network_csv:
    output_path: /tmp/network.csv
    skip_loopback: false

# JSON output, skip loopback
- name: Network interfaces to JSON
  network_csv:
    output_path: /tmp/network.json
    skip_loopback: true
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


def get_interface_info_sysfs(interface):
    """Direct sysfs interface info. No external commands needed."""
    base_path = f"/sys/class/net/{interface}"
    
    info = {
        'interface': interface,
        'mac_address': 'N/A',
        'state': 'N/A',
        'speed_mbps': 'N/A',
        'mtu': 'N/A'
    }
    
    # MAC address
    mac = read_file_safe(f"{base_path}/address", "N/A")
    if mac != "N/A" and mac != "00:00:00:00:00:00":
        info['mac_address'] = mac
    
    # Operational state
    info['state'] = read_file_safe(f"{base_path}/operstate", "N/A")
    
    # Speed (may not exist for all interfaces)
    speed = read_file_safe(f"{base_path}/speed", "N/A")
    if speed != "N/A" and speed.isdigit() and int(speed) > 0:
        info['speed_mbps'] = speed
    
    # MTU
    info['mtu'] = read_file_safe(f"{base_path}/mtu", "N/A")
    
    return info


def get_interfaces_from_ip(module):
    """Get interface list using ip command."""
    interfaces = []
    
    output = run_cmd(module, "ip -o link show", use_shell=True, ignore_errors=True)
    if output != "N/A":
        for line in output.splitlines():
            match = re.match(r'^\d+:\s+(\S+):', line)
            if match:
                iface = match.group(1)
                # Remove @ suffix if present (vlan notation)
                if '@' in iface:
                    iface = iface.split('@')[0]
                interfaces.append(iface)
    
    return interfaces


def get_interfaces_from_sysfs():
    """Direct sysfs interface enumeration. Always works on Linux."""
    interfaces = []
    
    try:
        if os.path.exists('/sys/class/net'):
            interfaces = [
                iface for iface in os.listdir('/sys/class/net')
                if os.path.isdir(f'/sys/class/net/{iface}')
            ]
    except Exception:
        pass
    
    return interfaces


def collect_network_data(module, skip_loopback=False):
    """Main network data collection."""
    nic_data = []
    timestamp = get_timestamp()
    hostname = get_hostname()
    user = get_run_user()
    
    # Try ip command first, fallback to sysfs
    interfaces = get_interfaces_from_ip(module)
    if not interfaces:
        interfaces = get_interfaces_from_sysfs()
        if interfaces:
            module.warn("ip command unavailable, using sysfs")
    
    if not interfaces:
        return nic_data
    
    # Process each interface
    for interface in interfaces:
        # Skip loopback if requested
        if skip_loopback and interface == 'lo':
            continue
        
        try:
            # Get interface details
            info = get_interface_info_sysfs(interface)
            
            # Add metadata
            info.update({
                'hostname': hostname,
                'run_by': user,
                'timestamp': timestamp
            })
            
            nic_data.append(info)
            
        except Exception as e:
            # Interface issues - still add entry with N/A values
            nic_data.append({
                'interface': interface,
                'mac_address': 'N/A',
                'state': 'N/A',
                'speed_mbps': 'N/A',
                'mtu': 'N/A',
                'hostname': hostname,
                'run_by': user,
                'timestamp': timestamp
            })
    
    return nic_data


def main():
    """Main execution. Target-only network collection."""
    module = AnsibleModule(
        argument_spec=dict(
            output_path=dict(type='str', required=True),
            include_headers=dict(type='bool', default=True),
            skip_loopback=dict(type='bool', default=False)
        ),
        supports_check_mode=True
    )
    
    output_path = module.params['output_path']
    include_headers = module.params['include_headers']
    skip_loopback = module.params['skip_loopback']
    
    try:
        # Linux check
        if not os.path.exists('/sys/class/net'):
            module.fail_json(msg="Requires Linux with /sys/class/net")
        
        # Collect network data
        network_data = collect_network_data(module, skip_loopback)
        
        # Validate schema
        if network_data:
            network_data = validate_schema(module, network_data, NIC_FIELDS)
        
        # Check mode
        if module.check_mode:
            module.exit_json(
                changed=False,
                msg="Check mode: data not written",
                data=network_data,
                entries=len(network_data)
            )
        
        # Handle no data
        if not network_data:
            module.exit_json(
                changed=False,
                msg="No network interfaces found",
                entries=0
            )
        
        # Write data locally
        entries = write_data_local(
            module,
            output_path,
            network_data,
            include_headers,
            NIC_FIELDS
        )
        
        # Success
        module.exit_json(
            changed=True,
            msg=f"Network data written to {output_path}",
            entries=entries,
            data=network_data
        )
        
    except Exception as e:
        module.fail_json(msg=f"Network collection failed: {str(e)}")


if __name__ == '__main__':
    main()
