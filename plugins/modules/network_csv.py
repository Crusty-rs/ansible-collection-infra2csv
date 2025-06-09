#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Network Facts Collection Module
Copyright (c) 2025 Yasir Hamahdi Alsahli <crusty.rusty.engine@gmail.com>

Network interface scanner. Gets MACs, speeds, states, MTUs.
Works without ip command using /sys/class/net. Adaptable AF.
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.infra2csv_utils import (
    run_cmd, get_hostname, get_run_user, get_timestamp,
    write_csv, validate_schema, read_file_safe, NIC_FIELDS
)
import os
import re

DOCUMENTATION = '''
---
module: network_csv
short_description: Collect network interface information and write to CSV
description:
    - Gathers network interface details including MAC address, state, speed, and MTU
    - Works with or without ip command using sysfs fallbacks
    - Handles physical, virtual, and container network interfaces
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
    skip_loopback:
        description: Skip loopback interface (lo)
        required: false
        type: bool
        default: false
author:
    - Yasir Hamahdi Alsahli (@crusty.rusty.engine@gmail.com)
'''

EXAMPLES = '''
# Collect all interfaces including loopback
- name: Collect network interface information
  network_csv:
    csv_path: /tmp/network_inventory.csv
    include_headers: true
    skip_loopback: false

# Skip loopback interface
- name: Collect physical interfaces only
  network_csv:
    csv_path: /var/lib/infra2csv/network.csv
    skip_loopback: true
'''


def get_interface_info_sysfs(interface):
    """
    Get interface details straight from sysfs.
    No external commands needed. Direct kernel info.
    """
    base_path = f"/sys/class/net/{interface}"
    
    info = {
        'interface': interface,
        'mac_address': 'N/A',
        'state': 'N/A',
        'speed_mbps': 'N/A',
        'mtu': 'N/A'
    }
    
    # MAC address - the unique identifier
    info['mac_address'] = read_file_safe(f"{base_path}/address", "N/A")
    if info['mac_address'] == "00:00:00:00:00:00":
        info['mac_address'] = "N/A"  # Loopback and some virtuals have zeros
    
    # Operational state (up/down/unknown)
    info['state'] = read_file_safe(f"{base_path}/operstate", "N/A")
    
    # Speed in Mbps (might not exist for all interfaces)
    speed = read_file_safe(f"{base_path}/speed", "N/A")
    if speed != "N/A" and speed.isdigit() and int(speed) >= 0:
        info['speed_mbps'] = speed
    # Note: -1 means speed unknown, we treat as N/A
    
    # MTU - Maximum Transmission Unit
    info['mtu'] = read_file_safe(f"{base_path}/mtu", "N/A")
    
    return info


def get_interfaces_from_ip_command(module):
    """
    Get interface list using ip command.
    Modern way, but not always available (containers).
    """
    interfaces = []
    
    # Run ip command with oneline output
    output = run_cmd(module, "ip -o link show", use_shell=True, ignore_errors=True)
    if output and output != "N/A":
        for line in output.splitlines():
            # Parse interface name from ip output
            # Format: "1: lo: <LOOPBACK,UP,LOWER_UP> ..."
            match = re.match(r'^\d+:\s+(\S+):', line)
            if match:
                interfaces.append(match.group(1))
    
    return interfaces


def get_interfaces_from_sysfs():
    """
    Get interfaces directly from /sys/class/net.
    Fallback when ip command missing. Always works on Linux.
    """
    interfaces = []
    
    try:
        if os.path.exists('/sys/class/net'):
            # List all network interfaces
            interfaces = [
                iface for iface in os.listdir('/sys/class/net')
                if os.path.isdir(f'/sys/class/net/{iface}')
            ]
    except Exception:
        pass  # No /sys? That's... unusual
    
    return interfaces


def get_network_info(module, skip_loopback=False):
    """
    Main network collection function.
    Tries ip command first, falls back to sysfs. Always gets the data.
    """
    nic_data = []
    timestamp = get_timestamp()
    hostname = get_hostname()
    user = get_run_user()
    skipped_count = 0
    
    # Try ip command first (the modern way)
    interfaces = get_interfaces_from_ip_command(module)
    
    # Fallback to sysfs if ip fails (the reliable way)
    if not interfaces:
        interfaces = get_interfaces_from_sysfs()
        if interfaces:
            module.warn("ip command not available, using /sys/class/net")
    
    # No interfaces at all? That's concerning
    if not interfaces:
        module.warn("No network interfaces found")
        return nic_data
    
    # Process each interface
    for interface in interfaces:
        # Skip loopback if requested
        if skip_loopback and interface == 'lo':
            continue  # lo not needed? Skipping
        
        try:
            # Get interface details from sysfs
            info = get_interface_info_sysfs(interface)
            
            # Add common fields for correlation
            info['hostname'] = hostname
            info['run_by'] = user
            info['timestamp'] = timestamp
            
            nic_data.append(info)
            
        except Exception as e:
            # Interface vanished? Happens with virtual interfaces
            module.warn(f"Failed to get info for interface {interface}: {str(e)}")
            skipped_count += 1
            
            # Still add entry with N/A values - data completeness matters
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
    
    # Report any issues
    if skipped_count > 0:
        module.warn(f"Failed to get complete info for {skipped_count} interface(s)")
    
    return nic_data


def main():
    """Main execution. Network discovery starts here."""
    # Define module parameters
    module = AnsibleModule(
        argument_spec=dict(
            csv_path=dict(type='str', required=True),
            include_headers=dict(type='bool', default=True),
            skip_loopback=dict(type='bool', default=False)
        ),
        supports_check_mode=True  # Preview mode enabled
    )
    
    # Get parameters
    csv_path = module.params['csv_path']
    include_headers = module.params['include_headers']
    skip_loopback = module.params['skip_loopback']
    
    try:
        # Linux check - this module needs /sys/class/net
        if not os.path.exists('/sys/class/net'):
            module.fail_json(msg="This module requires Linux with /sys/class/net")
        
        # Gather network interface data
        network_data = get_network_info(module, skip_loopback)
        
        # Validate schema - consistency is key
        if network_data:
            network_data = validate_schema(module, network_data, NIC_FIELDS)
        
        # Check mode - show what we'd collect
        if module.check_mode:
            module.exit_json(
                changed=False,
                msg="Check mode: data not written",
                network=network_data,
                entries=len(network_data)
            )
        
        # No interfaces found? (shouldn't happen but...)
        if not network_data:
            module.exit_json(
                changed=False,
                msg="No network interfaces found to process",
                entries=0
            )
        
        # Write to CSV - drop the data
        entries = write_csv(module, csv_path, network_data, include_headers, NIC_FIELDS)
        
        # Success report
        module.exit_json(
            changed=True,
            msg="Network data written successfully",
            entries=entries,
            network=network_data
        )
        
    except Exception as e:
        # Network scan failed? Report the issue
        module.fail_json(msg=f"Failed to collect network data: {str(e)}")


if __name__ == '__main__':
    main()
