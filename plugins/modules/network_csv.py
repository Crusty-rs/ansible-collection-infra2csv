#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, yasir hamadi alsahli <crusty.rusty.engine@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: network_csv
short_description: Collect network configuration from target systems
description:
    - Gathers network interface information
    - Includes IP addresses, routing, and DNS details
    - Supports CSV and JSON output formats
    - Enhanced error handling for minimal environments
author:
    - yasir hamadi alsahli (@crusty.rusty.engine)
options:
    output_path:
        description: 
            - Output file path for network data
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
    skip_loopback:
        description: 
            - Skip loopback interface (lo) in output
            - When false, includes loopback interface data
        required: false
        type: bool
        default: true
requirements:
    - Target systems must be Linux-based
    - Python 3.6+ on target systems
notes:
    - Module runs on target hosts, not controller
    - Handles missing network tools gracefully
    - Compatible with minimal container environments
    - Version 6 with enhanced Rocky/Alma compatibility
seealso:
    - module: ansible.builtin.setup
    - module: crusty_rs.infra2csv.hardware_csv
'''

EXAMPLES = r'''
# Basic network collection to CSV
- name: Collect network information
  crusty_rs.infra2csv.network_csv:
    output_path: /tmp/network.csv

# Network audit with custom path, including loopback
- name: Network audit to custom location
  crusty_rs.infra2csv.network_csv:
    output_path: /opt/audit/network_{{ ansible_date_time.date }}.csv
    include_headers: true
    skip_loopback: false

# Network data to JSON format
- name: Network snapshot
  crusty_rs.infra2csv.network_csv:
    output_path: /tmp/network.json
    skip_loopback: true

# Complete network audit playbook
- name: Infrastructure network audit
  hosts: all
  tasks:
    - name: Collect network information
      crusty_rs.infra2csv.network_csv:
        output_path: /tmp/network_{{ inventory_hostname }}.csv
        skip_loopback: false
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
    sample: "Network data written to /tmp/network.csv"
entries:
    description: Number of data entries written
    type: int
    returned: success
    sample: 3
data:
    description: The network data that was collected
    type: list
    returned: success
    sample:
        - hostname: "server01"
          interface: "eth0"
          ip_address: "192.168.1.100"
          network_mask: "255.255.255.0"
          gateway: "192.168.1.1"
          dns_servers: "8.8.8.8,8.8.4.4"
          mac_address: "00:16:3e:12:34:56"
          timestamp: "2025-06-11T10:30:45"
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.crusty_rs.infra2csv.plugins.module_utils.infra2csv_utils import (
    run_cmd, get_hostname, get_timestamp, write_csv,
    validate_schema, read_file_safe, NETWORK_FIELDS
)
import os
import re
import json
import ipaddress
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


def get_network_interfaces(module, skip_loopback=True):
    """Get network interface information with multiple methods."""
    interfaces = []

    # Method 1: ip command (preferred)
    ip_output = run_cmd(module, "ip addr show", ignore_errors=True)
    if ip_output != "N/A":
        interfaces = parse_ip_addr_output(ip_output, skip_loopback)
        if interfaces:
            return interfaces

    # Method 2: ifconfig command (fallback)
    ifconfig_output = run_cmd(module, "ifconfig", ignore_errors=True)
    if ifconfig_output != "N/A":
        interfaces = parse_ifconfig_output(ifconfig_output, skip_loopback)
        if interfaces:
            return interfaces

    # Method 3: /proc/net/dev + /sys/class/net (minimal fallback)
    interfaces = parse_proc_net_interfaces(module, skip_loopback)

    return interfaces


def parse_ip_addr_output(output, skip_loopback=True):
    """Parse 'ip addr show' output."""
    interfaces = []
    current_interface = None

    for line in output.splitlines():
        line = line.strip()
        
        # Interface line (e.g., "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>")
        if re.match(r'^\d+: \w+:', line):
            if current_interface:
                interfaces.append(current_interface)
            
            match = re.match(r'^\d+: (\w+):', line)
            if match:
                interface_name = match.group(1)
                # Skip loopback if requested
                if skip_loopback and interface_name == 'lo':
                    current_interface = None
                else:
                    current_interface = {
                        'interface': interface_name,
                        'ip_address': 'N/A',
                        'network_mask': 'N/A',
                        'mac_address': 'N/A'
                    }

        # MAC address line
        elif line.startswith('link/ether') and current_interface:
            parts = line.split()
            if len(parts) >= 2:
                current_interface['mac_address'] = parts[1]

        # IP address line
        elif line.startswith('inet ') and current_interface:
            parts = line.split()
            if len(parts) >= 2:
                ip_cidr = parts[1]
                try:
                    network = ipaddress.ip_network(ip_cidr, strict=False)
                    current_interface['ip_address'] = str(network.network_address)
                    current_interface['network_mask'] = str(network.netmask)
                except:
                    # Fallback parsing
                    if '/' in ip_cidr:
                        ip, cidr = ip_cidr.split('/')
                        current_interface['ip_address'] = ip
                        try:
                            # Convert CIDR to netmask
                            mask = ipaddress.IPv4Network(f'0.0.0.0/{cidr}').netmask
                            current_interface['network_mask'] = str(mask)
                        except:
                            current_interface['network_mask'] = f'/{cidr}'

    # Add the last interface
    if current_interface:
        interfaces.append(current_interface)

    return interfaces


def parse_ifconfig_output(output, skip_loopback=True):
    """Parse ifconfig output."""
    interfaces = []
    current_interface = None

    for line in output.splitlines():
        # Interface line (e.g., "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>")
        if not line.startswith(' ') and ':' in line:
            if current_interface:
                interfaces.append(current_interface)
            
            interface_name = line.split(':')[0].strip()
            # Skip loopback if requested
            if skip_loopback and interface_name == 'lo':
                current_interface = None
            else:
                current_interface = {
                    'interface': interface_name,
                    'ip_address': 'N/A',
                    'network_mask': 'N/A',
                    'mac_address': 'N/A'
                }

        # IP address line
        elif 'inet ' in line and current_interface:
            match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
            if match:
                current_interface['ip_address'] = match.group(1)
            
            # Netmask
            match = re.search(r'netmask (\d+\.\d+\.\d+\.\d+)', line)
            if match:
                current_interface['network_mask'] = match.group(1)

        # MAC address line
        elif 'ether ' in line and current_interface:
            match = re.search(r'ether ([a-fA-F0-9:]{17})', line)
            if match:
                current_interface['mac_address'] = match.group(1)

    # Add the last interface
    if current_interface:
        interfaces.append(current_interface)

    return interfaces


def parse_proc_net_interfaces(module, skip_loopback=True):
    """Fallback method using /proc/net/dev and /sys/class/net."""
    interfaces = []

    # Read interface names from /proc/net/dev
    proc_net_dev = read_file_safe('/proc/net/dev', '')
    if not proc_net_dev:
        return interfaces

    for line in proc_net_dev.splitlines()[2:]:  # Skip header lines
        interface_name = line.split(':')[0].strip()
        if interface_name:
            # Skip loopback if requested
            if skip_loopback and interface_name == 'lo':
                continue
            
            interface_data = {
                'interface': interface_name,
                'ip_address': 'N/A',
                'network_mask': 'N/A',
                'mac_address': 'N/A'
            }

            # Try to get MAC address from /sys/class/net
            mac_path = f'/sys/class/net/{interface_name}/address'
            mac_address = read_file_safe(mac_path, '').strip()
            if mac_address:
                interface_data['mac_address'] = mac_address

            interfaces.append(interface_data)

    return interfaces


def get_gateway_info(module):
    """Get default gateway information."""
    # Method 1: ip route command
    route_output = run_cmd(module, "ip route show default", ignore_errors=True)
    if route_output != "N/A":
        match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', route_output)
        if match:
            return match.group(1)

    # Method 2: route command
    route_output = run_cmd(module, "route -n", ignore_errors=True)
    if route_output != "N/A":
        for line in route_output.splitlines():
            if line.startswith('0.0.0.0'):
                parts = line.split()
                if len(parts) >= 2:
                    return parts[1]

    # Method 3: netstat command
    netstat_output = run_cmd(module, "netstat -rn", ignore_errors=True)
    if netstat_output != "N/A":
        for line in netstat_output.splitlines():
            if line.startswith('0.0.0.0') or line.startswith('default'):
                parts = line.split()
                if len(parts) >= 2:
                    return parts[1]

    return 'N/A'


def get_dns_servers(module):
    """Get DNS server information."""
    dns_servers = []

    # Method 1: /etc/resolv.conf
    resolv_conf = read_file_safe('/etc/resolv.conf', '')
    if resolv_conf:
        for line in resolv_conf.splitlines():
            if line.strip().startswith('nameserver'):
                parts = line.split()
                if len(parts) >= 2:
                    dns_servers.append(parts[1])

    # Method 2: systemd-resolve (if available)
    if not dns_servers:
        resolve_output = run_cmd(module, "systemd-resolve --status", ignore_errors=True)
        if resolve_output != "N/A":
            for line in resolve_output.splitlines():
                if 'DNS Servers:' in line:
                    dns_part = line.split(':', 1)[1].strip()
                    if dns_part:
                        dns_servers.append(dns_part)

    return ','.join(dns_servers) if dns_servers else 'N/A'


def collect_network_data(module, skip_loopback=True):
    """Main network data collection."""
    hostname = get_hostname()
    timestamp = get_timestamp()

    # Get network interfaces
    interfaces = get_network_interfaces(module, skip_loopback)
    
    # Get gateway and DNS (same for all interfaces)
    gateway = get_gateway_info(module)
    dns_servers = get_dns_servers(module)

    # Build network data
    network_data = []

    if not interfaces:
        # No interfaces found, create a basic entry
        network_data.append({
            'hostname': hostname,
            'interface': 'N/A',
            'ip_address': 'N/A',
            'network_mask': 'N/A',
            'gateway': gateway,
            'dns_servers': dns_servers,
            'mac_address': 'N/A',
            'timestamp': timestamp
        })
    else:
        # Process each interface
        for interface in interfaces:
            network_entry = {
                'hostname': hostname,
                'interface': interface['interface'],
                'ip_address': interface['ip_address'],
                'network_mask': interface['network_mask'],
                'gateway': gateway,
                'dns_servers': dns_servers,
                'mac_address': interface['mac_address'],
                'timestamp': timestamp
            }
            network_data.append(network_entry)

    return network_data


def main():
    """Main execution. Target-only network collection."""
    module = AnsibleModule(
        argument_spec=dict(
            output_path=dict(type='str', required=True),
            include_headers=dict(type='bool', default=True),
            skip_loopback=dict(type='bool', default=True)
        ),
        supports_check_mode=True
    )

    output_path = module.params['output_path']
    include_headers = module.params['include_headers']
    skip_loopback = module.params['skip_loopback']

    try:
        # Collect network data
        network_data = collect_network_data(module, skip_loopback)

        # Validate schema
        if network_data:
            network_data = validate_schema(module, network_data, NETWORK_FIELDS)

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
                msg="No network data found",
                entries=0
            )

        # Write data locally
        entries = write_data_local(
            module,
            output_path,
            network_data,
            include_headers,
            NETWORK_FIELDS
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
