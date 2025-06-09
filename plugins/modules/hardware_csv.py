#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Hardware Facts Collection Module
Copyright (c) 2025 Yasir Hamadi Alsahli <crusty.rusty.engine@gmail.com>

Grabs all the hardware specs. CPU, RAM, disks - the whole setup.
Works everywhere: bare metal, VMs, containers. No cap.
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.infra2csv_utils import (
    run_cmd, get_hostname, get_ip_address, get_run_user, get_timestamp,
    write_csv, validate_schema, read_file_safe, HARDWARE_FIELDS
)
import platform
import os

DOCUMENTATION = '''
---
module: hardware_csv
short_description: Collect hardware information and write to CSV
description:
    - Gathers system hardware information including CPU, memory, disk, and system details
    - Appends data to a CSV file for inventory tracking
    - Works on physical, virtual, and containerized systems
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
requirements:
    - Linux operating system
    - Commands: lscpu, dmidecode (optional), who, lsblk
author:
    - Yasir Hamadi Alsahli (@crusty.rusty.engine@gmail.com)
'''

EXAMPLES = '''
# Basic hardware collection
- name: Collect hardware information
  hardware_csv:
    csv_path: /tmp/hardware_inventory.csv
    include_headers: true

# Without headers (appending to existing file)
- name: Append hardware data
  hardware_csv:
    csv_path: /var/lib/infra2csv/hardware.csv
    include_headers: false
'''

RETURN = '''
changed:
    description: Whether the module made changes
    type: bool
hardware:
    description: Hardware information collected
    type: dict
    sample: {
        "hostname": "web-server-01",
        "cpu": "Intel Xeon E5-2680",
        "ram_gb": 64.0
    }
entries:
    description: Number of CSV rows written
    type: int
    sample: 1
'''


def get_cpu_info(module):
    """
    Get CPU specs with multiple fallbacks.
    Tries: lscpu → /proc/cpuinfo → os.cpu_count() → platform
    Never gives up. Always returns something.
    """
    cpu_info = {
        'cpu': 'N/A',
        'cpu_cores': 'N/A', 
        'cpu_threads': 'N/A'
    }
    
    # Method 1: lscpu (the preferred way)
    lscpu_output = run_cmd(module, "lscpu", ignore_errors=True)
    if lscpu_output and lscpu_output != "N/A":
        # Parse that output like a boss
        lines = lscpu_output.splitlines()
        for line in lines:
            if line.startswith('Model name:'):
                cpu_info['cpu'] = line.split(':', 1)[1].strip()
            elif line.startswith('Core(s) per socket:'):
                cpu_info['cpu_cores'] = line.split(':', 1)[1].strip()
            elif line.startswith('CPU(s):'):
                cpu_info['cpu_threads'] = line.split(':', 1)[1].strip()
    
    # Method 2: /proc/cpuinfo fallback (old school)
    if cpu_info['cpu'] == 'N/A':
        try:
            with open('/proc/cpuinfo', 'r') as f:
                for line in f:
                    if line.startswith('model name'):
                        cpu_info['cpu'] = line.split(':', 1)[1].strip()
                        break
        except Exception:
            pass  # /proc not available? Moving on...
    
    # Method 3: Python's os module (container friendly)
    if cpu_info['cpu_threads'] == 'N/A':
        try:
            cpu_info['cpu_threads'] = str(os.cpu_count() or 'N/A')
        except Exception:
            pass  # Even this failed? Rough
    
    # Method 4: Platform module (last resort)
    if cpu_info['cpu'] == 'N/A':
        cpu_info['cpu'] = platform.processor() or 'N/A'
    
    return cpu_info


def get_memory_info(module):
    """
    Get RAM size. Tries sysconf first, then /proc/meminfo.
    Returns GB rounded to 2 decimals. Clean numbers only.
    """
    try:
        # Method 1: sysconf (the fast way)
        ram = os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES') / (1024.**3)
        return round(ram, 2)
    except Exception:
        pass  # No sysconf? Let's check /proc
    
    # Method 2: /proc/meminfo (the reliable way)
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if line.startswith('MemTotal:'):
                    kb = int(line.split()[1])
                    return round(kb / (1024.**2), 2)  # KB to GB
    except Exception:
        pass  # No /proc either? That's tough
    
    return 'N/A'  # Memory info unavailable (container things)


def get_disk_total(module):
    """
    Calculate total disk size across all physical disks.
    Uses lsblk to get the real picture. VMs might show virtual sizes.
    """
    try:
        # Get all block devices in bytes
        output = run_cmd(module, "lsblk -b -d -n -o SIZE,TYPE", use_shell=True)
        if output and output != "N/A":
            total_bytes = 0
            for line in output.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[1] == 'disk' and parts[0].isdigit():
                    total_bytes += int(parts[0])
            return round(total_bytes / (1024**3), 2)  # Bytes to GB
    except Exception:
        pass  # lsblk issues? It happens
    
    return 'N/A'  # Disk info not available


def get_system_info(module):
    """
    Get hardware model and serial number.
    Needs dmidecode (requires root). VMs/containers might return generic info.
    """
    info = {
        'serial_number': 'N/A',
        'model': 'N/A'
    }
    
    # Check if dmidecode exists (might not in containers)
    dmidecode_path = module.get_bin_path('dmidecode', required=False)
    if dmidecode_path:
        # Get serial number (might be VMware/QEMU string)
        info['serial_number'] = run_cmd(
            module, 
            [dmidecode_path, '-s', 'system-serial-number'],
            ignore_errors=True
        )
        # Get model/product name
        info['model'] = run_cmd(
            module,
            [dmidecode_path, '-s', 'system-product-name'],
            ignore_errors=True
        )
    
    return info


def get_boot_info(module):
    """
    Get uptime and boot time.
    Multiple methods because different distros do different things.
    """
    info = {
        'uptime_sec': 'N/A',
        'boot_time': 'N/A'
    }
    
    # Get uptime in seconds (should always work)
    try:
        uptime_data = read_file_safe('/proc/uptime', 'N/A')
        if uptime_data != 'N/A':
            info['uptime_sec'] = int(float(uptime_data.split()[0]))
    except Exception:
        pass  # No /proc/uptime? Weird flex but ok
    
    # Get boot time - try multiple methods
    # Method 1: who -b (traditional)
    boot_time = run_cmd(module, "who -b", use_shell=True, ignore_errors=True)
    if boot_time and boot_time != "N/A" and 'system boot' in boot_time:
        # Extract the timestamp after "system boot"
        parts = boot_time.split('system boot')
        if len(parts) > 1:
            info['boot_time'] = parts[1].strip()
    
    # Method 2: uptime -s (modern systems)
    if info['boot_time'] == 'N/A':
        boot_time = run_cmd(module, "uptime -s", ignore_errors=True)
        if boot_time and boot_time != "N/A":
            info['boot_time'] = boot_time
    
    return info


def get_user_count(module):
    """Count logged-in users. Security needs this info."""
    output = run_cmd(module, "who", ignore_errors=True)
    if output and output != "N/A":
        return str(len(output.splitlines()))
    return "0"  # No users or 'who' command missing


def get_hardware_data(module):
    """
    Main function that orchestrates all hardware data collection.
    Combines all the helper functions into one clean dataset.
    """
    # Start with basic system info
    data = {
        'hostname': get_hostname(),
        'ip': get_ip_address(),
        'os': platform.system(),
        'os_version': platform.version(),
        'arch': platform.machine(),
        'ram_gb': get_memory_info(module),
        'disk_total_gb': get_disk_total(module),
        'user_count': get_user_count(module),
        'run_by': get_run_user(),
        'timestamp': get_timestamp()
    }
    
    # Add CPU information
    cpu_info = get_cpu_info(module)
    data.update(cpu_info)
    
    # Add system/hardware info (model, serial)
    system_info = get_system_info(module)
    data.update(system_info)
    
    # Add boot/uptime info
    boot_info = get_boot_info(module)
    data.update(boot_info)
    
    # Validate against schema - keep it clean
    data = validate_schema(module, data, HARDWARE_FIELDS)
    
    return data


def main():
    """Main execution. Where the magic happens."""
    # Define module parameters
    module = AnsibleModule(
        argument_spec=dict(
            csv_path=dict(type='str', required=True),
            include_headers=dict(type='bool', default=True)
        ),
        supports_check_mode=True  # We support dry runs
    )
    
    # Get parameters
    csv_path = module.params['csv_path']
    include_headers = module.params['include_headers']
    
    try:
        # Collect all hardware data
        hardware_data = get_hardware_data(module)
        
        # Check mode - show what we'd do without doing it
        if module.check_mode:
            module.exit_json(
                changed=False,
                msg="Check mode: data not written",
                hardware=hardware_data
            )
        
        # Write to CSV (the main event)
        entries = write_csv(module, csv_path, hardware_data, include_headers, HARDWARE_FIELDS)
        
        # Success! Report back
        module.exit_json(
            changed=True,
            msg="Hardware data written successfully",
            entries=entries,
            hardware=hardware_data
        )
        
    except Exception as e:
        # Something went wrong? Be honest about it
        module.fail_json(msg=f"Failed to collect hardware data: {str(e)}")

if __name__ == '__main__':
    main()
