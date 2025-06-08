#!/usr/bin/python3
# -*- coding: utf-8 -*-

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
'''

EXAMPLES = '''
- name: Collect hardware information
  hardware_csv:
    csv_path: /tmp/hardware_inventory.csv
    include_headers: true
'''

RETURN = '''
changed:
    description: Whether the module made changes
    type: bool
hardware:
    description: Hardware information collected
    type: dict
'''


def get_cpu_info(module):
    """Get CPU information with multiple fallback methods"""
    cpu_info = {
        'cpu': 'N/A',
        'cpu_cores': 'N/A',
        'cpu_threads': 'N/A'
    }
    
    # Try lscpu first
    lscpu_output = run_cmd(module, "lscpu", ignore_errors=True)
    if lscpu_output and lscpu_output != "N/A":
        lines = lscpu_output.splitlines()
        for line in lines:
            if line.startswith('Model name:'):
                cpu_info['cpu'] = line.split(':', 1)[1].strip()
            elif line.startswith('Core(s) per socket:'):
                cpu_info['cpu_cores'] = line.split(':', 1)[1].strip()
            elif line.startswith('CPU(s):'):
                cpu_info['cpu_threads'] = line.split(':', 1)[1].strip()
    
    # Fallback to /proc/cpuinfo if needed
    if cpu_info['cpu'] == 'N/A':
        try:
            with open('/proc/cpuinfo', 'r') as f:
                for line in f:
                    if line.startswith('model name'):
                        cpu_info['cpu'] = line.split(':', 1)[1].strip()
                        break
        except Exception:
            pass
    
    # Fallback for CPU count
    if cpu_info['cpu_threads'] == 'N/A':
        try:
            cpu_info['cpu_threads'] = str(os.cpu_count() or 'N/A')
        except Exception:
            pass
    
    # Use platform as last resort
    if cpu_info['cpu'] == 'N/A':
        cpu_info['cpu'] = platform.processor() or 'N/A'
    
    return cpu_info


def get_memory_info(module):
    """Get memory information with fallback methods"""
    try:
        # Try using sysconf first
        ram = os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES') / (1024.**3)
        return round(ram, 2)
    except Exception:
        pass
    
    # Fallback to /proc/meminfo
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if line.startswith('MemTotal:'):
                    kb = int(line.split()[1])
                    return round(kb / (1024.**2), 2)
    except Exception:
        pass
    
    return 'N/A'


def get_disk_total(module):
    """Get total disk size across all disks"""
    try:
        output = run_cmd(module, "lsblk -b -d -n -o SIZE,TYPE", use_shell=True)
        if output and output != "N/A":
            total_bytes = 0
            for line in output.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[1] == 'disk' and parts[0].isdigit():
                    total_bytes += int(parts[0])
            return round(total_bytes / (1024**3), 2)
    except Exception:
        pass
    
    return 'N/A'


def get_system_info(module):
    """Get system information with dmidecode (optional)"""
    info = {
        'serial_number': 'N/A',
        'model': 'N/A'
    }
    
    # Only try dmidecode if available
    dmidecode_path = module.get_bin_path('dmidecode', required=False)
    if dmidecode_path:
        info['serial_number'] = run_cmd(
            module, 
            [dmidecode_path, '-s', 'system-serial-number'],
            ignore_errors=True
        )
        info['model'] = run_cmd(
            module,
            [dmidecode_path, '-s', 'system-product-name'],
            ignore_errors=True
        )
    
    return info


def get_boot_info(module):
    """Get boot time and uptime information"""
    info = {
        'uptime_sec': 'N/A',
        'boot_time': 'N/A'
    }
    
    # Get uptime
    try:
        uptime_data = read_file_safe('/proc/uptime', 'N/A')
        if uptime_data != 'N/A':
            info['uptime_sec'] = int(float(uptime_data.split()[0]))
    except Exception:
        pass
    
    # Get boot time - try multiple methods
    boot_time = run_cmd(module, "who -b", use_shell=True, ignore_errors=True)
    if boot_time and boot_time != "N/A" and 'system boot' in boot_time:
        # Extract date/time after "system boot"
        parts = boot_time.split('system boot')
        if len(parts) > 1:
            info['boot_time'] = parts[1].strip()
    
    # Alternative: uptime -s
    if info['boot_time'] == 'N/A':
        boot_time = run_cmd(module, "uptime -s", ignore_errors=True)
        if boot_time and boot_time != "N/A":
            info['boot_time'] = boot_time
    
    return info


def get_user_count(module):
    """Get logged in user count"""
    output = run_cmd(module, "who", ignore_errors=True)
    if output and output != "N/A":
        return str(len(output.splitlines()))
    return "0"


def get_hardware_data(module):
    """Main function to gather all hardware data"""
    # Basic system info
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
    
    # CPU info
    cpu_info = get_cpu_info(module)
    data.update(cpu_info)
    
    # System info (dmidecode)
    system_info = get_system_info(module)
    data.update(system_info)
    
    # Boot info
    boot_info = get_boot_info(module)
    data.update(boot_info)
    
    # Validate against expected schema
    data = validate_schema(module, data, HARDWARE_FIELDS)
    
    return data


def main():
    module = AnsibleModule(
        argument_spec=dict(
            csv_path=dict(type='str', required=True),
            include_headers=dict(type='bool', default=True)
        ),
        supports_check_mode=True
    )
    
    csv_path = module.params['csv_path']
    include_headers = module.params['include_headers']
    
    try:
        # Gather hardware data
        hardware_data = get_hardware_data(module)
        
        # Check mode - return data without writing
        if module.check_mode:
            module.exit_json(
                changed=False,
                msg="Check mode: data not written",
                hardware=hardware_data
            )
        
        # Write to CSV
        entries = write_csv(module, csv_path, hardware_data, include_headers, HARDWARE_FIELDS)
        
        module.exit_json(
            changed=True,
            msg="Hardware data written successfully",
            entries=entries,
            hardware=hardware_data
        )
        
    except Exception as e:
        module.fail_json(msg=f"Failed to collect hardware data: {str(e)}")


if __name__ == '__main__':
    main()
