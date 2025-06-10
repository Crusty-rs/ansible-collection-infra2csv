#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Hardware Facts Collection Module - Fixed for existing utils
Copyright (c) 2025 Yasir Hamadi Alsahli <crusty.rusty.engine@gmail.com>

Target-only hardware collection. Works with existing write_csv function.
Supports CSV and JSON output. Zero controller dependencies.
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.infra2csv_utils import (
    run_cmd, get_hostname, get_ip_address, get_run_user, get_timestamp,
    write_csv, validate_schema, read_file_safe, get_bin_path_safe, HARDWARE_FIELDS
)
import platform
import os
import json
from pathlib import Path

DOCUMENTATION = '''
---
module: hardware_csv
short_description: Collect hardware info and write locally
description: |
  Gathers system hardware information and writes directly to target host.
  Supports CSV and JSON output based on file extension.
  Works on physical, virtual, and containerized systems.
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
requirements:
  - Linux operating system
author:
  - Yasir Hamadi Alsahli (@crusty.rusty.engine@gmail.com)
'''

EXAMPLES = '''
# CSV output with headers
- name: Collect hardware to CSV
  hardware_csv:
    output_path: /tmp/hardware.csv
    include_headers: true

# JSON output (full data dump)
- name: Collect hardware to JSON  
  hardware_csv:
    output_path: /tmp/hardware.json
'''


def write_data_local(module, path, data, include_headers=True, fieldnames=None):
    """
    Local data writer. Handles both CSV and JSON based on extension.
    Uses existing write_csv function for CSV, adds JSON support.
    """
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


def get_cpu_info(module):
    """Multi-method CPU detection. Never fails."""
    cpu_info = {
        'cpu': 'N/A',
        'cpu_cores': 'N/A', 
        'cpu_threads': 'N/A'
    }
    
    # Method 1: lscpu (preferred)
    lscpu_output = run_cmd(module, "lscpu", ignore_errors=True)
    if lscpu_output != "N/A":
        for line in lscpu_output.splitlines():
            if line.startswith('Model name:'):
                cpu_info['cpu'] = line.split(':', 1)[1].strip()
            elif line.startswith('Core(s) per socket:'):
                try:
                    cores_per_socket = int(line.split(':', 1)[1].strip())
                    # Get socket count
                    for sub_line in lscpu_output.splitlines():
                        if sub_line.startswith('Socket(s):'):
                            sockets = int(sub_line.split(':', 1)[1].strip())
                            cpu_info['cpu_cores'] = str(cores_per_socket * sockets)
                            break
                    else:
                        cpu_info['cpu_cores'] = str(cores_per_socket)
                except (ValueError, IndexError):
                    pass
            elif line.startswith('CPU(s):'):
                cpu_info['cpu_threads'] = line.split(':', 1)[1].strip()
    
    # Method 2: /proc/cpuinfo fallback
    if cpu_info['cpu'] == 'N/A':
        cpuinfo = read_file_safe('/proc/cpuinfo', '')
        if cpuinfo:
            for line in cpuinfo.splitlines():
                if line.startswith('model name'):
                    cpu_info['cpu'] = line.split(':', 1)[1].strip()
                    break
    
    # Method 3: Python fallbacks
    if cpu_info['cpu_threads'] == 'N/A':
        try:
            cpu_info['cpu_threads'] = str(os.cpu_count() or 'N/A')
        except Exception:
            pass
    
    if cpu_info['cpu'] == 'N/A':
        cpu_info['cpu'] = platform.processor() or 'N/A'
    
    return cpu_info


def get_memory_info(module):
    """RAM detection with multiple methods."""
    # Method 1: sysconf (fastest)
    try:
        ram = os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES') / (1024.**3)
        return round(ram, 2)
    except Exception:
        pass
    
    # Method 2: /proc/meminfo (reliable)
    meminfo = read_file_safe('/proc/meminfo', '')
    if meminfo:
        for line in meminfo.splitlines():
            if line.startswith('MemTotal:'):
                try:
                    kb = int(line.split()[1])
                    return round(kb / (1024.**2), 2)  # KB to GB
                except (ValueError, IndexError):
                    pass
    
    return 'N/A'


def get_disk_total(module):
    """Total disk size across all physical devices."""
    try:
        output = run_cmd(module, "lsblk -b -d -n -o SIZE,TYPE", use_shell=True)
        if output != "N/A":
            total_bytes = 0
            for line in output.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[1] == 'disk' and parts[0].isdigit():
                    total_bytes += int(parts[0])
            if total_bytes > 0:
                return round(total_bytes / (1024**3), 2)
    except Exception:
        pass
    
    return 'N/A'


def get_system_info(module):
    """Hardware model and serial. Handles VMs gracefully."""
    info = {
        'serial_number': 'N/A',
        'model': 'N/A'
    }
    
    dmidecode_path = get_bin_path_safe(module, 'dmidecode', required=False)
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
    """Uptime and boot time. Multiple detection methods."""
    info = {
        'uptime_sec': 'N/A',
        'boot_time': 'N/A'
    }
    
    # Get uptime in seconds
    uptime_data = read_file_safe('/proc/uptime', '')
    if uptime_data:
        try:
            info['uptime_sec'] = int(float(uptime_data.split()[0]))
        except (ValueError, IndexError):
            pass
    
    # Get boot time - try multiple methods
    boot_time = run_cmd(module, "who -b", use_shell=True, ignore_errors=True)
    if boot_time != "N/A" and 'system boot' in boot_time:
        parts = boot_time.split('system boot')
        if len(parts) > 1:
            info['boot_time'] = parts[1].strip()
    
    if info['boot_time'] == 'N/A':
        boot_time = run_cmd(module, "uptime -s", ignore_errors=True)
        if boot_time != "N/A":
            info['boot_time'] = boot_time
    
    return info


def get_user_count(module):
    """Count active users."""
    output = run_cmd(module, "who", ignore_errors=True)
    if output != "N/A":
        return str(len(output.splitlines()))
    return "0"


def collect_hardware_data(module):
    """Main data collection orchestrator."""
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
    
    # Add CPU info
    data.update(get_cpu_info(module))
    
    # Add system info  
    data.update(get_system_info(module))
    
    # Add boot info
    data.update(get_boot_info(module))
    
    # Validate against schema
    return validate_schema(module, data, HARDWARE_FIELDS)


def main():
    """Main execution. Target-only hardware collection."""
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
        # Collect hardware data
        hardware_data = collect_hardware_data(module)
        
        # Check mode - preview only
        if module.check_mode:
            module.exit_json(
                changed=False,
                msg="Check mode: data not written",
                data=hardware_data,
                output_path=output_path
            )
        
        # Write data locally (CSV or JSON based on extension)
        entries = write_data_local(
            module, 
            output_path, 
            hardware_data, 
            include_headers, 
            HARDWARE_FIELDS
        )
        
        # Success response
        module.exit_json(
            changed=True,
            msg=f"Hardware data written to {output_path}",
            entries=entries,
            data=hardware_data
        )
        
    except Exception as e:
        module.fail_json(msg=f"Hardware collection failed: {str(e)}")


if __name__ == '__main__':
    main()
