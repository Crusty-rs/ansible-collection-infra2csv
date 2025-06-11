#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, yasir hamadi alsahli <crusty.rusty.engine@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: hardware_csv
short_description: Collect hardware information from target systems
description:
    - Gathers comprehensive hardware information
    - Includes CPU, memory, and system details
    - Supports CSV and JSON output formats
    - Enhanced error handling for minimal environments
    - Version 6 with improved compatibility
version_added: "1.0.0"
author:
    - yasir hamadi alsahli (@crusty.rusty.engine)
options:
    output_path:
        description: 
            - Output file path for hardware data
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
requirements:
    - Target systems must be Linux-based
    - Python 3.6+ on target systems
notes:
    - Module runs on target hosts, not controller
    - Handles missing hardware detection tools gracefully
    - Compatible with minimal container environments
    - Version 6 with enhanced Rocky/Alma compatibility
seealso:
    - module: ansible.builtin.setup
    - module: crusty_rs.infra2csv.network_csv
'''

EXAMPLES = r'''
# Basic hardware collection to CSV
- name: Collect hardware information
  crusty_rs.infra2csv.hardware_csv:
    output_path: /tmp/hardware.csv

# Hardware audit with custom path
- name: Hardware audit to custom location
  crusty_rs.infra2csv.hardware_csv:
    output_path: /opt/audit/hardware_{{ ansible_date_time.date }}.csv
    include_headers: true

# Hardware data to JSON format
- name: Hardware snapshot
  crusty_rs.infra2csv.hardware_csv:
    output_path: /tmp/hardware.json

# Complete hardware audit playbook
- name: Infrastructure hardware audit
  hosts: all
  tasks:
    - name: Collect hardware information
      crusty_rs.infra2csv.hardware_csv:
        output_path: /tmp/hardware_{{ inventory_hostname }}.csv
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
    sample: "Hardware data written to /tmp/hardware.csv"
entries:
    description: Number of data entries written
    type: int
    returned: success
    sample: 1
data:
    description: The hardware data that was collected
    type: dict
    returned: success
    sample:
        hostname: "server01"
        cpu_cores: "8"
        cpu_model: "Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz"
        memory_total_gb: "16.0"
        memory_available_gb: "12.5"
        architecture: "x86_64"
        kernel_version: "5.4.0-74-generic"
        timestamp: "2025-06-11T10:30:45"
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.crusty_rs.infra2csv.plugins.module_utils.infra2csv_utils import (
    run_cmd, get_hostname, get_timestamp, write_csv,
    validate_schema, read_file_safe, HARDWARE_FIELDS,
    bytes_to_gb, safe_float_convert, safe_int_convert
)
import os
import re
import json
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


def get_cpu_info(module):
    """Get CPU information with multiple detection methods."""
    cpu_data = {
        'cpu_cores': 'N/A',
        'cpu_model': 'N/A'
    }

    # Method 1: /proc/cpuinfo
    cpuinfo = read_file_safe('/proc/cpuinfo', '')
    if cpuinfo:
        # Count processor entries
        processor_count = len([line for line in cpuinfo.splitlines() if line.startswith('processor')])
        if processor_count > 0:
            cpu_data['cpu_cores'] = str(processor_count)

        # Get model name
        for line in cpuinfo.splitlines():
            if line.startswith('model name'):
                model = line.split(':', 1)[1].strip()
                cpu_data['cpu_model'] = model
                break

    # Method 2: lscpu command (if available)
    lscpu_output = run_cmd(module, "lscpu", ignore_errors=True)
    if lscpu_output != "N/A":
        for line in lscpu_output.splitlines():
            if line.startswith('CPU(s):') and cpu_data['cpu_cores'] == 'N/A':
                cpu_data['cpu_cores'] = line.split(':')[1].strip()
            elif line.startswith('Model name:') and cpu_data['cpu_model'] == 'N/A':
                cpu_data['cpu_model'] = line.split(':', 1)[1].strip()

    # Method 3: nproc command for core count
    if cpu_data['cpu_cores'] == 'N/A':
        nproc_output = run_cmd(module, "nproc", ignore_errors=True)
        if nproc_output != "N/A":
            cpu_data['cpu_cores'] = nproc_output.strip()

    return cpu_data


def get_memory_info(module):
    """Get memory information with multiple detection methods."""
    memory_data = {
        'memory_total_gb': 'N/A',
        'memory_available_gb': 'N/A'
    }

    # Method 1: /proc/meminfo
    meminfo = read_file_safe('/proc/meminfo', '')
    if meminfo:
        for line in meminfo.splitlines():
            if line.startswith('MemTotal:'):
                # Convert from KB to GB
                kb_value = safe_int_convert(line.split()[1])
                memory_data['memory_total_gb'] = str(bytes_to_gb(kb_value * 1024))
            elif line.startswith('MemAvailable:'):
                # Convert from KB to GB
                kb_value = safe_int_convert(line.split()[1])
                memory_data['memory_available_gb'] = str(bytes_to_gb(kb_value * 1024))

    # Method 2: free command (if available)
    free_output = run_cmd(module, "free -b", ignore_errors=True)
    if free_output != "N/A" and memory_data['memory_total_gb'] == 'N/A':
        lines = free_output.splitlines()
        for line in lines:
            if line.startswith('Mem:'):
                parts = line.split()
                if len(parts) >= 7:
                    total_bytes = safe_int_convert(parts[1])
                    available_bytes = safe_int_convert(parts[6])  # available column
                    memory_data['memory_total_gb'] = str(bytes_to_gb(total_bytes))
                    memory_data['memory_available_gb'] = str(bytes_to_gb(available_bytes))
                break

    # Fallback: Calculate available as free + buffer + cache if available not found
    if memory_data['memory_available_gb'] == 'N/A' and memory_data['memory_total_gb'] != 'N/A':
        free_output = run_cmd(module, "free -b", ignore_errors=True)
        if free_output != "N/A":
            lines = free_output.splitlines()
            for line in lines:
                if line.startswith('Mem:'):
                    parts = line.split()
                    if len(parts) >= 4:
                        free_bytes = safe_int_convert(parts[3])
                        memory_data['memory_available_gb'] = str(bytes_to_gb(free_bytes))
                    break

    return memory_data


def get_system_info(module):
    """Get system architecture and kernel information."""
    system_data = {
        'architecture': 'N/A',
        'kernel_version': 'N/A'
    }

    # Architecture
    arch_output = run_cmd(module, "uname -m", ignore_errors=True)
    if arch_output != "N/A":
        system_data['architecture'] = arch_output.strip()

    # Kernel version
    kernel_output = run_cmd(module, "uname -r", ignore_errors=True)
    if kernel_output != "N/A":
        system_data['kernel_version'] = kernel_output.strip()

    return system_data


def collect_hardware_data(module):
    """Main hardware data collection."""
    hostname = get_hostname()
    timestamp = get_timestamp()

    # Gather hardware information
    cpu_info = get_cpu_info(module)
    memory_info = get_memory_info(module)
    system_info = get_system_info(module)

    # Build hardware data structure
    hardware_data = {
        'hostname': hostname,
        'cpu_cores': cpu_info['cpu_cores'],
        'cpu_model': cpu_info['cpu_model'],
        'memory_total_gb': memory_info['memory_total_gb'],
        'memory_available_gb': memory_info['memory_available_gb'],
        'architecture': system_info['architecture'],
        'kernel_version': system_info['kernel_version'],
        'timestamp': timestamp
    }

    return hardware_data


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

        # Validate schema
        hardware_data = validate_schema(module, hardware_data, HARDWARE_FIELDS)

        # Check mode
        if module.check_mode:
            module.exit_json(
                changed=False,
                msg="Check mode: data not written",
                data=hardware_data
            )

        # Write data locally
        entries = write_data_local(
            module,
            output_path,
            hardware_data,
            include_headers,
            HARDWARE_FIELDS
        )

        # Success
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
