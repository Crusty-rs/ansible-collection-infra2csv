#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, yasir hamadi alsahli <crusty.rusty.engine@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Enhanced Infrastructure Data Collection Utilities - Version 6
Copyright (c) 2025 Yasir Hamadi Alsahli <crusty.rusty.engine@gmail.com>

Shared utilities for robust cross-platform data collection.
Enhanced command execution with better error handling.
Improved compatibility with Rocky, Alma, and minimal environments.
"""

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import subprocess
import csv
import json
from datetime import datetime
from pathlib import Path

# CSV Schema definitions
HARDWARE_FIELDS = [
    'hostname', 'cpu_cores', 'cpu_model', 'memory_total_gb', 
    'memory_available_gb', 'architecture', 'kernel_version', 'timestamp'
]

NETWORK_FIELDS = [
    'hostname', 'interface', 'ip_address', 'network_mask', 
    'gateway', 'dns_servers', 'mac_address', 'timestamp'
]

STORAGE_FIELDS = [
    'hostname', 'device', 'mount_point', 'filesystem_type', 
    'total_size_gb', 'used_size_gb', 'available_size_gb', 'usage_percent', 'timestamp'
]

USER_FIELDS = [
    'hostname', 'username', 'uid', 'gid', 'home_directory', 
    'shell', 'last_login', 'schedule', 'command', 'source_type',
    'enabled', 'next_run_time', 'timestamp', 'is_privileged'
]

SECURITY_FIELDS = [
    'hostname', 'selinux_status', 'firewalld_status', 'ssh_root_login',
    'password_auth_status', 'users_with_sudo', 'timestamp'
]

FILESYSTEM_FIELDS = [
    'hostname', 'filesystem', 'mount_point', 'type', 'total_inodes',
    'used_inodes', 'free_inodes', 'inode_usage_percent', 'timestamp'
]


def get_hostname():
    """Get system hostname safely."""
    try:
        import socket
        return socket.gethostname()
    except Exception:
        # Fallback methods
        try:
            with open('/etc/hostname', 'r') as f:
                return f.read().strip()
        except:
            try:
                result = subprocess.run(['hostname'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    return result.stdout.strip()
            except:
                pass
        return "unknown"


def get_timestamp():
    """Get current timestamp in ISO format."""
    return datetime.now().isoformat()


def command_exists(command):
    """Check if a command exists in PATH."""
    try:
        # Use which/where depending on platform
        check_cmd = "where" if os.name == "nt" else "which"
        result = subprocess.run(
            [check_cmd, command],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False


def run_cmd(module, command, use_shell=False, ignore_errors=False, timeout=30):
    """
    Enhanced command execution with robust error handling.
    
    Args:
        module: Ansible module instance
        command: Command to execute (string or list)
        use_shell: Use shell for execution
        ignore_errors: Return 'N/A' instead of failing
        timeout: Command timeout in seconds
    
    Returns:
        Command output or 'N/A' if failed and ignore_errors=True
    """
    try:
        # Parse command
        if isinstance(command, str):
            if use_shell:
                cmd_args = command
            else:
                cmd_args = command.split()
        else:
            cmd_args = command

        # Check if base command exists (for non-shell commands)
        if not use_shell and isinstance(cmd_args, list) and cmd_args:
            base_cmd = cmd_args[0]
            if not command_exists(base_cmd):
                if ignore_errors:
                    return "N/A"
                else:
                    module.fail_json(msg=f"Command not found: {base_cmd}")

        # Execute command
        result = subprocess.run(
            cmd_args,
            shell=use_shell,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        # Handle return codes
        if result.returncode == 0:
            return result.stdout.strip()
        elif ignore_errors:
            # Return N/A for non-zero exit codes when ignoring errors
            return "N/A"
        else:
            error_msg = f"Command failed (rc={result.returncode}): {command}"
            if result.stderr:
                error_msg += f" -> {result.stderr.strip()}"
            module.fail_json(msg=error_msg)

    except subprocess.TimeoutExpired:
        if ignore_errors:
            return "N/A"
        else:
            module.fail_json(msg=f"Command timeout after {timeout}s: {command}")
    
    except FileNotFoundError:
        if ignore_errors:
            return "N/A"
        else:
            module.fail_json(msg=f"Command not found: {command}")
    
    except Exception as e:
        if ignore_errors:
            return "N/A"
        else:
            module.fail_json(msg=f"Command execution error: {str(e)}")


def read_file_safe(filepath, default_value=""):
    """Safely read file contents with fallback."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except Exception:
        return default_value


def write_csv(module, filepath, data, include_headers=True, fieldnames=None):
    """
    Write data to CSV file with proper error handling.
    
    Args:
        module: Ansible module instance
        filepath: Output file path
        data: Data to write (dict or list of dicts)
        include_headers: Include CSV headers
        fieldnames: Field names for CSV (required for dict data)
    
    Returns:
        Number of rows written
    """
    try:
        # Ensure parent directory exists
        path_obj = Path(filepath).resolve()
        path_obj.parent.mkdir(parents=True, exist_ok=True)
        
        # Normalize data to list
        if isinstance(data, dict):
            rows = [data]
        else:
            rows = list(data)
        
        if not rows:
            return 0
        
        # Auto-detect fieldnames if not provided
        if not fieldnames and rows:
            if isinstance(rows[0], dict):
                fieldnames = list(rows[0].keys())
            else:
                module.fail_json(msg="Fieldnames required for non-dict data")
        
        # Write CSV atomically
        temp_path = f"{filepath}.tmp.{os.getpid()}"
        
        with open(temp_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            
            if include_headers:
                writer.writeheader()
            
            for row in rows:
                if isinstance(row, dict):
                    # Ensure all required fields exist
                    clean_row = {}
                    for field in fieldnames:
                        clean_row[field] = str(row.get(field, 'N/A'))
                    writer.writerow(clean_row)
                else:
                    module.fail_json(msg="All data rows must be dictionaries")
        
        # Atomic move
        os.rename(temp_path, filepath)
        
        return len(rows)
        
    except Exception as e:
        # Cleanup temp file if it exists
        temp_path = f"{filepath}.tmp.{os.getpid()}"
        if os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except:
                pass
        
        module.fail_json(msg=f"Failed to write CSV to {filepath}: {str(e)}")


def validate_schema(module, data, expected_fields):
    """
    Validate and normalize data against expected schema.
    
    Args:
        module: Ansible module instance
        data: Data to validate (dict or list of dicts)
        expected_fields: List of expected field names
    
    Returns:
        Validated and normalized data
    """
    try:
        # Normalize to list
        if isinstance(data, dict):
            rows = [data]
        else:
            rows = list(data)
        
        validated_rows = []
        
        for row in rows:
            if not isinstance(row, dict):
                module.fail_json(msg="Data rows must be dictionaries")
            
            # Create normalized row with all expected fields
            normalized_row = {}
            for field in expected_fields:
                value = row.get(field, 'N/A')
                # Convert to string and handle None values
                if value is None:
                    normalized_row[field] = 'N/A'
                else:
                    normalized_row[field] = str(value)
            
            validated_rows.append(normalized_row)
        
        # Return original format (single dict vs list)
        if isinstance(data, dict):
            return validated_rows[0] if validated_rows else {}
        else:
            return validated_rows
        
    except Exception as e:
        module.fail_json(msg=f"Schema validation failed: {str(e)}")


def safe_float_convert(value, default=0.0):
    """Safely convert value to float with fallback."""
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


def safe_int_convert(value, default=0):
    """Safely convert value to integer with fallback."""
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def bytes_to_gb(bytes_value, decimal_places=2):
    """Convert bytes to gigabytes with proper rounding."""
    try:
        gb_value = float(bytes_value) / (1024 ** 3)
        return round(gb_value, decimal_places)
    except (ValueError, TypeError, ZeroDivisionError):
        return 0.0


def parse_df_output(df_line):
    """Parse df command output line into structured data."""
    try:
        parts = df_line.split()
        if len(parts) >= 6:
            return {
                'device': parts[0],
                'total': safe_int_convert(parts[1]) * 1024,  # Convert from KB to bytes
                'used': safe_int_convert(parts[2]) * 1024,
                'available': safe_int_convert(parts[3]) * 1024,
                'usage_percent': parts[4].rstrip('%'),
                'mount_point': parts[5]
            }
    except Exception:
        pass
    return None


def get_memory_from_proc():
    """Get memory information from /proc/meminfo."""
    memory_info = {
        'total': 0,
        'available': 0,
        'free': 0
    }
    
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if line.startswith('MemTotal:'):
                    memory_info['total'] = safe_int_convert(line.split()[1]) * 1024  # KB to bytes
                elif line.startswith('MemAvailable:'):
                    memory_info['available'] = safe_int_convert(line.split()[1]) * 1024
                elif line.startswith('MemFree:'):
                    memory_info['free'] = safe_int_convert(line.split()[1]) * 1024
    except Exception:
        pass
    
    return memory_info


def get_cpu_count_from_proc():
    """Get CPU count from /proc/cpuinfo."""
    try:
        with open('/proc/cpuinfo', 'r') as f:
            content = f.read()
            return len([line for line in content.splitlines() if line.startswith('processor')])
    except Exception:
        return 0


def format_timestamp(timestamp_str=None):
    """Format timestamp consistently."""
    if timestamp_str:
        try:
            # Try to parse and reformat
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            return dt.isoformat()
        except:
            return timestamp_str
    else:
        return datetime.now().isoformat()


def clean_string_for_csv(value):
    """Clean string value for CSV output."""
    if value is None:
        return 'N/A'
    
    # Convert to string
    str_value = str(value).strip()
    
    # Replace problematic characters
    str_value = str_value.replace('\n', ' ').replace('\r', ' ')
    str_value = str_value.replace(',', ';')  # Avoid CSV delimiter issues
    
    # Limit length for CSV compatibility
    if len(str_value) > 500:
        str_value = str_value[:497] + '...'
    
    return str_value if str_value else 'N/A'


def is_virtual_filesystem(device_name, mount_point):
    """Check if filesystem is virtual/special."""
    virtual_devices = [
        'tmpfs', 'devtmpfs', 'sysfs', 'proc', 'devpts', 
        'cgroup', 'pstore', 'mqueue', 'hugetlbfs',
        'debugfs', 'tracefs', 'securityfs', 'fusectl'
    ]
    
    virtual_mounts = [
        '/dev', '/sys', '/proc', '/run', '/tmp/systemd-private-'
    ]
    
    # Check device type
    for vdev in virtual_devices:
        if device_name.startswith(vdev):
            return True
    
    # Check mount point
    for vmount in virtual_mounts:
        if mount_point.startswith(vmount):
            return True
    
    # Check snap mounts
    if device_name.startswith('/dev/loop') and mount_point.startswith('/snap'):
        return True
    
    return False


def get_distribution_info():
    """Get Linux distribution information."""
    dist_info = {
        'name': 'Unknown',
        'version': 'Unknown',
        'codename': 'Unknown'
    }
    
    # Try /etc/os-release first
    os_release = read_file_safe('/etc/os-release', '')
    if os_release:
        for line in os_release.splitlines():
            if line.startswith('NAME='):
                dist_info['name'] = line.split('=', 1)[1].strip('"')
            elif line.startswith('VERSION='):
                dist_info['version'] = line.split('=', 1)[1].strip('"')
            elif line.startswith('VERSION_CODENAME='):
                dist_info['codename'] = line.split('=', 1)[1].strip('"')
    
    return dist_info


def ensure_directory_exists(filepath):
    """Ensure parent directory exists for file."""
    try:
        path_obj = Path(filepath).resolve()
        path_obj.parent.mkdir(parents=True, exist_ok=True)
        return True
    except Exception:
        return False
