# -*- coding: utf-8 -*-
"""
Shared utility module for infra2csv Ansible collection
Provides common functions for all CSV modules

This file should be placed in:
collections/ansible_collections/infra2csv/infra2csv/plugins/module_utils/infra2csv_utils.py
"""

import os
import csv
import socket
import getpass
from datetime import datetime


def run_cmd(module, cmd, use_shell=False, ignore_errors=True):
    """
    Execute system command with proper error handling
    
    Args:
        module: AnsibleModule instance
        cmd: Command to execute (string or list)
        use_shell: Whether to use shell execution
        ignore_errors: If True, return empty string on error; if False, fail module
    
    Returns:
        Command output (stripped) or empty string/N/A on error
    """
    try:
        if isinstance(cmd, str) and not use_shell:
            # Convert to list for safer execution
            cmd = cmd.split()
        
        rc, out, err = module.run_command(cmd, use_unsafe_shell=use_shell)
        
        if rc != 0:
            if ignore_errors:
                module.warn(f"Command failed (rc={rc}): {cmd} -> {err}")
                return "N/A"
            else:
                module.fail_json(msg=f"Command failed: {cmd}", rc=rc, stderr=err)
        
        return out.strip()
    except Exception as e:
        if ignore_errors:
            module.warn(f"Exception running command {cmd}: {str(e)}")
            return "N/A"
        else:
            module.fail_json(msg=f"Failed to execute command: {cmd}", exception=str(e))


def get_hostname():
    """Get system hostname with fallback"""
    try:
        return socket.gethostname()
    except Exception:
        return "N/A"


def get_ip_address():
    """Get primary IP address"""
    try:
        hostname = socket.gethostname()
        return socket.gethostbyname(hostname)
    except Exception:
        return "N/A"


def get_run_user():
    """Get current user with fallback"""
    try:
        return getpass.getuser()
    except Exception:
        return "N/A"


def get_timestamp():
    """Get standardized ISO timestamp"""
    return datetime.now().isoformat()


def ensure_dir(path):
    """Ensure directory exists for given file path"""
    if not path:
        return
    
    dir_path = os.path.dirname(path)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)


def read_file_safe(filepath, default="N/A"):
    """Safely read a file with fallback"""
    try:
        with open(filepath, 'r') as f:
            return f.read().strip()
    except Exception:
        return default


def write_csv(module, path, data, include_headers=True, fieldnames=None):
    """
    Write data to CSV file with consistent handling
    
    Args:
        module: AnsibleModule instance
        path: CSV file path
        data: Single dict or list of dicts
        include_headers: Whether to write headers
        fieldnames: Explicit field names (optional)
    
    Returns:
        Number of rows written
    """
    # Normalize data to list
    rows = [data] if isinstance(data, dict) else list(data)
    
    if not rows:
        return 0
    
    # Determine fieldnames
    if not fieldnames:
        fieldnames = list(rows[0].keys())
    
    # Ensure all rows have all fields
    for row in rows:
        for field in fieldnames:
            if field not in row:
                row[field] = "N/A"
    
    # Ensure directory exists
    ensure_dir(path)
    
    try:
        file_exists = os.path.exists(path) and os.path.getsize(path) > 0
        
        with open(path, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            
            # Write header if needed
            if include_headers and not file_exists:
                writer.writeheader()
            
            # Write data
            for row in rows:
                writer.writerow(row)
        
        return len(rows)
    
    except Exception as e:
        module.fail_json(msg=f"Failed to write CSV to {path}: {str(e)}")


def validate_schema(module, data, expected_fields):
    """
    Validate data against expected schema
    
    Args:
        module: AnsibleModule instance
        data: Dict or list of dicts to validate
        expected_fields: List of expected field names
    
    Returns:
        Validated data with all expected fields
    """
    rows = [data] if isinstance(data, dict) else list(data)
    
    for row in rows:
        # Check for unexpected fields
        extra_fields = set(row.keys()) - set(expected_fields)
        if extra_fields:
            module.warn(f"Unexpected fields in data: {extra_fields}")
        
        # Ensure all expected fields exist
        for field in expected_fields:
            if field not in row:
                row[field] = "N/A"
    
    return data


def get_bin_path_safe(module, binary, required=False):
    """Safely get binary path with fallback"""
    try:
        return module.get_bin_path(binary, required=required)
    except Exception as e:
        if required:
            module.fail_json(msg=f"Required binary '{binary}' not found: {str(e)}")
        return None


# Schema definitions for each module type
HARDWARE_FIELDS = [
    "hostname", "ip", "os", "os_version", "arch", "cpu", "ram_gb",
    "uptime_sec", "boot_time", "serial_number", "model", "cpu_cores",
    "cpu_threads", "disk_total_gb", "user_count", "run_by", "timestamp"
]

NIC_FIELDS = [
    "interface", "mac_address", "state", "speed_mbps", "mtu",
    "hostname", "run_by", "timestamp"
]

STORAGE_FS_FIELDS = [
    "mode", "device", "type", "size", "used", "avail", "use_percent",
    "mountpoint", "hostname", "run_by", "timestamp"
]

STORAGE_DEVICE_FIELDS = [
    "mode", "device", "size_bytes", "type", "model",
    "hostname", "run_by", "timestamp"
]

USER_FIELDS = [
    "hostname", "username", "uid", "gid", "home_directory", "shell",
    "last_login", "schedule", "command", "source_type", "enabled",
    "next_run_time", "timestamp", "is_privileged"
]

SECURITY_FIELDS = [
    "hostname", "selinux_status", "firewalld_status", "ssh_root_login",
    "password_auth_status", "users_with_sudo", "timestamp"
]

FILESYSTEM_HEALTH_FIELDS = [
    "hostname", "mountpoint", "fsck_required", "last_fsck",
    "last_fsck_result", "filesystem_type", "timestamp"
]
