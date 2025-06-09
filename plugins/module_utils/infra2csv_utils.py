# -*- coding: utf-8 -*-
"""
infra2csv Shared Utility Module
Copyright (c) 2025 Yasir Hamahdi Alsahli <crusty.rusty.engine@gmail.com>

Core utils for the squad. Clean, consistent, no cap.
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
    Execute system commands without the drama.
    
    Args:
        module: Ansible module instance (the boss)
        cmd: Command to run (string or list)
        use_shell: Shell mode on/off (default: nah)
        ignore_errors: Keep vibing on errors (default: yep)
    
    Returns:
        Command output or "N/A" when things go sideways
    """
    try:
        # Convert string to list for safer execution (security ftw)
        if isinstance(cmd, str) and not use_shell:
            cmd = cmd.split()
        
        # Let Ansible handle the heavy lifting
        rc, out, err = module.run_command(cmd, use_unsafe_shell=use_shell)
        
        if rc != 0:
            if ignore_errors:
                # Log the L but keep moving
                module.warn(f"Command failed (rc={rc}): {cmd} -> {err}")
                return "N/A"
            else:
                # Full stop, this is serious
                module.fail_json(msg=f"Command failed: {cmd}", rc=rc, stderr=err)
        
        return out.strip()
    except Exception as e:
        if ignore_errors:
            # Catch the exception, log it, move on
            module.warn(f"Exception running command {cmd}: {str(e)}")
            return "N/A"
        else:
            # Nope, we're done here
            module.fail_json(msg=f"Failed to execute command: {cmd}", exception=str(e))


def get_hostname():
    """Get system hostname. No hostname? No problem."""
    try:
        return socket.gethostname()
    except Exception:
        return "N/A"  # Anonymous vibes


def get_ip_address():
    """Get primary IP. Living off the grid? We got you."""
    try:
        hostname = socket.gethostname()
        return socket.gethostbyname(hostname)
    except Exception:
        return "N/A"  # Ghost mode activated


def get_run_user():
    """Who's running this? Let's find out."""
    try:
        return getpass.getuser()
    except Exception:
        return "N/A"  # Mystery user


def get_timestamp():
    """ISO timestamp. Keeping receipts since 2025."""
    return datetime.now().isoformat()


def ensure_dir(path):
    """Make sure directory exists. Creating paths like we create opportunities."""
    if not path:
        return
    
    dir_path = os.path.dirname(path)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)


def read_file_safe(filepath, default="N/A"):
    """
    Read files without the stress.
    
    Args:
        filepath: Where we looking?
        default: Backup plan (default: "N/A")
    
    Returns:
        File contents or default value. No panic.
    """
    try:
        with open(filepath, 'r') as f:
            return f.read().strip()
    except Exception:
        return default  # File not found? It's chill


def write_csv(module, path, data, include_headers=True, fieldnames=None):
    """
    Write CSV like a pro. Clean, consistent, no mess.
    
    Args:
        module: Ansible module instance
        path: Where we dropping this CSV
        data: The goods (dict or list of dicts)
        include_headers: Headers or nah? (default: yeah)
        fieldnames: Column order (optional, we'll figure it out)
    
    Returns:
        Number of rows written. Keeping score.
    """
    # Normalize data - everything's a list now
    rows = [data] if isinstance(data, dict) else list(data)
    
    if not rows:
        return 0  # Nothing to write? We out
    
    # Figure out field names if not provided
    if not fieldnames:
        fieldnames = list(rows[0].keys())
    
    # Fill missing fields with "N/A" - no blanks allowed
    for row in rows:
        for field in fieldnames:
            if field not in row:
                row[field] = "N/A"
    
    # Ensure directory exists (creating the future)
    ensure_dir(path)
    
    try:
        # Check if file exists and has content
        file_exists = os.path.exists(path) and os.path.getsize(path) > 0
        
        # Open in append mode - we're building history
        with open(path, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            
            # Write header if needed (first time's special)
            if include_headers and not file_exists:
                writer.writeheader()
            
            # Drop the data
            for row in rows:
                writer.writerow(row)
        
        return len(rows)  # Mission accomplished
    
    except Exception as e:
        # CSV write failed? That's a wrap
        module.fail_json(msg=f"Failed to write CSV to {path}: {str(e)}")


def validate_schema(module, data, expected_fields):
    """
    Keep the data clean and consistent. Schema police.
    
    Args:
        module: Ansible module instance  
        data: Data to validate (dict or list)
        expected_fields: The law (list of required fields)
    
    Returns:
        Validated data with all fields present
    """
    # Make it a list for easier processing
    rows = [data] if isinstance(data, dict) else list(data)
    
    for row in rows:
        # Check for rogues (unexpected fields)
        extra_fields = set(row.keys()) - set(expected_fields)
        if extra_fields:
            module.warn(f"Unexpected fields in data: {extra_fields}")
        
        # Ensure all expected fields exist - no gaps
        for field in expected_fields:
            if field not in row:
                row[field] = "N/A"
    
    return data  # Clean and validated


def get_bin_path_safe(module, binary, required=False):
    """Find binary path. Not there? We'll deal."""
    try:
        return module.get_bin_path(binary, required=required)
    except Exception as e:
        if required:
            # Required binary missing? Game over
            module.fail_json(msg=f"Required binary '{binary}' not found: {str(e)}")
        return None  # Optional binary? No stress


# Schema definitions - the blueprint for success
# Each list defines exact field order and names

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
