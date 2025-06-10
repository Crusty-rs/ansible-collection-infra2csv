# -*- coding: utf-8 -*-
"""
infra2csv Enhanced Utility Module
Copyright (c) 2025 Yasir Hamadi Alsahli <crusty.rusty.engine@gmail.com>

Target-only data collection. No controller BS. Clean, fast, bulletproof.
Writes CSV or JSON directly on managed hosts. Zero delegation drama.
"""

import os
import csv
import json
import socket
import getpass
import tempfile
from datetime import datetime
from pathlib import Path


def run_cmd(module, cmd, use_shell=False, ignore_errors=True):
    """Execute commands with zero drama. Returns output or 'N/A'."""
    try:
        if isinstance(cmd, str) and not use_shell:
            cmd = cmd.split()
        
        rc, out, err = module.run_command(cmd, use_unsafe_shell=use_shell)
        
        if rc != 0:
            if ignore_errors:
                return "N/A"
            else:
                module.fail_json(msg=f"Command failed: {cmd}", rc=rc, stderr=err)
        
        return out.strip()
    except Exception as e:
        if ignore_errors:
            return "N/A"
        else:
            module.fail_json(msg=f"Failed to execute: {cmd}", exception=str(e))


def get_hostname():
    """Get hostname. Always works."""
    try:
        return socket.gethostname()
    except Exception:
        return "localhost"


def get_ip_address():
    """Get primary IP. Falls back gracefully."""
    try:
        hostname = socket.gethostname()
        return socket.gethostbyname(hostname)
    except Exception:
        return "127.0.0.1"


def get_run_user():
    """Current user. No mysteries."""
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def get_timestamp():
    """ISO timestamp. Always consistent."""
    return datetime.now().isoformat()


def sanitize_path(path):
    """Clean and validate file path. Security first."""
    if not path:
        raise ValueError("Path cannot be empty")
    
    # Convert to Path object for better handling
    path_obj = Path(path).resolve()
    
    # Ensure parent directory exists
    path_obj.parent.mkdir(parents=True, exist_ok=True)
    
    return str(path_obj)


def detect_output_format(path):
    """Detect output format from file extension."""
    path_lower = path.lower()
    if path_lower.endswith('.json'):
        return 'json'
    elif path_lower.endswith('.csv'):
        return 'csv'
    else:
        # Default to CSV for unknown extensions
        return 'csv'


def write_data(module, path, data, include_headers=True, fieldnames=None):
    """
    Universal data writer. CSV or JSON based on extension.
    Target-only. No controller assumptions. Bulletproof.
    """
    if not data:
        return 0
    
    try:
        # Sanitize path and detect format
        clean_path = sanitize_path(path)
        output_format = detect_output_format(clean_path)
        
        # Normalize data to list
        rows = [data] if isinstance(data, dict) else list(data)
        
        if output_format == 'json':
            return write_json(module, clean_path, rows)
        else:
            return write_csv(module, clean_path, rows, include_headers, fieldnames)
            
    except Exception as e:
        module.fail_json(msg=f"Failed to write data to {path}: {str(e)}")


def write_json(module, path, data):
    """Write JSON data. Clean, atomic, reliable."""
    try:
        # Add metadata
        output_data = {
            'timestamp': get_timestamp(),
            'hostname': get_hostname(),
            'data_count': len(data),
            'data': data
        }
        
        # Atomic write using temp file
        temp_path = f"{path}.tmp.{os.getpid()}"
        
        with open(temp_path, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        
        # Atomic move
        os.rename(temp_path, path)
        
        return len(data)
        
    except Exception as e:
        # Clean up temp file if exists
        temp_path = f"{path}.tmp.{os.getpid()}"
        if os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except:
                pass
        raise e


def write_csv(module, path, data, include_headers=True, fieldnames=None):
    """Write CSV data. Append-safe, consistent schema."""
    if not data:
        return 0
    
    try:
        rows = [data] if isinstance(data, dict) else list(data)
        
        # Determine fieldnames
        if not fieldnames:
            fieldnames = list(rows[0].keys())
        
        # Fill missing fields with "N/A"
        for row in rows:
            for field in fieldnames:
                if field not in row:
                    row[field] = "N/A"
        
        # Check if file exists and has content
        file_exists = os.path.exists(path) and os.path.getsize(path) > 0
        
        # Atomic write using temp file for new files, direct append for existing
        if file_exists:
            # File exists, append directly
            with open(path, 'a', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                for row in rows:
                    writer.writerow(row)
        else:
            # New file, use atomic write
            temp_path = f"{path}.tmp.{os.getpid()}"
            
            with open(temp_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                
                if include_headers:
                    writer.writeheader()
                
                for row in rows:
                    writer.writerow(row)
            
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


def read_file_safe(filepath, default="N/A"):
    """Read files without drama. Always returns something."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read().strip()
    except Exception:
        return default


def validate_schema(module, data, expected_fields):
    """Ensure data consistency. Fill gaps, warn about extras."""
    rows = [data] if isinstance(data, dict) else list(data)
    
    for row in rows:
        # Check for unexpected fields
        extra_fields = set(row.keys()) - set(expected_fields)
        if extra_fields:
            module.warn(f"Unexpected fields: {extra_fields}")
        
        # Fill missing fields
        for field in expected_fields:
            if field not in row:
                row[field] = "N/A"
    
    return data


def get_bin_path_safe(module, binary, required=False):
    """Find binary path. Graceful degradation."""
    try:
        return module.get_bin_path(binary, required=required)
    except Exception as e:
        if required:
            module.fail_json(msg=f"Required binary '{binary}' not found: {str(e)}")
        return None


# Schema definitions - exact field order and names
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
