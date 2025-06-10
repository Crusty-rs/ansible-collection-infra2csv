#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Enhanced Infrastructure Data Collection Utilities
Copyright (c) 2025 Yasir Hamadi Alsahli <crusty.rusty.engine@gmail.com>

Shared utilities for robust cross-platform data collection.
Enhanced command execution with better error handling.
"""

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
