"""
Input validation utilities.
"""

import re
import ipaddress
from typing import List, Tuple, Optional
import socket


def validate_ip(ip_str: str) -> bool:
    """
    Validate if string is a valid IP address.
    
    Args:
        ip_str: IP address string
        
    Returns:
        True if valid IP, False otherwise
    """
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def validate_cidr(cidr_str: str) -> bool:
    """
    Validate if string is a valid CIDR notation.
    
    Args:
        cidr_str: CIDR notation string (e.g., "192.168.1.0/24")
        
    Returns:
        True if valid CIDR, False otherwise
    """
    try:
        ipaddress.ip_network(cidr_str, strict=False)
        return True
    except ValueError:
        return False


def validate_hostname(hostname: str) -> bool:
    """
    Validate if string is a valid hostname.
    
    Args:
        hostname: Hostname string
        
    Returns:
        True if valid hostname, False otherwise
    """
    if len(hostname) > 255:
        return False
    
    # Remove trailing dot if present
    if hostname.endswith("."):
        hostname = hostname[:-1]
    
    # Check each label
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(label) for label in hostname.split("."))


def validate_port(port: int) -> bool:
    """
    Validate if port number is in valid range.
    
    Args:
        port: Port number
        
    Returns:
        True if valid port (1-65535), False otherwise
    """
    return 1 <= port <= 65535


def validate_port_range(port_range: str) -> Tuple[bool, Optional[str]]:
    """
    Validate port range string.
    
    Args:
        port_range: Port range string (e.g., "80", "1-1024", "80,443,8080")
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        # Single port
        if port_range.isdigit():
            port = int(port_range)
            if not validate_port(port):
                return False, f"Port {port} out of range (1-65535)"
            return True, None
        
        # Port range (e.g., "1-1024")
        if "-" in port_range and "," not in port_range:
            parts = port_range.split("-")
            if len(parts) != 2:
                return False, "Invalid port range format"
            
            start, end = parts
            if not start.isdigit() or not end.isdigit():
                return False, "Port range must be numeric"
            
            start_port, end_port = int(start), int(end)
            if not validate_port(start_port) or not validate_port(end_port):
                return False, "Port numbers out of range (1-65535)"
            
            if start_port > end_port:
                return False, "Start port must be less than end port"
            
            return True, None
        
        # Comma-separated ports (e.g., "80,443,8080")
        if "," in port_range:
            ports = port_range.split(",")
            for port_str in ports:
                port_str = port_str.strip()
                if "-" in port_str:
                    # Nested range validation
                    valid, error = validate_port_range(port_str)
                    if not valid:
                        return False, error
                elif port_str.isdigit():
                    port = int(port_str)
                    if not validate_port(port):
                        return False, f"Port {port} out of range"
                else:
                    return False, f"Invalid port specification: {port_str}"
            return True, None
        
        return False, "Invalid port range format"
    
    except Exception as e:
        return False, str(e)


def parse_port_list(port_spec: str) -> List[int]:
    """
    Parse port specification into list of port numbers.
    
    Args:
        port_spec: Port specification (e.g., "80", "1-100", "80,443,8080-8090")
        
    Returns:
        List of port numbers
    """
    ports = []
    
    # Split by comma
    for part in port_spec.split(","):
        part = part.strip()
        
        # Range
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.extend(range(start, end + 1))
        # Single port
        else:
            ports.append(int(part))
    
    return sorted(list(set(ports)))


def is_private_ip(ip_str: str) -> bool:
    """
    Check if IP address is private.
    
    Args:
        ip_str: IP address string
        
    Returns:
        True if private IP, False otherwise
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False


def resolve_hostname(hostname: str) -> Optional[str]:
    """
    Resolve hostname to IP address.
    
    Args:
        hostname: Hostname to resolve
        
    Returns:
        IP address string or None if resolution fails
    """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def sanitize_input(text: str, max_length: int = 1000) -> str:
    """
    Sanitize user input to prevent injection attacks.
    
    Args:
        text: Input text
        max_length: Maximum allowed length
        
    Returns:
        Sanitized text
    """
    # Truncate to max length
    text = text[:max_length]
    
    # Remove control characters except newline and tab
    text = ''.join(char for char in text if char.isprintable() or char in '\n\t')
    
    return text


def validate_file_path(file_path: str) -> Tuple[bool, Optional[str]]:
    """
    Validate file path for security.
    
    Args:
        file_path: File path to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    import os
    from pathlib import Path
    
    try:
        # Resolve to absolute canonical path to prevent traversal attacks
        requested_path = Path(file_path).resolve()
        
        # Get current working directory as allowed base
        base_path = Path.cwd().resolve()
        
        # Check if resolved path is within allowed directory
        try:
            requested_path.relative_to(base_path)
        except ValueError:
            # Path is outside allowed directory
            return False, "Path must be within current directory"
        
        # Check for sensitive locations
        sensitive_paths = ["/etc", "/sys", "/proc", "C:\\Windows", "C:\\System32"]
        for sensitive in sensitive_paths:
            if str(requested_path).startswith(sensitive):
                return False, f"Access to {sensitive} not allowed"
        
        return True, None
    
    except Exception as e:
        return False, f"Path validation error: {e}"
