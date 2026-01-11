"""
Backend security module for Enterprise Port Scanner.

This module provides security controls including:
- Exclusion lists for target validation
- Secure file validation
- Network monitoring
- Audit logging
"""

import os
import json
import ipaddress
from datetime import datetime
from pathlib import Path
from typing import List, Set, Optional
from dataclasses import dataclass, field

from config import AUDIT_LOG_PATH, PRIVATE_IP_RANGES
from utils.logger import security_logger


@dataclass
class ExclusionList:
    """
    Manages IP exclusion/inclusion lists for scan target validation.
    
    Provides comprehensive security controls to prevent unauthorized scanning.
    """
    
    allowed_networks: Set[str] = field(default_factory=set)
    denied_networks: Set[str] = field(default_factory=set)
    allowed_ips: Set[str] = field(default_factory=set)
    denied_ips: Set[str] = field(default_factory=set)
    require_explicit_allow: bool = False
    
    def __post_init__(self):
        """Initialize with default private networks as allowed."""
        if not self.allowed_networks:
            # Allow private IP ranges by default
            for cidr in PRIVATE_IP_RANGES:
                self.allowed_networks.add(cidr)
    
    def add_allowed_network(self, cidr: str) -> None:
        """Add a network to the allow list."""
        try:
            # Validate CIDR
            ipaddress.ip_network(cidr, strict=False)
            self.allowed_networks.add(cidr)
            security_logger.info(f"Added allowed network: {cidr}")
        except ValueError as e:
            security_logger.error(f"Invalid CIDR notation: {cidr} - {e}")
            raise
    
    def add_denied_network(self, cidr: str) -> None:
        """Add a network to the deny list."""
        try:
            ipaddress.ip_network(cidr, strict=False)
            self.denied_networks.add(cidr)
            security_logger.warning(f"Added denied network: {cidr}")
        except ValueError as e:
            security_logger.error(f"Invalid CIDR notation: {cidr} - {e}")
            raise
    
    def add_allowed_ip(self, ip: str) -> None:
        """Add an IP to the allow list."""
        try:
            ipaddress.ip_address(ip)
            self.allowed_ips.add(ip)
            security_logger.info(f"Added allowed IP: {ip}")
        except ValueError as e:
            security_logger.error(f"Invalid IP address: {ip} - {e}")
            raise
    
    def add_denied_ip(self, ip: str) -> None:
        """Add an IP to the deny list."""
        try:
            ipaddress.ip_address(ip)
            self.denied_ips.add(ip)
            security_logger.warning(f"Added denied IP: {ip}")
        except ValueError as e:
            security_logger.error(f"Invalid IP address: {ip} - {e}")
            raise
    
    def is_allowed(self, ip: str) -> tuple:
        """
        Check if an IP address is allowed to be scanned.
        
        Args:
            ip: IP address to check
            
        Returns:
            Tuple of (is_allowed: bool, reason: str)
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return False, f"Invalid IP address: {ip}"
        
        # Check explicit deny list first
        if ip in self.denied_ips:
            return False, f"IP {ip} is explicitly denied"
        
        # Check if IP is in denied network
        for cidr in self.denied_networks:
            network = ipaddress.ip_network(cidr, strict=False)
            if ip_obj in network:
                return False, f"IP {ip} is in denied network {cidr}"
        
        # Check explicit allow list
        if ip in self.allowed_ips:
            return True, f"IP {ip} is explicitly allowed"
        
        # Check if IP is in allowed network
        for cidr in self.allowed_networks:
            network = ipaddress.ip_network(cidr, strict=False)
            if ip_obj in network:
                return True, f"IP {ip} is in allowed network {cidr}"
        
        # If require_explicit_allow is True, deny by default
        if self.require_explicit_allow:
            return False, f"IP {ip} not in allow list (explicit allow required)"
        
        # Warn about external IPs
        if not ip_obj.is_private:
            return False, f"IP {ip} is external/public (requires explicit permission)"
        
        # Allow by default for private IPs
        return True, f"IP {ip} is allowed"
    
    def validate_targets(self, targets: List[str]) -> tuple:
        """
        Validate a list of target IPs.
        
        Args:
            targets: List of IP addresses
            
        Returns:
            Tuple of (valid_targets: List[str], invalid_targets: Dict[str, str])
        """
        valid = []
        invalid = {}
        
        for ip in targets:
            is_allowed, reason = self.is_allowed(ip)
            if is_allowed:
                valid.append(ip)
            else:
                invalid[ip] = reason
                security_logger.warning(f"Target validation failed: {reason}")
        
        return valid, invalid
    
    def save_to_file(self, file_path: str) -> None:
        """Save exclusion list to JSON file."""
        data = {
            "allowed_networks": list(self.allowed_networks),
            "denied_networks": list(self.denied_networks),
            "allowed_ips": list(self.allowed_ips),
            "denied_ips": list(self.denied_ips),
            "require_explicit_allow": self.require_explicit_allow,
        }
        
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        security_logger.info(f"Exclusion list saved to {file_path}")
    
    @classmethod
    def load_from_file(cls, file_path: str) -> 'ExclusionList':
        """Load exclusion list from JSON file."""
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        exclusion_list = cls(
            allowed_networks=set(data.get("allowed_networks", [])),
            denied_networks=set(data.get("denied_networks", [])),
            allowed_ips=set(data.get("allowed_ips", [])),
            denied_ips=set(data.get("denied_ips", [])),
            require_explicit_allow=data.get("require_explicit_allow", False),
        )
        
        security_logger.info(f"Exclusion list loaded from {file_path}")
        return exclusion_list


class SecureFileValidator:
    """
    Validates file paths to prevent path traversal and unauthorized access.
    """
    
    DANGEROUS_PATHS = [
        "/etc", "/sys", "/proc", "/dev", "/root",
        "C:\\Windows", "C:\\System32", "C:\\Program Files"
    ]
    
    @staticmethod
    def validate_path(file_path: str) -> tuple:
        """
        Validate file path for security.
        
        Args:
            file_path: File path to validate
            
        Returns:
            Tuple of (is_valid: bool, reason: str)
        """
        try:
            # Resolve to absolute path
            abs_path = Path(file_path).resolve()
            
            # Check for path traversal
            if ".." in str(file_path):
                return False, "Path traversal detected"
            
            # Check against dangerous paths
            for dangerous in SecureFileValidator.DANGEROUS_PATHS:
                if str(abs_path).startswith(dangerous):
                    return False, f"Access to {dangerous} not allowed"
            
            return True, "Path is valid"
        
        except Exception as e:
            return False, f"Path validation error: {e}"
    
    @staticmethod
    def validate_and_read(file_path: str, max_size: int = 10 * 1024 * 1024) -> tuple:
        """
        Validate and read a file safely.
        
        Args:
            file_path: File path to read
            max_size: Maximum file size in bytes (default 10MB)
            
        Returns:
            Tuple of (success: bool, content_or_error: str)
        """
        is_valid, reason = SecureFileValidator.validate_path(file_path)
        if not is_valid:
            security_logger.error(f"File validation failed: {reason}")
            return False, reason
        
        try:
            path = Path(file_path)
            
            # Check file exists
            if not path.exists():
                return False, "File does not exist"
            
            # Check file size
            if path.stat().st_size > max_size:
                return False, f"File too large (max {max_size} bytes)"
            
            # Read file
            with open(path, 'r') as f:
                content = f.read()
            
            security_logger.info(f"File read successfully: {file_path}")
            return True, content
        
        except Exception as e:
            security_logger.error(f"Error reading file: {e}")
            return False, str(e)


class NetworkMonitor:
    """
    Monitors network connectivity and provides diagnostic information.
    """
    
    @staticmethod
    def check_connectivity(host: str = "8.8.8.8", port: int = 53, timeout: float = 3.0) -> bool:
        """
        Check if network connectivity is available.
        
        Args:
            host: Host to check (default: Google DNS)
            port: Port to check
            timeout: Connection timeout
            
        Returns:
            True if connected, False otherwise
        """
        import socket
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.close()
            return True
        except (socket.error, socket.timeout):
            return False
    
    @staticmethod
    def get_local_ip() -> Optional[str]:
        """
        Get local IP address.
        
        Returns:
            Local IP address or None
        """
        import socket
        
        try:
            # Connect to external host to determine local IP
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]
            sock.close()
            return local_ip
        except Exception:
            return None
    
    @staticmethod
    def get_network_interfaces() -> List[dict]:
        """
        Get available network interfaces.
        
        Returns:
            List of interface information
        """
        import psutil
        
        interfaces = []
        
        try:
            addrs = psutil.net_if_addrs()
            for interface_name, addr_list in addrs.items():
                for addr in addr_list:
                    if addr.family == 2:  # AF_INET (IPv4)
                        interfaces.append({
                            "name": interface_name,
                            "ip": addr.address,
                            "netmask": addr.netmask,
                        })
        except Exception as e:
            security_logger.error(f"Error getting network interfaces: {e}")
        
        return interfaces


class AuditLogger:
    """
    Provides tamper-proof audit logging for security events.
    """
    
    def __init__(self, log_file: str = None):
        """
        Initialize audit logger.
        
        Args:
            log_file: Path to audit log file
        """
        self.log_file = Path(log_file) if log_file else AUDIT_LOG_PATH
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
    
    def log_event(self, event_type: str, user: str, details: dict) -> None:
        """
        Log a security event.
        
        Args:
            event_type: Type of event (e.g., "SCAN_START", "LOGIN", "PERMISSION_DENIED")
            user: Username
            details: Event details dictionary
        """
        entry = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "user": user,
            "details": details,
        }
        
        try:
            # Append to log file
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(entry) + '\n')
            
            security_logger.info(f"Audit log: {event_type} by {user}")
        
        except Exception as e:
            security_logger.error(f"Failed to write audit log: {e}")
    
    def get_recent_events(self, count: int = 100) -> List[dict]:
        """
        Get recent audit events.
        
        Args:
            count: Number of recent events to retrieve
            
        Returns:
            List of audit events
        """
        events = []
        
        try:
            if self.log_file.exists():
                with open(self.log_file, 'r') as f:
                    lines = f.readlines()
                    # Get last N lines
                    for line in lines[-count:]:
                        try:
                            events.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
        except Exception as e:
            security_logger.error(f"Error reading audit log: {e}")
        
        return events


# Global instances
default_exclusion_list = ExclusionList()
audit_logger = AuditLogger()
