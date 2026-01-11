"""
Network validation module for pre-scan checks.
"""

import socket
from typing import Tuple, List
import ipaddress

from utils.logger import scanner_logger


class NetworkValidator:
    """
    Validates network targets and connectivity before scanning.
    """
    
    @staticmethod
    def validate_target(target: str) -> Tuple[bool, str]:
        """
        Validate a scan target.
        
        Args:
            target: IP address or hostname
            
        Returns:
            Tuple of (is_valid, message)
        """
        # Try as IP address
        try:
            ipaddress.ip_address(target)
            return True, f"Valid IP address: {target}"
        except ValueError:
            pass
        
        # Try as hostname
        try:
            ip = socket.gethostbyname(target)
            return True, f"Hostname resolved to {ip}"
        except socket.gaierror:
            return False, f"Cannot resolve hostname: {target}"
    
    @staticmethod
    def check_reachability(host: str, timeout: float = 2.0) -> Tuple[bool, str]:
        """
        Check if a host is reachable.
        
        Args:
            host: IP address or hostname
            timeout: Timeout in seconds
            
        Returns:
            Tuple of (is_reachable, message)
        """
        try:
            # Try to connect to port 80 as reachability check
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, 80))
            sock.close()
            
            # Any result means host is up (connection refused = host is up, port is closed)
            return True, f"Host {host} is reachable"
        
        except socket.timeout:
            return False, f"Host {host} timed out"
        except socket.error as e:
            return False, f"Host {host} unreachable: {e}"
        except Exception as e:
            return False, f"Error checking {host}: {e}"
    
    @staticmethod
    def dns_resolve(hostname: str) -> Tuple[bool, str, str]:
        """
        Resolve hostname to IP address.
        
        Args:
            hostname: Hostname to resolve
            
        Returns:
            Tuple of (success, ip_address, message)
        """
        try:
            ip = socket.gethostbyname(hostname)
            return True, ip, f"Resolved {hostname} to {ip}"
        except socket.gaierror as e:
            return False, "", f"DNS resolution failed for {hostname}: {e}"
    
    @staticmethod
    def reverse_dns(ip: str) -> Tuple[bool, str, str]:
        """
        Perform reverse DNS lookup.
        
        Args:
            ip: IP address
            
        Returns:
            Tuple of (success, hostname, message)
        """
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return True, hostname, f"Reverse DNS: {ip} -> {hostname}"
        except socket.herror:
            return False, "", f"No reverse DNS for {ip}"
    
    @staticmethod
    def validate_network_range(cidr: str) -> Tuple[bool, int, str]:
        """
        Validate CIDR network range.
        
        Args:
            cidr: CIDR notation (e.g., "192.168.1.0/24")
            
        Returns:
            Tuple of (is_valid, host_count, message)
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            host_count = network.num_addresses - 2  # Exclude network and broadcast
            
            if host_count > 10000:
                return True, host_count, f"Warning: Large range ({host_count} hosts)"
            else:
                return True, host_count, f"Valid range with {host_count} hosts"
        
        except ValueError as e:
            return False, 0, f"Invalid CIDR notation: {e}"
    
    @staticmethod
    def estimate_scan_time(
        host_count: int,
        port_count: int,
        timeout: float,
        threads: int
    ) -> float:
        """
        Estimate scan duration.
        
        Args:
            host_count: Number of hosts
            port_count: Number of ports per host
            timeout: Timeout per connection
            threads: Number of parallel threads
            
        Returns:
            Estimated time in seconds
        """
        total_connections = host_count * port_count
        avg_time_per_port = timeout / 2  # Assume average is half of timeout
        
        # Calculate time with parallel execution
        estimated_time = (total_connections * avg_time_per_port) / threads
        
        return estimated_time
    
    @staticmethod
    def get_network_info() -> dict:
        """
        Get local network information.
        
        Returns:
            Dictionary with network info
        """
        info = {
            "hostname": socket.gethostname(),
            "fqdn": socket.getfqdn(),
            "local_ip": None,
        }
        
        try:
            # Get local IP
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            info["local_ip"] = sock.getsockname()[0]
            sock.close()
        except Exception as e:
            scanner_logger.error(f"Error getting local IP: {e}")
        
        return info
