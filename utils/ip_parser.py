"""
IP address and CIDR parsing utilities.
"""

import ipaddress
from typing import List, Iterator
import socket


def parse_targets(target_input: str) -> List[str]:
    """
    Parse target input into list of IP addresses.
    
    Supports:
    - Single IP: 192.168.1.1
    - Multiple IPs: 192.168.1.1,192.168.1.2
    - CIDR: 192.168.1.0/24
    - Hostnames: example.com
    - Mixed: 192.168.1.1,10.0.0.0/24,example.com
    
    Args:
        target_input: Target specification string
        
    Returns:
        List of IP addresses
    """
    targets = []
    
    # Split by comma or newline
    parts = [p.strip() for p in target_input.replace('\n', ',').split(',') if p.strip()]
    
    for part in parts:
        # Try CIDR
        if '/' in part:
            try:
                network = ipaddress.ip_network(part, strict=False)
                targets.extend([str(ip) for ip in network.hosts()])
            except ValueError:
                pass  # Invalid CIDR, skip
        # Try IP address
        else:
            try:
                ipaddress.ip_address(part)
                targets.append(part)
            except ValueError:
                # Try hostname resolution
                try:
                    ip = socket.gethostbyname(part)
                    targets.append(ip)
                except socket.gaierror:
                    pass  # Invalid hostname, skip
    
    return list(set(targets))  # Remove duplicates


def expand_cidr(cidr: str) -> List[str]:
    """
    Expand CIDR notation into list of IP addresses.
    
    Args:
        cidr: CIDR notation (e.g., "192.168.1.0/24")
        
    Returns:
        List of IP addresses
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return []


def cidr_to_ip_range(cidr: str) -> tuple:
    """
    Convert CIDR to start and end IP addresses.
    
    Args:
        cidr: CIDR notation
        
    Returns:
        Tuple of (start_ip, end_ip)
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return str(network.network_address), str(network.broadcast_address)
    except ValueError:
        return None, None


def is_ip_in_range(ip: str, cidr: str) -> bool:
    """
    Check if IP address is within CIDR range.
    
    Args:
        ip: IP address
        cidr: CIDR notation
        
    Returns:
        True if IP is in range, False otherwise
    """
    try:
        ip_addr = ipaddress.ip_address(ip)
        network = ipaddress.ip_network(cidr, strict=False)
        return ip_addr in network
    except ValueError:
        return False


def get_ip_version(ip: str) -> int:
    """
    Get IP version (4 or 6).
    
    Args:
        ip: IP address
        
    Returns:
        4 for IPv4, 6 for IPv6, 0 for invalid
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.version
    except ValueError:
        return 0


def parse_target_file(file_path: str) -> List[str]:
    """
    Parse targets from a text file.
    
    Args:
        file_path: Path to file containing targets (one per line)
        
    Returns:
        List of IP addresses
    """
    targets = []
    
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Parse each line as target input
                    targets.extend(parse_targets(line))
    except Exception:
        pass
    
    return list(set(targets))


def batch_ips(ips: List[str], batch_size: int = 100) -> Iterator[List[str]]:
    """
    Batch IP addresses into chunks for processing.
    
    Args:
        ips: List of IP addresses
        batch_size: Size of each batch
        
    Yields:
        Batches of IP addresses
    """
    for i in range(0, len(ips), batch_size):
        yield ips[i:i + batch_size]
