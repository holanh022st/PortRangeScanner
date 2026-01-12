"""
Scan profile data model.
"""

from dataclasses import dataclass, field, asdict
from typing import Optional, List
import json


@dataclass
class ScanProfile:
    """
    Represents a scan configuration profile.
    
    Attributes:
        name: Profile name
        description: Profile description
        scan_type: TCP, UDP, or both
        speed: Scan speed (Very Slow, Normal, Fast, etc.)
        timeout: Connection timeout in seconds
        max_threads: Maximum parallel threads
        retries: Number of retries per port
        enable_service_detection: Detect service types
        enable_banner_grabbing: Grab service banners
        enable_version_detection: Detect service versions
        rescan_open_ports: Re-scan open ports for confirmation
        port_ranges: List of port ranges/presets
        is_locked: Whether profile is read-only
        created_by: User who created the profile
        is_default: Whether this is a default profile
    """
    name: str
    description: str = ""
    scan_type: str = "TCP"
    speed: str = "Normal"
    timeout: float = 2.0
    max_threads: int = 50
    retries: int = 1
    enable_service_detection: bool = True
    enable_banner_grabbing: bool = True
    enable_version_detection: bool = True
    rescan_open_ports: bool = False
    port_ranges: List[str] = field(default_factory=list)
    is_locked: bool = False
    created_by: str = "System"
    is_default: bool = False
    
    def to_dict(self) -> dict:
        """Convert profile to dictionary."""
        return asdict(self)
    
    def to_json(self) -> str:
        """Convert profile to JSON string."""
        return json.dumps(self.to_dict(), indent=2)
    
    @classmethod
    def from_dict(cls, data: dict) -> 'ScanProfile':
        """Create profile from dictionary."""
        return cls(**data)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'ScanProfile':
        """Create profile from JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)
    
    @classmethod
    def create_default_profiles(cls) -> List['ScanProfile']:
        """Create standard default profiles."""
        return [
            cls(
                name="Quick Web Scan",
                description="Fast scan of common web ports",
                speed="Fast",
                port_ranges=["80", "443", "8080", "8443"],
                timeout=1.0,
                max_threads=100,
                is_default=True,
            ),
            cls(
                name="Full Network Audit",
                description="Comprehensive scan of all common ports",
                speed="Normal",
                port_ranges=["1-1024"],
                enable_service_detection=True,
                enable_banner_grabbing=True,
                enable_version_detection=True,
                rescan_open_ports=True,
                is_default=True,
            ),
            cls(
                name="Database Discovery",
                description="Scan common database ports",
                speed="Normal",
                port_ranges=["3306", "5432", "1433", "27017", "6379"],
                enable_service_detection=True,
                enable_banner_grabbing=True,
                is_default=True,
            ),
            cls(
                name="Remote Access Scan",
                description="Scan remote administration ports",
                speed="Normal",
                port_ranges=["22", "23", "3389", "5900"],
                enable_service_detection=True,
                enable_banner_grabbing=True,
                is_default=True,
            ),
            cls(
                name="Stealth Scan",
                description="Slow and careful scanning",
                speed="Very Slow",
                port_ranges=["1-1024"],
                timeout=5.0,
                max_threads=10,
                is_default=True,
            ),
        ]
