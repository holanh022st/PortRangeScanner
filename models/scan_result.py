"""
Data models for scan results.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class ScanResult:
    """
    Represents the result of scanning a single port on a target.
    
    Attributes:
        host: Target IP or hostname
        port: Port number
        state: Port state (Open, Closed, Filtered, etc.)
        service: Detected service name
        version: Service version (if detected)
        banner: Raw banner data
        risk_level: Risk assessment (Low, Medium, High, Critical)
        response_time: Time taken to scan in seconds
        timestamp: When the scan was performed
        protocol: TCP or UDP
        scan_id: Associated scan session ID
        notes: Additional notes or flags
    """
    host: str
    port: int
    state: str
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    risk_level: str = "Low"
    response_time: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)
    protocol: str = "TCP"
    scan_id: Optional[int] = None
    notes: str = ""
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "host": self.host,
            "port": self.port,
            "state": self.state,
            "service": self.service,
            "version": self.version,
            "banner": self.banner,
            "risk_level": self.risk_level,
            "response_time": self.response_time,
            "timestamp": self.timestamp.isoformat(),
            "protocol": self.protocol,
            "scan_id": self.scan_id,
            "notes": self.notes,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'ScanResult':
        """Create from dictionary."""
        if isinstance(data.get("timestamp"), str):
            data["timestamp"] = datetime.fromisoformat(data["timestamp"])
        return cls(**data)


@dataclass
class ScanSession:
    """
    Represents a complete scan session with metadata.
    
    Attributes:
        id: Unique session ID
        name: User-friendly name
        targets: List of scan targets
        ports: Port specification
        profile_name: Scan profile used
        user: User who ran the scan
        start_time: Scan start timestamp
        end_time: Scan end timestamp
        total_hosts: Total hosts scanned
        total_ports: Total ports scanned
        open_count: Number of open ports found
        closed_count: Number of closed ports
        filtered_count: Number of filtered ports
        status: Running, Completed, Failed, Stopped
        justification: Reason for the scan
        results_hash: Hash for integrity verification
    """
    targets: list
    ports: str
    profile_name: str = "Default"
    user: str = "Unknown"
    name: str = ""
    id: Optional[int] = None
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    total_hosts: int = 0
    total_ports: int = 0
    open_count: int = 0
    closed_count: int = 0
    filtered_count: int = 0
    status: str = "Running"
    justification: str = ""
    results_hash: str = ""
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "targets": self.targets,
            "ports": self.ports,
            "profile_name": self.profile_name,
            "user": self.user,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "total_hosts": self.total_hosts,
            "total_ports": self.total_ports,
            "open_count": self.open_count,
            "closed_count": self.closed_count,
            "filtered_count": self.filtered_count,
            "status": self.status,
            "justification": self.justification,
            "results_hash": self.results_hash,
        }
