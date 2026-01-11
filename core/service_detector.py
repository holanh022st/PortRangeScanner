"""
Service detection module for identifying services on open ports.
"""

import socket
from typing import Optional, Dict

from config import SERVICE_TIMEOUT
from utils.logger import scanner_logger


# Common port-to-service mappings
SERVICE_MAPPINGS = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    587: "smtp-submission",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    27017: "mongodb",
}


class ServiceDetector:
    """
    Detects services running on open ports.
    """
    
    @staticmethod
    def detect_service(host: str, port: int, banner: str = None) -> Dict[str, Optional[str]]:
        """
        Detect service type and version.
        
        Args:
            host: Target host
            port: Port number
            banner: Optional banner string
            
        Returns:
            Dictionary with 'service', 'version', and 'confidence' keys
        """
        result = {
            "service": None,
            "version": None,
            "confidence": "low"
        }
        
        # First, try port-based detection
        if port in SERVICE_MAPPINGS:
            result["service"] = SERVICE_MAPPINGS[port]
            result["confidence"] = "medium"
        
        # If we have a banner, try banner-based detection
        if banner:
            service, version = ServiceDetector._detect_from_banner(banner, port)
            if service:
                result["service"] = service
                result["confidence"] = "high"
            if version:
                result["version"] = version
        
        return result
    
    @staticmethod
    def _detect_from_banner(banner: str, port: int) -> tuple:
        """
        Detect service and version from banner.
        
        Args:
            banner: Banner string
            port: Port number
            
        Returns:
            Tuple of (service, version)
        """
        service = None
        version = None
        banner_lower = banner.lower()
        
        # HTTP detection
        if "http" in banner_lower or "html" in banner_lower:
            service = "http" if port != 443 else "https"
            if "apache" in banner_lower:
                service = "apache"
                # Try to extract version
                if "apache/" in banner_lower:
                    try:
                        version = banner.split("Apache/")[1].split()[0]
                    except:
                        pass
            elif "nginx" in banner_lower:
                service = "nginx"
                if "nginx/" in banner_lower:
                    try:
                        version = banner.split("nginx/")[1].split()[0]
                    except:
                        pass
            elif "iis" in banner_lower:
                service = "iis"
        
        # SSH detection
        elif "ssh" in banner_lower:
            service = "ssh"
            if "openssh" in banner_lower:
                service = "openssh"
                try:
                    version = banner.split("OpenSSH_")[1].split()[0]
                except:
                    pass
        
        # FTP detection
        elif "ftp" in banner_lower:
            service = "ftp"
            if "vsftpd" in banner_lower:
                service = "vsftpd"
            elif "proftpd" in banner_lower:
                service = "proftpd"
        
        # SMTP detection
        elif "smtp" in banner_lower or "mail" in banner_lower:
            service = "smtp"
            if "postfix" in banner_lower:
                service = "postfix"
            elif "sendmail" in banner_lower:
                service = "sendmail"
            elif "exim" in banner_lower:
                service = "exim"
        
        # Database detection
        elif "mysql" in banner_lower:
            service = "mysql"
            try:
                # MySQL version is often in the banner
                if "5." in banner or "8." in banner:
                    version = banner.split()[0]
            except:
                pass
        
        elif "postgresql" in banner_lower:
            service = "postgresql"
        
        elif "mongodb" in banner_lower:
            service = "mongodb"
        
        elif "redis" in banner_lower:
            service = "redis"
        
        # Remote access
        elif "vnc" in banner_lower or "rfb" in banner_lower:
            service = "vnc"
        
        elif "rdp" in banner_lower or "terminal" in banner_lower:
            service = "rdp"
        
        # DNS
        elif port == 53:
            service = "dns"
        
        return service, version
    
    @staticmethod
    def get_service_description(service: str) -> str:
        """
        Get a human-readable description of the service.
        
        Args:
            service: Service name
            
        Returns:
            Service description
        """
        descriptions = {
            "http": "Web Server (HTTP)",
            "https": "Secure Web Server (HTTPS)",
            "ssh": "Secure Shell",
            "ftp": "File Transfer Protocol",
            "smtp": "Mail Transfer Protocol",
            "pop3": "Mail Retrieval Protocol",
            "imap": "Mail Access Protocol",
            "dns": "Domain Name System",
            "mysql": "MySQL Database",
            "postgresql": "PostgreSQL Database",
            "mongodb": "MongoDB Database",
            "redis": "Redis Cache",
            "rdp": "Remote Desktop Protocol",
            "vnc": "Virtual Network Computing",
            "smb": "Server Message Block",
            "telnet": "Telnet (Unencrypted Remote Access)",
        }
        
        return descriptions.get(service, service or "Unknown Service")
