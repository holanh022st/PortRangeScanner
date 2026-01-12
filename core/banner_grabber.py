"""
Banner grabbing module for retrieving service banners.
"""

import socket
from typing import Optional

from config import BANNER_MAX_BYTES, SERVICE_TIMEOUT
from utils.logger import scanner_logger


class BannerGrabber:
    """
    Grabs service banners from open ports.
    """
    
    @staticmethod
    def grab_banner(host: str, port: int, timeout: float = SERVICE_TIMEOUT) -> Optional[str]:
        """
        Grab banner from an open port.
        
        Args:
            host: Target host
            port: Port number
            timeout: Connection timeout
            
        Returns:
            Banner string or None
        """
        banner = None
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # Try to receive banner (some services send it immediately)
            try:
                banner = sock.recv(BANNER_MAX_BYTES).decode('utf-8', errors='ignore').strip()
            except socket.timeout:
                # No immediate banner, try sending a probe
                banner = BannerGrabber._probe_service(sock, port)
            
            sock.close()
            
        except Exception as e:
            scanner_logger.debug(f"Banner grab failed for {host}:{port} - {e}")
        
        return banner if banner else None
    
    @staticmethod
    def _probe_service(sock: socket.socket, port: int) -> Optional[str]:
        """
        Send service-specific probes to elicit a banner.
        
        Args:
            sock: Connected socket
            port: Port number
            
        Returns:
            Banner string or None
        """
        banner = None
        
        try:
            # HTTP probe
            if port in [80, 8080, 8000, 8888]:
                sock.send(b"GET / HTTP/1.0\r\n\r\n")
                banner = sock.recv(BANNER_MAX_BYTES).decode('utf-8', errors='ignore').strip()
            
            # HTTPS probe
            elif port in [443, 8443]:
                # For HTTPS, we'd need SSL/TLS, so skip for now
                pass
            
            # SMTP probe
            elif port == 25 or port == 587:
                sock.send(b"EHLO example.com\r\n")
                banner = sock.recv(BANNER_MAX_BYTES).decode('utf-8', errors='ignore').strip()
            
            # FTP probe
            elif port == 21:
                # FTP usually sends banner immediately, but try USER command
                sock.send(b"USER anonymous\r\n")
                banner = sock.recv(BANNER_MAX_BYTES).decode('utf-8', errors='ignore').strip()
            
            # POP3 probe
            elif port == 110:
                sock.send(b"CAPA\r\n")
                banner = sock.recv(BANNER_MAX_BYTES).decode('utf-8', errors='ignore').strip()
            
            # IMAP probe
            elif port == 143:
                sock.send(b"A001 CAPABILITY\r\n")
                banner = sock.recv(BANNER_MAX_BYTES).decode('utf-8', errors='ignore').strip()
            
            # Generic probe (newline)
            else:
                sock.send(b"\r\n")
                banner = sock.recv(BANNER_MAX_BYTES).decode('utf-8', errors='ignore').strip()
        
        except Exception as e:
            scanner_logger.debug(f"Service probe failed on port {port} - {e}")
        
        return banner if banner else None
    
    @staticmethod
    def sanitize_banner(banner: str) -> str:
        """
        Sanitize banner for safe display and logging.
        
        Args:
            banner: Raw banner string
            
        Returns:
            Sanitized banner
        """
        if not banner:
            return ""
        
        # Remove control characters except newline
        sanitized = ''.join(char for char in banner if char.isprintable() or char == '\n')
        
        # Truncate if too long
        if len(sanitized) > 500:
            sanitized = sanitized[:500] + "..."
        
        # Remove excessive whitespace
        sanitized = ' '.join(sanitized.split())
        
        return sanitized
