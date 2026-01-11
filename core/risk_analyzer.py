"""
Risk analysis module for assessing security risks of scan results.
"""

from typing import Dict
from models.scan_result import ScanResult
from config import (
    RISK_CRITICAL, RISK_HIGH, RISK_MEDIUM, RISK_LOW, RISK_INFO,
    HIGH_RISK_SERVICES, ADMIN_SERVICES, LEGACY_PROTOCOLS, PORT_STATE_OPEN
)


class RiskAnalyzer:
    """
    Analyzes scan results to determine security risk levels.
    """
    
    # Critical risk ports (often targeted)
    CRITICAL_PORTS = {
        23: "Telnet - Unencrypted remote access",
        445: "SMB - Vulnerable to ransomware attacks",
        3389: "RDP - Common brute-force target",
        1433: "MSSQL - Database exposure",
        3306: "MySQL - Database exposure",
        5432: "PostgreSQL - Database exposure",
        27017: "MongoDB - Database exposure (often misconfigured)",
    }
    
    # High risk ports
    HIGH_RISK_PORTS = {
        21: "FTP - Unencrypted file transfer",
        22: "SSH - Admin access (should be restricted)",
        25: "SMTP - Mail relay abuse potential",
        53: "DNS - DDoS amplification risk",
        135: "RPC - Windows remote procedure calls",
        139: "NetBIOS - Legacy Windows networking",
        443: "HTTPS - Check for vulnerabilities",
        5900: "VNC - Remote desktop",
        6379: "Redis - Often exposed without auth",
    }
    
    @staticmethod
    def analyze_risk(result: ScanResult) -> Dict[str, str]:
        """
        Analyze risk level of a scan result.
        
        Args:
            result: Scan result to analyze
            
        Returns:
            Dictionary with 'risk_level', 'reason', and 'recommendation' keys
        """
        # Only assess open ports
        if result.state != PORT_STATE_OPEN:
            return {
                "risk_level": RISK_INFO,
                "reason": "Port is not open",
                "recommendation": "No action needed"
            }
        
        risk_level = RISK_LOW
        reason = "Open port detected"
        recommendation = "Monitor this port"
        
        # Check critical ports
        if result.port in RiskAnalyzer.CRITICAL_PORTS:
            risk_level = RISK_CRITICAL
            reason = RiskAnalyzer.CRITICAL_PORTS[result.port]
            recommendation = "Immediately restrict or disable this service"
        
        # Check high risk ports
        elif result.port in RiskAnalyzer.HIGH_RISK_PORTS:
            risk_level = RISK_HIGH
            reason = RiskAnalyzer.HIGH_RISK_PORTS[result.port]
            recommendation = "Restrict access and ensure proper security controls"
        
        # Service-based analysis
        if result.service:
            service_lower = result.service.lower()
            
            # High-risk services
            if any(hrs in service_lower for hrs in HIGH_RISK_SERVICES):
                if risk_level == RISK_LOW:
                    risk_level = RISK_HIGH
                reason += f" - High-risk service: {result.service}"
                recommendation = "Review security configuration and access controls"
            
            # Admin services exposed
            if any(adm in service_lower for adm in ADMIN_SERVICES):
                if risk_level in [RISK_LOW, RISK_MEDIUM]:
                    risk_level = RISK_HIGH
                reason += f" - Admin service exposed: {result.service}"
                recommendation = "Restrict to internal networks only"
            
            # Legacy/unencrypted protocols
            if any(leg in service_lower for leg in LEGACY_PROTOCOLS):
                if risk_level == RISK_LOW:
                    risk_level = RISK_MEDIUM
                reason += f" - Legacy/unencrypted protocol: {result.service}"
                recommendation = "Upgrade to encrypted alternative"
        
        # Version-based analysis
        if result.version:
            # Check for very old versions (basic heuristic)
            if any(old in result.version.lower() for old in ["1.0", "2.0", "0.9"]):
                if risk_level == RISK_LOW:
                    risk_level = RISK_MEDIUM
                reason += " - Potentially outdated version"
                recommendation += ". Update to latest version."
        
        # Port range analysis
        if result.port < 1024:
            # System ports - should be carefully managed
            if risk_level == RISK_LOW:
                risk_level = RISK_MEDIUM
                reason += " - System port exposed"
        
        # Common web ports with low risk if no other issues
        if result.port in [80, 443, 8080, 8443] and risk_level == RISK_LOW:
            reason = "Common web port - verify security configuration"
            recommendation = "Ensure HTTPS, check for vulnerabilities"
        
        return {
            "risk_level": risk_level,
            "reason": reason,
            "recommendation": recommendation
        }
    
    @staticmethod
    def get_risk_score(risk_level: str) -> int:
        """
        Convert risk level to numeric score.
        
        Args:
            risk_level: Risk level string
            
        Returns:
            Numeric score (0-100)
        """
        scores = {
            RISK_CRITICAL: 100,
            RISK_HIGH: 75,
            RISK_MEDIUM: 50,
            RISK_LOW: 25,
            RISK_INFO: 0,
        }
        return scores.get(risk_level, 0)
    
    @staticmethod
    def aggregate_risks(results: list) -> Dict:
        """
        Aggregate risk statistics from scan results.
        
        Args:
            results: List of scan results
            
        Returns:
            Dictionary with risk statistics
        """
        stats = {
            RISK_CRITICAL: 0,
            RISK_HIGH: 0,
            RISK_MEDIUM: 0,
            RISK_LOW: 0,
            RISK_INFO: 0,
            "total_open": 0,
            "average_score": 0,
        }
        
        total_score = 0
        
        for result in results:
            if result.state == PORT_STATE_OPEN:
                stats["total_open"] += 1
                stats[result.risk_level] += 1
                total_score += RiskAnalyzer.get_risk_score(result.risk_level)
        
        if stats["total_open"] > 0:
            stats["average_score"] = total_score / stats["total_open"]
        
        return stats
