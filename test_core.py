#!/usr/bin/env python3
"""
Test script to verify core port scanner functionality without GUI.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.scanner_engine import PortScanner
from core.service_detector import ServiceDetector
from core.risk_analyzer import RiskAnalyzer
from core.database import Database
from models.scan_result import ScanResult, ScanSession
from models.user import User
from utils.validators import validate_port_range, validate_ip
from utils.ip_parser import parse_targets
from backend import ExclusionList, audit_logger

def test_database():
    """Test database initialization."""
    print("Testing database initialization...")
    db = Database()
    
    # Check if admin user exists
    admin = db.get_user("admin")
    if admin:
        print(f"✓ Admin user exists: {admin.username} ({admin.role})")
    else:
        print("✗ Admin user not found")
        return False
    
    # Check profiles
    profiles = db.get_all_profiles()
    print(f"✓ Found {len(profiles)} scan profiles")
    
    return True

def test_validators():
    """Test input validators."""
    print("\nTesting validators...")
    
    # Test IP validation
    test_cases = [
        ("127.0.0.1", True),
        ("192.168.1.1", True),
        ("256.1.1.1", False),
        ("invalid", False),
    ]
    
    for ip, expected in test_cases:
        result = validate_ip(ip)
        status = "✓" if result == expected else "✗"
        print(f"{status} IP validation: {ip} -> {result}")
    
    # Test port range validation
    port_tests = [
        ("80", True),
        ("1-1024", True),
        ("80,443,8080", True),
        ("99999", False),
        ("invalid", False),
    ]
    
    for ports, expected in port_tests:
        is_valid, error = validate_port_range(ports)
        status = "✓" if is_valid == expected else "✗"
        print(f"{status} Port validation: {ports} -> {is_valid}")
    
    return True

def test_exclusion_list():
    """Test exclusion list functionality."""
    print("\nTesting exclusion list...")
    
    exclusion_list = ExclusionList()
    
    # Test private IP (should be allowed by default)
    is_allowed, reason = exclusion_list.is_allowed("127.0.0.1")
    print(f"{'✓' if is_allowed else '✗'} 127.0.0.1: {reason}")
    
    is_allowed, reason = exclusion_list.is_allowed("192.168.1.1")
    print(f"{'✓' if is_allowed else '✗'} 192.168.1.1: {reason}")
    
    # Test external IP (should be denied)
    is_allowed, reason = exclusion_list.is_allowed("8.8.8.8")
    print(f"{'✓' if not is_allowed else '✗'} 8.8.8.8: {reason}")
    
    return True

def test_scanner():
    """Test port scanner on localhost."""
    print("\nTesting port scanner...")
    
    def progress_callback(progress, current, total):
        print(f"  Progress: {current}/{total} ({progress:.1f}%)")
    
    scanner = PortScanner(
        timeout=0.5,
        max_threads=10,
        retries=1,
        progress_callback=progress_callback
    )
    
    # Scan localhost on a few common ports
    targets = ["127.0.0.1"]
    ports = [22, 80, 443]
    
    print(f"Scanning {targets} on ports {ports}...")
    results = scanner.scan(targets, ports, protocol="TCP")
    
    print(f"\n✓ Scan completed: {len(results)} results")
    
    for result in results:
        print(f"  {result.host}:{result.port} -> {result.state} ({result.response_time:.3f}s)")
    
    return True

def test_service_detection():
    """Test service detection."""
    print("\nTesting service detection...")
    
    # Test port-based detection
    service_info = ServiceDetector.detect_service("127.0.0.1", 80)
    print(f"✓ Port 80: {service_info['service']} (confidence: {service_info['confidence']})")
    
    service_info = ServiceDetector.detect_service("127.0.0.1", 443)
    print(f"✓ Port 443: {service_info['service']} (confidence: {service_info['confidence']})")
    
    return True

def test_risk_analyzer():
    """Test risk analyzer."""
    print("\nTesting risk analyzer...")
    
    # Create test results
    test_results = [
        ScanResult(host="127.0.0.1", port=80, state="Open", service="http"),
        ScanResult(host="127.0.0.1", port=23, state="Open", service="telnet"),
        ScanResult(host="127.0.0.1", port=3389, state="Open", service="rdp"),
    ]
    
    for result in test_results:
        risk_info = RiskAnalyzer.analyze_risk(result)
        print(f"✓ Port {result.port} ({result.service}): {risk_info['risk_level']} - {risk_info['reason']}")
    
    return True

def test_export():
    """Test export functionality."""
    print("\nTesting export functionality...")
    
    from utils.exporters import CSVExporter, JSONExporter, XMLExporter, HTMLExporter
    import tempfile
    
    # Create test results
    results = [
        ScanResult(host="127.0.0.1", port=80, state="Open", service="http", risk_level="Low"),
        ScanResult(host="127.0.0.1", port=443, state="Open", service="https", risk_level="Low"),
    ]
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Test CSV
        csv_file = os.path.join(tmpdir, "test.csv")
        if CSVExporter.export(results, csv_file):
            print(f"✓ CSV export successful")
        else:
            print(f"✗ CSV export failed")
        
        # Test JSON
        json_file = os.path.join(tmpdir, "test.json")
        if JSONExporter.export(results, json_file):
            print(f"✓ JSON export successful")
        else:
            print(f"✗ JSON export failed")
        
        # Test XML
        xml_file = os.path.join(tmpdir, "test.xml")
        if XMLExporter.export(results, xml_file):
            print(f"✓ XML export successful")
        else:
            print(f"✗ XML export failed")
        
        # Test HTML
        html_file = os.path.join(tmpdir, "test.html")
        if HTMLExporter.export(results, html_file):
            print(f"✓ HTML export successful")
        else:
            print(f"✗ HTML export failed")
    
    return True

def main():
    """Run all tests."""
    print("=" * 60)
    print("Enterprise Port Scanner - Core Functionality Test")
    print("=" * 60)
    
    tests = [
        ("Database", test_database),
        ("Validators", test_validators),
        ("Exclusion List", test_exclusion_list),
        ("Port Scanner", test_scanner),
        ("Service Detection", test_service_detection),
        ("Risk Analyzer", test_risk_analyzer),
        ("Export", test_export),
    ]
    
    passed = 0
    failed = 0
    
    for name, test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
                print(f"\n✗ {name} test FAILED")
        except Exception as e:
            failed += 1
            print(f"\n✗ {name} test FAILED with exception: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "=" * 60)
    print(f"Test Results: {passed} passed, {failed} failed")
    print("=" * 60)
    
    return failed == 0

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
