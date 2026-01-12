"""
Unit tests for validators module.
"""

import unittest
from utils.validators import (
    validate_ip, validate_cidr, validate_hostname, validate_port,
    validate_port_range, parse_port_list, is_private_ip, sanitize_input
)


class TestValidators(unittest.TestCase):
    """Test validation functions."""
    
    def test_validate_ip(self):
        """Test IP address validation."""
        self.assertTrue(validate_ip("127.0.0.1"))
        self.assertTrue(validate_ip("192.168.1.1"))
        self.assertTrue(validate_ip("8.8.8.8"))
        self.assertFalse(validate_ip("256.1.1.1"))
        self.assertFalse(validate_ip("invalid"))
        self.assertFalse(validate_ip(""))
    
    def test_validate_cidr(self):
        """Test CIDR validation."""
        self.assertTrue(validate_cidr("192.168.1.0/24"))
        self.assertTrue(validate_cidr("10.0.0.0/8"))
        self.assertTrue(validate_cidr("172.16.0.0/12"))
        self.assertTrue(validate_cidr("192.168.1.0"))  # Valid IP, treated as /32
        self.assertFalse(validate_cidr("invalid/24"))
    
    def test_validate_hostname(self):
        """Test hostname validation."""
        self.assertTrue(validate_hostname("example.com"))
        self.assertTrue(validate_hostname("sub.example.com"))
        self.assertTrue(validate_hostname("localhost"))
        self.assertFalse(validate_hostname(""))
        self.assertFalse(validate_hostname("a" * 300))
    
    def test_validate_port(self):
        """Test port number validation."""
        self.assertTrue(validate_port(1))
        self.assertTrue(validate_port(80))
        self.assertTrue(validate_port(65535))
        self.assertFalse(validate_port(0))
        self.assertFalse(validate_port(65536))
        self.assertFalse(validate_port(-1))
    
    def test_validate_port_range(self):
        """Test port range validation."""
        is_valid, _ = validate_port_range("80")
        self.assertTrue(is_valid)
        
        is_valid, _ = validate_port_range("1-1024")
        self.assertTrue(is_valid)
        
        is_valid, _ = validate_port_range("80,443,8080")
        self.assertTrue(is_valid)
        
        is_valid, _ = validate_port_range("99999")
        self.assertFalse(is_valid)
        
        is_valid, _ = validate_port_range("invalid")
        self.assertFalse(is_valid)
    
    def test_parse_port_list(self):
        """Test port list parsing."""
        ports = parse_port_list("80")
        self.assertEqual(ports, [80])
        
        ports = parse_port_list("80,443,8080")
        self.assertEqual(sorted(ports), [80, 443, 8080])
        
        ports = parse_port_list("1-5")
        self.assertEqual(ports, [1, 2, 3, 4, 5])
    
    def test_is_private_ip(self):
        """Test private IP detection."""
        self.assertTrue(is_private_ip("127.0.0.1"))
        self.assertTrue(is_private_ip("192.168.1.1"))
        self.assertTrue(is_private_ip("10.0.0.1"))
        self.assertFalse(is_private_ip("8.8.8.8"))
        self.assertFalse(is_private_ip("1.1.1.1"))
    
    def test_sanitize_input(self):
        """Test input sanitization."""
        result = sanitize_input("normal text")
        self.assertEqual(result, "normal text")
        
        result = sanitize_input("a" * 2000, max_length=100)
        self.assertEqual(len(result), 100)


if __name__ == "__main__":
    unittest.main()
