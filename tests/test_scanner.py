"""
Unit tests for scanner engine.
"""

import unittest
from core.scanner_engine import PortScanner
from models.scan_result import ScanResult


class TestScannerEngine(unittest.TestCase):
    """Test scanner engine functionality."""
    
    def test_scanner_initialization(self):
        """Test scanner initialization with parameters."""
        scanner = PortScanner(
            timeout=2.0,
            max_threads=50,
            retries=1
        )
        
        self.assertEqual(scanner.timeout, 2.0)
        self.assertEqual(scanner.max_threads, 50)
        self.assertEqual(scanner.retries, 1)
    
    def test_localhost_scan(self):
        """Test scanning localhost."""
        scanner = PortScanner(timeout=0.5, max_threads=5)
        
        results = scanner.scan(
            hosts=["127.0.0.1"],
            ports=[22, 80],
            protocol="TCP"
        )
        
        # Should get 2 results (one for each port)
        self.assertEqual(len(results), 2)
        
        # Each result should be a ScanResult
        for result in results:
            self.assertIsInstance(result, ScanResult)
            self.assertEqual(result.host, "127.0.0.1")
            self.assertIn(result.port, [22, 80])
            self.assertIn(result.state, ["Open", "Closed", "Filtered", "Timeout"])
    
    def test_stop_functionality(self):
        """Test scan stop functionality."""
        scanner = PortScanner(timeout=1.0, max_threads=10)
        
        # Stop immediately
        scanner.stop()
        
        self.assertTrue(scanner.stop_flag.is_set())


if __name__ == "__main__":
    unittest.main()
