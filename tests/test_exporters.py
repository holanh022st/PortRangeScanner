"""
Unit tests for exporters.
"""

import unittest
import tempfile
import os
from utils.exporters import CSVExporter, JSONExporter, XMLExporter, HTMLExporter
from models.scan_result import ScanResult


class TestExporters(unittest.TestCase):
    """Test export functionality."""
    
    def setUp(self):
        """Set up test data."""
        self.test_results = [
            ScanResult(
                host="127.0.0.1",
                port=80,
                state="Open",
                service="http",
                risk_level="Low"
            ),
            ScanResult(
                host="127.0.0.1",
                port=443,
                state="Open",
                service="https",
                risk_level="Low"
            ),
        ]
    
    def test_csv_export(self):
        """Test CSV export."""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "test.csv")
            success = CSVExporter.export(self.test_results, file_path)
            
            self.assertTrue(success)
            self.assertTrue(os.path.exists(file_path))
            
            # Check file content
            with open(file_path, 'r') as f:
                content = f.read()
                self.assertIn("127.0.0.1", content)
                self.assertIn("80", content)
                self.assertIn("http", content)
    
    def test_json_export(self):
        """Test JSON export."""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "test.json")
            success = JSONExporter.export(self.test_results, file_path)
            
            self.assertTrue(success)
            self.assertTrue(os.path.exists(file_path))
    
    def test_xml_export(self):
        """Test XML export."""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "test.xml")
            success = XMLExporter.export(self.test_results, file_path)
            
            self.assertTrue(success)
            self.assertTrue(os.path.exists(file_path))
    
    def test_html_export(self):
        """Test HTML export."""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "test.html")
            success = HTMLExporter.export(self.test_results, file_path)
            
            self.assertTrue(success)
            self.assertTrue(os.path.exists(file_path))
            
            # Check HTML content
            with open(file_path, 'r') as f:
                content = f.read()
                self.assertIn("<!DOCTYPE html>", content)
                self.assertIn("127.0.0.1", content)


if __name__ == "__main__":
    unittest.main()
