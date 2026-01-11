"""
Results view widget for displaying scan results.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QPushButton, QLineEdit, QLabel, QComboBox, QMessageBox
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor

from models.scan_result import ScanResult
from config import STATE_COLORS, RISK_COLORS
from utils.exporters import CSVExporter, JSONExporter, XMLExporter, HTMLExporter, PDFExporter


class ResultsView(QWidget):
    """Widget for displaying and filtering scan results."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.results = []
        self.filtered_results = []
        self.init_ui()
    
    def init_ui(self):
        """Initialize UI."""
        layout = QVBoxLayout()
        
        # Title and filter bar
        header_layout = QHBoxLayout()
        
        title = QLabel("Scan Results")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #007bff;")
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        # Search box
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search...")
        self.search_input.setMaximumWidth(200)
        self.search_input.textChanged.connect(self.filter_results)
        header_layout.addWidget(self.search_input)
        
        # State filter
        self.state_filter = QComboBox()
        self.state_filter.addItems(["All States", "Open", "Closed", "Filtered"])
        self.state_filter.currentTextChanged.connect(self.filter_results)
        header_layout.addWidget(self.state_filter)
        
        # Risk filter
        self.risk_filter = QComboBox()
        self.risk_filter.addItems(["All Risks", "Critical", "High", "Medium", "Low"])
        self.risk_filter.currentTextChanged.connect(self.filter_results)
        header_layout.addWidget(self.risk_filter)
        
        layout.addLayout(header_layout)
        
        # Results table
        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels([
            "Host", "Port", "State", "Protocol", "Service", "Version", "Risk", "Response Time"
        ])
        
        # Configure table
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        
        # Set column widths
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)  # Host
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)  # Port
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)  # State
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)  # Protocol
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)  # Service
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)  # Version
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)  # Risk
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)  # Response Time
        
        layout.addWidget(self.table)
        
        # Statistics bar
        stats_layout = QHBoxLayout()
        
        self.stats_label = QLabel("No results")
        self.stats_label.setStyleSheet("color: #888888;")
        stats_layout.addWidget(self.stats_label)
        
        stats_layout.addStretch()
        
        # Export button
        export_btn = QPushButton("Export")
        export_btn.clicked.connect(self.export_dialog)
        stats_layout.addWidget(export_btn)
        
        layout.addLayout(stats_layout)
        
        self.setLayout(layout)
    
    def set_results(self, results: list):
        """Set scan results to display."""
        self.results = results
        self.filtered_results = results
        self.update_table()
        self.update_statistics()
    
    def update_table(self):
        """Update table with current filtered results."""
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        
        for i, result in enumerate(self.filtered_results):
            self.table.insertRow(i)
            
            # Host
            host_item = QTableWidgetItem(result.host)
            self.table.setItem(i, 0, host_item)
            
            # Port
            port_item = QTableWidgetItem(str(result.port))
            port_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(i, 1, port_item)
            
            # State
            state_item = QTableWidgetItem(result.state)
            state_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            # Color code by state
            state_color = STATE_COLORS.get(result.state, "#ffffff")
            state_item.setBackground(QColor(state_color))
            state_item.setForeground(QColor("#000000"))
            self.table.setItem(i, 2, state_item)
            
            # Protocol
            protocol_item = QTableWidgetItem(result.protocol)
            protocol_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(i, 3, protocol_item)
            
            # Service
            service_item = QTableWidgetItem(result.service or "-")
            self.table.setItem(i, 4, service_item)
            
            # Version
            version_item = QTableWidgetItem(result.version or "-")
            self.table.setItem(i, 5, version_item)
            
            # Risk
            risk_item = QTableWidgetItem(result.risk_level)
            risk_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            # Color code by risk
            risk_color = RISK_COLORS.get(result.risk_level, "#ffffff")
            risk_item.setBackground(QColor(risk_color))
            risk_item.setForeground(QColor("#000000" if result.risk_level in ["Low", "Info"] else "#ffffff"))
            self.table.setItem(i, 6, risk_item)
            
            # Response Time
            time_item = QTableWidgetItem(f"{result.response_time:.3f}s")
            time_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(i, 7, time_item)
        
        self.table.setSortingEnabled(True)
    
    def filter_results(self):
        """Filter results based on search and filters."""
        search_text = self.search_input.text().lower()
        state_filter = self.state_filter.currentText()
        risk_filter = self.risk_filter.currentText()
        
        self.filtered_results = []
        
        for result in self.results:
            # Search filter
            if search_text:
                searchable = f"{result.host} {result.port} {result.service or ''} {result.version or ''}".lower()
                if search_text not in searchable:
                    continue
            
            # State filter
            if state_filter != "All States" and result.state != state_filter:
                continue
            
            # Risk filter
            if risk_filter != "All Risks" and result.risk_level != risk_filter:
                continue
            
            self.filtered_results.append(result)
        
        self.update_table()
        self.update_statistics()
    
    def update_statistics(self):
        """Update statistics label."""
        if not self.results:
            self.stats_label.setText("No results")
            return
        
        total = len(self.results)
        filtered = len(self.filtered_results)
        
        open_count = sum(1 for r in self.filtered_results if r.state == "Open")
        closed_count = sum(1 for r in self.filtered_results if r.state == "Closed")
        
        critical_count = sum(1 for r in self.filtered_results if r.risk_level == "Critical")
        high_count = sum(1 for r in self.filtered_results if r.risk_level == "High")
        
        text = f"Showing {filtered} of {total} results | "
        text += f"Open: {open_count}, Closed: {closed_count} | "
        text += f"Critical: {critical_count}, High: {high_count}"
        
        self.stats_label.setText(text)
    
    def has_results(self) -> bool:
        """Check if there are results to export."""
        return len(self.results) > 0
    
    def export_dialog(self):
        """Show export dialog."""
        from PyQt6.QtWidgets import QFileDialog
        
        if not self.has_results():
            QMessageBox.information(self, "No Results", "No results to export")
            return
        
        file_path, file_type = QFileDialog.getSaveFileName(
            self,
            "Export Results",
            "",
            "CSV Files (*.csv);;JSON Files (*.json);;XML Files (*.xml);;HTML Files (*.html);;PDF Files (*.pdf)"
        )
        
        if file_path:
            self.export_results(file_path, file_type)
    
    def export_results(self, file_path: str, file_type: str) -> bool:
        """
        Export results to file.
        
        Args:
            file_path: Output file path
            file_type: File type filter string
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Determine format from file type
            if "CSV" in file_type or file_path.endswith('.csv'):
                success = CSVExporter.export(self.filtered_results, file_path)
            elif "JSON" in file_type or file_path.endswith('.json'):
                success = JSONExporter.export(self.filtered_results, file_path)
            elif "XML" in file_type or file_path.endswith('.xml'):
                success = XMLExporter.export(self.filtered_results, file_path)
            elif "HTML" in file_type or file_path.endswith('.html'):
                success = HTMLExporter.export(self.filtered_results, file_path)
            elif "PDF" in file_type or file_path.endswith('.pdf'):
                success = PDFExporter.export(self.filtered_results, file_path)
            else:
                # Default to CSV
                success = CSVExporter.export(self.filtered_results, file_path)
            
            if success:
                QMessageBox.information(self, "Success", f"Results exported to {file_path}")
            else:
                QMessageBox.critical(self, "Error", "Export failed")
            
            return success
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Export failed: {e}")
            return False
