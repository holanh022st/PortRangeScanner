"""
Dashboard widget for scan configuration and execution.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit,
    QLineEdit, QPushButton, QProgressBar, QGroupBox, QComboBox,
    QSpinBox, QCheckBox, QMessageBox
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread
from datetime import datetime

from core.scanner_engine import PortScanner
from core.service_detector import ServiceDetector
from core.banner_grabber import BannerGrabber
from core.risk_analyzer import RiskAnalyzer
from models.scan_result import ScanResult
from utils.validators import validate_port_range, parse_port_list
from utils.ip_parser import parse_targets
from backend import default_exclusion_list


class ScanThread(QThread):
    """Worker thread for scanning."""
    
    progress_updated = pyqtSignal(float, int, int)
    scan_completed = pyqtSignal(list)
    
    def __init__(self, targets, ports, config, parent=None):
        super().__init__(parent)
        self.targets = targets
        self.ports = ports
        self.config = config
        self.scanner = None
    
    def run(self):
        """Run scan in thread."""
        # Create scanner
        self.scanner = PortScanner(
            timeout=self.config.get('timeout', 2.0),
            max_threads=self.config.get('max_threads', 50),
            retries=self.config.get('retries', 1),
            progress_callback=self.progress_callback
        )
        
        # Perform scan
        results = self.scanner.scan(
            self.targets,
            self.ports,
            protocol=self.config.get('protocol', 'TCP')
        )
        
        # Enhance results with service detection and risk analysis
        enhanced_results = []
        for result in results:
            if result.state == "Open":
                # Service detection
                if self.config.get('enable_service_detection', True):
                    banner = None
                    if self.config.get('enable_banner_grabbing', True):
                        banner = BannerGrabber.grab_banner(result.host, result.port)
                        result.banner = banner
                    
                    service_info = ServiceDetector.detect_service(result.host, result.port, banner)
                    result.service = service_info['service']
                    result.version = service_info['version']
                
                # Risk analysis
                risk_info = RiskAnalyzer.analyze_risk(result)
                result.risk_level = risk_info['risk_level']
                result.notes = risk_info['reason']
            
            enhanced_results.append(result)
        
        self.scan_completed.emit(enhanced_results)
    
    def progress_callback(self, progress, current, total):
        """Progress callback from scanner."""
        self.progress_updated.emit(progress, current, total)
    
    def stop(self):
        """Stop scanning."""
        if self.scanner:
            self.scanner.stop()


class DashboardWidget(QWidget):
    """Dashboard for scan configuration and execution."""
    
    scan_started = pyqtSignal()
    scan_completed = pyqtSignal(list)
    scan_progress = pyqtSignal(float, int, int)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scan_thread = None
        self.init_ui()
    
    def init_ui(self):
        """Initialize UI."""
        layout = QVBoxLayout()
        layout.setSpacing(15)
        
        # Title
        title = QLabel("Port Scanner Dashboard")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #007bff;")
        layout.addWidget(title)
        
        # Target configuration
        target_group = QGroupBox("Target Configuration")
        target_layout = QVBoxLayout()
        
        target_label = QLabel("Targets (IP addresses, CIDR ranges, or hostnames):")
        target_layout.addWidget(target_label)
        
        self.target_input = QTextEdit()
        self.target_input.setPlaceholderText("127.0.0.1\n192.168.1.0/24\nexample.com")
        self.target_input.setMaximumHeight(100)
        target_layout.addWidget(self.target_input)
        
        target_group.setLayout(target_layout)
        layout.addWidget(target_group)
        
        # Port configuration
        port_group = QGroupBox("Port Configuration")
        port_layout = QVBoxLayout()
        
        port_label = QLabel("Ports (single, range, or comma-separated):")
        port_layout.addWidget(port_label)
        
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("80,443,8080 or 1-1024")
        port_layout.addWidget(self.port_input)
        
        # Port presets
        preset_layout = QHBoxLayout()
        preset_label = QLabel("Presets:")
        preset_layout.addWidget(preset_label)
        
        web_btn = QPushButton("Web")
        web_btn.clicked.connect(lambda: self.port_input.setText("80,443,8080,8443"))
        preset_layout.addWidget(web_btn)
        
        remote_btn = QPushButton("Remote")
        remote_btn.clicked.connect(lambda: self.port_input.setText("22,23,3389,5900"))
        preset_layout.addWidget(remote_btn)
        
        db_btn = QPushButton("Databases")
        db_btn.clicked.connect(lambda: self.port_input.setText("3306,5432,1433,27017"))
        preset_layout.addWidget(db_btn)
        
        common_btn = QPushButton("Common")
        common_btn.clicked.connect(lambda: self.port_input.setText("21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080"))
        preset_layout.addWidget(common_btn)
        
        port_layout.addLayout(preset_layout)
        port_group.setLayout(port_layout)
        layout.addWidget(port_group)
        
        # Scan options
        options_group = QGroupBox("Scan Options")
        options_layout = QVBoxLayout()
        
        # Speed and threading
        speed_layout = QHBoxLayout()
        speed_layout.addWidget(QLabel("Speed:"))
        
        self.speed_combo = QComboBox()
        self.speed_combo.addItems(["Very Slow", "Slow", "Normal", "Fast", "Very Fast"])
        self.speed_combo.setCurrentText("Normal")
        speed_layout.addWidget(self.speed_combo)
        
        speed_layout.addWidget(QLabel("Threads:"))
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 200)
        self.threads_spin.setValue(50)
        speed_layout.addWidget(self.threads_spin)
        
        speed_layout.addWidget(QLabel("Timeout:"))
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 10)
        self.timeout_spin.setValue(2)
        self.timeout_spin.setSuffix("s")
        speed_layout.addWidget(self.timeout_spin)
        
        speed_layout.addStretch()
        options_layout.addLayout(speed_layout)
        
        # Detection options
        detect_layout = QHBoxLayout()
        self.service_check = QCheckBox("Service Detection")
        self.service_check.setChecked(True)
        detect_layout.addWidget(self.service_check)
        
        self.banner_check = QCheckBox("Banner Grabbing")
        self.banner_check.setChecked(True)
        detect_layout.addWidget(self.banner_check)
        
        detect_layout.addStretch()
        options_layout.addLayout(detect_layout)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Progress section
        progress_group = QGroupBox("Scan Progress")
        progress_layout = QVBoxLayout()
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        progress_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("Ready to scan")
        progress_layout.addWidget(self.status_label)
        
        progress_group.setLayout(progress_layout)
        layout.addWidget(progress_group)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("Start Scan")
        self.start_btn.setStyleSheet("background-color: #28a745; padding: 12px 24px; font-size: 14px;")
        self.start_btn.clicked.connect(self.start_scan)
        button_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("Stop Scan")
        self.stop_btn.setStyleSheet("background-color: #dc3545; padding: 12px 24px; font-size: 14px;")
        self.stop_btn.clicked.connect(self.stop_scan)
        self.stop_btn.setEnabled(False)
        button_layout.addWidget(self.stop_btn)
        
        layout.addLayout(button_layout)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def set_targets(self, targets: str):
        """Set targets in the input field."""
        self.target_input.setPlainText(targets)
    
    def start_scan(self, config=None):
        """Start port scan."""
        # Validate inputs
        targets_text = self.target_input.toPlainText().strip()
        ports_text = self.port_input.text().strip()
        
        if not targets_text:
            QMessageBox.warning(self, "Error", "Please enter targets to scan")
            return
        
        if not ports_text:
            QMessageBox.warning(self, "Error", "Please enter ports to scan")
            return
        
        # Parse targets
        targets = parse_targets(targets_text)
        if not targets:
            QMessageBox.critical(self, "Error", "No valid targets found")
            return
        
        # Validate targets against exclusion list
        valid_targets, invalid_targets = default_exclusion_list.validate_targets(targets)
        if invalid_targets:
            msg = "The following targets are not allowed:\n\n"
            for ip, reason in list(invalid_targets.items())[:5]:
                msg += f"• {ip}: {reason}\n"
            if len(invalid_targets) > 5:
                msg += f"\n... and {len(invalid_targets) - 5} more"
            QMessageBox.critical(self, "Access Denied", msg)
            return
        
        if not valid_targets:
            QMessageBox.critical(self, "Error", "No valid targets to scan")
            return
        
        # Validate ports
        is_valid, error = validate_port_range(ports_text)
        if not is_valid:
            QMessageBox.critical(self, "Error", f"Invalid port specification: {error}")
            return
        
        # Parse ports
        try:
            ports = parse_port_list(ports_text)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error parsing ports: {e}")
            return
        
        # Confirm scan
        reply = QMessageBox.question(
            self,
            "Confirm Scan",
            f"Start scan on:\n\n"
            f"Targets: {len(valid_targets)} host(s)\n"
            f"Ports: {len(ports)} port(s)\n"
            f"Total scans: {len(valid_targets) * len(ports)}\n\n"
            f"Do you have permission to scan these targets?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.No:
            return
        
        # Prepare scan config
        if not config:
            config = {
                'timeout': self.timeout_spin.value(),
                'max_threads': self.threads_spin.value(),
                'retries': 1,
                'protocol': 'TCP',
                'enable_service_detection': self.service_check.isChecked(),
                'enable_banner_grabbing': self.banner_check.isChecked(),
            }
        
        # Update UI
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        self.status_label.setText("Starting scan...")
        
        # Create and start scan thread
        self.scan_thread = ScanThread(valid_targets, ports, config, self)
        self.scan_thread.progress_updated.connect(self.on_progress)
        self.scan_thread.scan_completed.connect(self.on_completed)
        self.scan_thread.start()
        
        self.scan_started.emit()
    
    def stop_scan(self):
        """Stop current scan."""
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
            self.scan_thread.wait()
            self.status_label.setText("Scan stopped")
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
    
    def on_progress(self, progress, current, total):
        """Handle progress update."""
        self.progress_bar.setValue(int(progress))
        self.status_label.setText(f"Scanning: {current}/{total} ({progress:.1f}%)")
        self.scan_progress.emit(progress, current, total)
    
    def on_completed(self, results):
        """Handle scan completion."""
        self.progress_bar.setValue(100)
        self.status_label.setText(f"Scan completed: {len(results)} results")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        
        self.scan_completed.emit(results)
