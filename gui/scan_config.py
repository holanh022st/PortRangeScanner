"""
Scan configuration dialog.
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QComboBox, QSpinBox, QCheckBox, QGroupBox,
    QTextEdit, QMessageBox
)
from PyQt6.QtCore import Qt

from core.database import Database
from models.user import User


class ScanConfigDialog(QDialog):
    """Dialog for configuring a new scan."""
    
    def __init__(self, db: Database, user: User, parent=None):
        super().__init__(parent)
        self.db = db
        self.user = user
        self.scan_config = {}
        self.init_ui()
    
    def init_ui(self):
        """Initialize UI."""
        self.setWindowTitle("New Scan Configuration")
        self.setModal(True)
        self.setMinimumSize(600, 500)
        
        layout = QVBoxLayout()
        
        # Profile selection
        profile_group = QGroupBox("Scan Profile")
        profile_layout = QHBoxLayout()
        
        profile_layout.addWidget(QLabel("Profile:"))
        self.profile_combo = QComboBox()
        
        # Load profiles from database
        profiles = self.db.get_all_profiles()
        for profile in profiles:
            self.profile_combo.addItem(profile.name)
        
        self.profile_combo.currentTextChanged.connect(self.load_profile)
        profile_layout.addWidget(self.profile_combo)
        
        profile_group.setLayout(profile_layout)
        layout.addWidget(profile_group)
        
        # Scan options
        options_group = QGroupBox("Scan Options")
        options_layout = QVBoxLayout()
        
        # Speed
        speed_layout = QHBoxLayout()
        speed_layout.addWidget(QLabel("Speed:"))
        self.speed_combo = QComboBox()
        self.speed_combo.addItems(["Very Slow", "Slow", "Normal", "Fast", "Very Fast"])
        self.speed_combo.setCurrentText("Normal")
        speed_layout.addWidget(self.speed_combo)
        speed_layout.addStretch()
        options_layout.addLayout(speed_layout)
        
        # Threads and timeout
        params_layout = QHBoxLayout()
        params_layout.addWidget(QLabel("Max Threads:"))
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 200)
        self.threads_spin.setValue(50)
        params_layout.addWidget(self.threads_spin)
        
        params_layout.addWidget(QLabel("Timeout:"))
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 10)
        self.timeout_spin.setValue(2)
        self.timeout_spin.setSuffix("s")
        params_layout.addWidget(self.timeout_spin)
        params_layout.addStretch()
        options_layout.addLayout(params_layout)
        
        # Detection options
        self.service_check = QCheckBox("Enable Service Detection")
        self.service_check.setChecked(True)
        options_layout.addWidget(self.service_check)
        
        self.banner_check = QCheckBox("Enable Banner Grabbing")
        self.banner_check.setChecked(True)
        options_layout.addWidget(self.banner_check)
        
        self.version_check = QCheckBox("Enable Version Detection")
        self.version_check.setChecked(True)
        options_layout.addWidget(self.version_check)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Justification (required for audit)
        justification_group = QGroupBox("Justification (Required)")
        justification_layout = QVBoxLayout()
        
        justification_layout.addWidget(QLabel("Reason for this scan:"))
        self.justification_input = QTextEdit()
        self.justification_input.setPlaceholderText("Enter justification for scanning these targets...")
        self.justification_input.setMaximumHeight(80)
        justification_layout.addWidget(self.justification_input)
        
        justification_group.setLayout(justification_layout)
        layout.addWidget(justification_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        ok_btn = QPushButton("Start Scan")
        ok_btn.clicked.connect(self.accept_config)
        button_layout.addWidget(ok_btn)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
        # Load first profile
        if self.profile_combo.count() > 0:
            self.load_profile(self.profile_combo.currentText())
    
    def load_profile(self, profile_name: str):
        """Load profile settings."""
        profile = self.db.get_profile(profile_name)
        if profile:
            self.speed_combo.setCurrentText(profile.speed)
            self.threads_spin.setValue(profile.max_threads)
            self.timeout_spin.setValue(int(profile.timeout))
            self.service_check.setChecked(profile.enable_service_detection)
            self.banner_check.setChecked(profile.enable_banner_grabbing)
            self.version_check.setChecked(profile.enable_version_detection)
    
    def accept_config(self):
        """Validate and accept configuration."""
        justification = self.justification_input.toPlainText().strip()
        
        if not justification:
            QMessageBox.warning(
                self,
                "Required Field",
                "Please provide a justification for this scan."
            )
            return
        
        # Build configuration
        self.scan_config = {
            'profile': self.profile_combo.currentText(),
            'speed': self.speed_combo.currentText(),
            'max_threads': self.threads_spin.value(),
            'timeout': self.timeout_spin.value(),
            'retries': 1,
            'protocol': 'TCP',
            'enable_service_detection': self.service_check.isChecked(),
            'enable_banner_grabbing': self.banner_check.isChecked(),
            'enable_version_detection': self.version_check.isChecked(),
            'justification': justification,
        }
        
        self.accept()
    
    def get_scan_config(self) -> dict:
        """Get the scan configuration."""
        return self.scan_config
