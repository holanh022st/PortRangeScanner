"""
Login dialog for user authentication.
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QMessageBox
)
from PyQt6.QtCore import Qt
from datetime import datetime

from core.database import Database
from models.user import User


class LoginDialog(QDialog):
    """User login dialog."""
    
    def __init__(self, db: Database, parent=None):
        super().__init__(parent)
        self.db = db
        self.current_user = None
        self.init_ui()
    
    def init_ui(self):
        """Initialize UI."""
        self.setWindowTitle("Login")
        self.setModal(True)
        self.setFixedSize(400, 250)
        
        layout = QVBoxLayout()
        layout.setSpacing(15)
        
        # Title
        title = QLabel("Enterprise Port Scanner")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #007bff;")
        layout.addWidget(title)
        
        subtitle = QLabel("Please log in to continue")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet("color: #888888;")
        layout.addWidget(subtitle)
        
        layout.addSpacing(20)
        
        # Username
        username_label = QLabel("Username:")
        layout.addWidget(username_label)
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter username")
        # Note: Default credentials are for demo/development only
        # Remove these lines in production deployment
        import os
        if os.getenv("SCANNER_DEV_MODE", "false").lower() == "true":
            self.username_input.setText("admin")  # Development only
        layout.addWidget(self.username_input)
        
        # Password
        password_label = QLabel("Password:")
        layout.addWidget(password_label)
        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Enter password")
        if os.getenv("SCANNER_DEV_MODE", "false").lower() == "true":
            self.password_input.setText("admin123")  # Development only
        layout.addWidget(self.password_input)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        login_btn = QPushButton("Login")
        login_btn.clicked.connect(self.login)
        login_btn.setDefault(True)
        button_layout.addWidget(login_btn)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)
        
        layout.addLayout(button_layout)
        
        # Info message
        info_label = QLabel("Default credentials: admin / admin123")
        info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        info_label.setStyleSheet("color: #888888; font-size: 11px; margin-top: 10px;")
        layout.addWidget(info_label)
        
        self.setLayout(layout)
        
        # Connect Enter key
        self.username_input.returnPressed.connect(self.login)
        self.password_input.returnPressed.connect(self.login)
    
    def login(self):
        """Perform login."""
        username = self.username_input.text().strip()
        password = self.password_input.text()
        
        if not username or not password:
            QMessageBox.warning(self, "Error", "Please enter username and password")
            return
        
        # Get user from database
        user = self.db.get_user(username)
        
        if not user:
            QMessageBox.critical(self, "Error", "Invalid username or password")
            return
        
        # Verify password
        if not user.verify_password(password):
            QMessageBox.critical(self, "Error", "Invalid username or password")
            
            # Increment failed login attempts
            user.failed_login_attempts += 1
            self.db.save_user(user)
            return
        
        # Check if account is active
        if not user.is_active:
            QMessageBox.critical(self, "Error", "Account is disabled")
            return
        
        # Successful login
        user.last_login = datetime.now()
        user.failed_login_attempts = 0
        self.db.save_user(user)
        
        self.current_user = user
        self.accept()
