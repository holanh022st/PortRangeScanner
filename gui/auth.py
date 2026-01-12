"""
Login dialog for user authentication. 
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QMessageBox, QFrame
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from datetime import datetime

from core.database import Database
from models.user import User


class LoginDialog(QDialog):
    """User login dialog with modern UI."""
    
    def __init__(self, db: Database, parent=None):
        super().__init__(parent)
        self.db = db
        self.current_user = None
        self. init_ui()
    
    def init_ui(self):
        """Initialize UI with modern styling."""
        self.setWindowTitle("Login")
        self.setModal(True)
        self.setFixedSize(450, 320)
        
        # Main stylesheet
        self.setStyleSheet("""
            QDialog {
                background-color: #f5f7fa;
            }
            QLabel {
                color: #2c3e50;
            }
            QLineEdit {
                padding: 12px 15px;
                border: 2px solid #e0e6ed;
                border-radius:  8px;
                background-color: white;
                font-size: 14px;
                color: #2c3e50;
            }
            QLineEdit:focus {
                border:  2px solid #3498db;
                background-color: #ffffff;
            }
            QLineEdit::placeholder {
                color: #95a5a6;
            }
            QPushButton {
                padding: 12px 24px;
                border-radius: 8px;
                font-size: 14px;
                font-weight: 600;
                border: none;
            }
            QPushButton#loginBtn {
                background-color:  #3498db;
                color: white;
            }
            QPushButton#loginBtn:hover {
                background-color: #2980b9;
            }
            QPushButton#loginBtn:pressed {
                background-color: #21618c;
            }
            QPushButton#cancelBtn {
                background-color: #ecf0f1;
                color: #7f8c8d;
            }
            QPushButton#cancelBtn:hover {
                background-color: #d5dbdb;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setSpacing(20)
        layout.setContentsMargins(40, 40, 40, 40)
        
        # Title section
        title = QLabel("Port Scanner")
        title.setAlignment(Qt.AlignmentFlag. AlignCenter)
        title_font = QFont()
        title_font.setPointSize(24)
        title_font.setBold(True)
        title.setFont(title_font)
        title.setStyleSheet("color: #2c3e50; margin-bottom: 5px;")
        layout.addWidget(title)
        
        subtitle = QLabel("Sign in to continue")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle. setStyleSheet("color: #7f8c8d; font-size: 13px; margin-bottom: 10px;")
        layout.addWidget(subtitle)
        
        # Separator line
        line = QFrame()
        line.setFrameShape(QFrame. Shape.HLine)
        line.setStyleSheet("background-color: #e0e6ed; max-height: 1px;")
        layout.addWidget(line)
        
        layout.addSpacing(10)
        
        # Username
        username_label = QLabel("Username")
        username_label.setStyleSheet("font-weight: 600; font-size: 13px; margin-bottom: 5px;")
        layout.addWidget(username_label)
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter your username")
        # Development mode auto-fill
        import os
        if os.getenv("SCANNER_DEV_MODE", "false").lower() == "true":
            self.username_input.setText("admin")
        layout.addWidget(self.username_input)
        
        # Password
        password_label = QLabel("Password")
        password_label.setStyleSheet("font-weight: 600; font-size: 13px; margin-bottom: 5px;")
        layout.addWidget(password_label)
        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input. setPlaceholderText("Enter your password")
        if os.getenv("SCANNER_DEV_MODE", "false").lower() == "true":
            self. password_input.setText("admin123")
        layout.addWidget(self.password_input)
        
        layout.addSpacing(10)
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(12)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setObjectName("cancelBtn")
        cancel_btn.clicked.connect(self.reject)
        cancel_btn.setFixedHeight(44)
        button_layout.addWidget(cancel_btn)
        
        login_btn = QPushButton("Sign In")
        login_btn.setObjectName("loginBtn")
        login_btn.clicked.connect(self.login)
        login_btn.setDefault(True)
        login_btn.setFixedHeight(44)
        button_layout.addWidget(login_btn)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
        # Connect Enter key
        self.username_input.returnPressed.connect(self.login)
        self.password_input.returnPressed.connect(self.login)
    
    def login(self):
        """Perform login."""
        username = self.username_input.text().strip()
        password = self.password_input. text()
        
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
