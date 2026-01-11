"""
Main application window for Enterprise Port Scanner.
"""

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QTabWidget, QMenuBar, QMenu, QToolBar, QStatusBar, QMessageBox,
    QFileDialog, QLabel, QApplication
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread
from PyQt6.QtGui import QAction

from config import APP_NAME, APP_VERSION, WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT
from gui.dashboard import DashboardWidget
from gui.results_view import ResultsView
from gui.scan_config import ScanConfigDialog
from gui.auth import LoginDialog
from gui.history import HistoryDialog
from core.database import Database
from backend import audit_logger
from utils.logger import app_logger


class MainWindow(QMainWindow):
    """Main application window."""
    
    def __init__(self):
        super().__init__()
        self.current_user = None
        self.db = Database()
        self.init_ui()
        self.show_login()
    
    def init_ui(self):
        """Initialize user interface."""
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        self.setMinimumSize(WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT)
        
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        layout = QVBoxLayout(central_widget)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Create tab widget
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)
        
        # Dashboard tab
        self.dashboard = DashboardWidget()
        self.tabs.addTab(self.dashboard, "Dashboard")
        
        # Results tab
        self.results_view = ResultsView()
        self.tabs.addTab(self.results_view, "Results")
        
        # Connect signals
        self.dashboard.scan_started.connect(self.on_scan_started)
        self.dashboard.scan_completed.connect(self.on_scan_completed)
        self.dashboard.scan_progress.connect(self.on_scan_progress)
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create toolbar
        self.create_toolbar()
        
        # Create status bar
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("Ready")
        
        # Apply dark theme styling
        self.apply_styling()
    
    def create_menu_bar(self):
        """Create application menu bar."""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("&File")
        
        import_action = QAction("&Import Targets", self)
        import_action.triggered.connect(self.import_targets)
        file_menu.addAction(import_action)
        
        file_menu.addSeparator()
        
        export_action = QAction("&Export Results", self)
        export_action.setShortcut("Ctrl+E")
        export_action.triggered.connect(self.export_results)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("E&xit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Scan menu
        scan_menu = menubar.addMenu("&Scan")
        
        new_scan_action = QAction("&New Scan", self)
        new_scan_action.setShortcut("Ctrl+N")
        new_scan_action.triggered.connect(self.new_scan)
        scan_menu.addAction(new_scan_action)
        
        stop_scan_action = QAction("&Stop Scan", self)
        stop_scan_action.setShortcut("Ctrl+S")
        stop_scan_action.triggered.connect(self.stop_scan)
        scan_menu.addAction(stop_scan_action)
        
        # Tools menu
        tools_menu = menubar.addMenu("&Tools")
        
        history_action = QAction("Scan &History", self)
        history_action.setShortcut("Ctrl+H")
        history_action.triggered.connect(self.show_history)
        tools_menu.addAction(history_action)
        
        settings_action = QAction("&Settings", self)
        settings_action.triggered.connect(self.show_settings)
        tools_menu.addAction(settings_action)
        
        # Help menu
        help_menu = menubar.addMenu("&Help")
        
        about_action = QAction("&About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def create_toolbar(self):
        """Create application toolbar."""
        toolbar = QToolBar()
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        
        # New scan button
        new_scan_btn = QPushButton("New Scan")
        new_scan_btn.clicked.connect(self.new_scan)
        toolbar.addWidget(new_scan_btn)
        
        toolbar.addSeparator()
        
        # Stop scan button
        stop_scan_btn = QPushButton("Stop")
        stop_scan_btn.clicked.connect(self.stop_scan)
        toolbar.addWidget(stop_scan_btn)
        
        toolbar.addSeparator()
        
        # Export button
        export_btn = QPushButton("Export")
        export_btn.clicked.connect(self.export_results)
        toolbar.addWidget(export_btn)
        
        toolbar.addSeparator()
        
        # User label
        self.user_label = QLabel("Not logged in")
        toolbar.addWidget(self.user_label)
    
    def apply_styling(self):
        """Apply dark theme styling."""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2b2b2b;
            }
            QWidget {
                background-color: #2b2b2b;
                color: #ffffff;
            }
            QTabWidget::pane {
                border: 1px solid #444444;
                background-color: #2b2b2b;
            }
            QTabBar::tab {
                background-color: #3c3c3c;
                color: #ffffff;
                padding: 8px 16px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #007bff;
            }
            QPushButton {
                background-color: #007bff;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #0056b3;
            }
            QPushButton:pressed {
                background-color: #004085;
            }
            QLineEdit, QTextEdit, QSpinBox, QComboBox {
                background-color: #3c3c3c;
                color: #ffffff;
                border: 1px solid #555555;
                padding: 6px;
                border-radius: 3px;
            }
            QTableWidget {
                background-color: #2b2b2b;
                alternate-background-color: #3c3c3c;
                gridline-color: #555555;
            }
            QHeaderView::section {
                background-color: #007bff;
                color: white;
                padding: 6px;
                border: none;
                font-weight: bold;
            }
            QStatusBar {
                background-color: #1e1e1e;
                color: #ffffff;
            }
            QMenuBar {
                background-color: #2b2b2b;
                color: #ffffff;
            }
            QMenuBar::item:selected {
                background-color: #007bff;
            }
            QMenu {
                background-color: #2b2b2b;
                color: #ffffff;
                border: 1px solid #555555;
            }
            QMenu::item:selected {
                background-color: #007bff;
            }
        """)
    
    def show_login(self):
        """Show login dialog."""
        dialog = LoginDialog(self.db, self)
        if dialog.exec() == 1:  # Accepted
            self.current_user = dialog.current_user
            self.user_label.setText(f"User: {self.current_user.username} ({self.current_user.role})")
            audit_logger.log_event("LOGIN", self.current_user.username, {})
            app_logger.info(f"User logged in: {self.current_user.username}")
        else:
            # Close application gracefully if login cancelled
            app_logger.info("Login cancelled by user")
            QApplication.quit()
    
    def new_scan(self):
        """Show new scan dialog."""
        if not self.current_user:
            QMessageBox.warning(self, "Error", "Please log in first")
            return
        
        dialog = ScanConfigDialog(self.db, self.current_user, self)
        if dialog.exec() == 1:  # Accepted
            # Start scan with configuration
            self.dashboard.start_scan(dialog.get_scan_config())
    
    def stop_scan(self):
        """Stop current scan."""
        self.dashboard.stop_scan()
    
    def import_targets(self):
        """Import targets from file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Import Targets",
            "",
            "Text Files (*.txt);;CSV Files (*.csv);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    targets = f.read()
                self.dashboard.set_targets(targets)
                self.statusBar.showMessage(f"Imported targets from {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to import targets: {e}")
    
    def export_results(self):
        """Export scan results."""
        if not self.results_view.has_results():
            QMessageBox.information(self, "No Results", "No scan results to export")
            return
        
        # Show export dialog
        file_path, file_type = QFileDialog.getSaveFileName(
            self,
            "Export Results",
            "",
            "CSV Files (*.csv);;JSON Files (*.json);;XML Files (*.xml);;HTML Files (*.html);;PDF Files (*.pdf)"
        )
        
        if file_path:
            success = self.results_view.export_results(file_path, file_type)
            if success:
                self.statusBar.showMessage(f"Results exported to {file_path}")
                QMessageBox.information(self, "Success", "Results exported successfully")
            else:
                QMessageBox.critical(self, "Error", "Failed to export results")
    
    def show_history(self):
        """Show scan history dialog."""
        dialog = HistoryDialog(self.db, self)
        dialog.exec()
    
    def show_settings(self):
        """Show settings dialog."""
        QMessageBox.information(self, "Settings", "Settings dialog coming soon")
    
    def show_about(self):
        """Show about dialog."""
        QMessageBox.about(
            self,
            "About",
            f"{APP_NAME} v{APP_VERSION}\n\n"
            f"Enterprise-grade port scanner with comprehensive security features.\n\n"
            f"© 2026 Security Team"
        )
    
    def on_scan_started(self):
        """Handle scan started event."""
        self.statusBar.showMessage("Scan started...")
        self.tabs.setCurrentWidget(self.dashboard)
        
        if self.current_user:
            audit_logger.log_event("SCAN_START", self.current_user.username, {})
    
    def on_scan_completed(self, results):
        """Handle scan completed event."""
        self.statusBar.showMessage(f"Scan completed: {len(results)} results")
        
        # Update results view
        self.results_view.set_results(results)
        
        # Switch to results tab
        self.tabs.setCurrentWidget(self.results_view)
        
        if self.current_user:
            audit_logger.log_event("SCAN_COMPLETE", self.current_user.username, {
                "result_count": len(results)
            })
        
        # Show summary
        open_count = sum(1 for r in results if r.state == "Open")
        QMessageBox.information(
            self,
            "Scan Complete",
            f"Scan completed successfully!\n\n"
            f"Total results: {len(results)}\n"
            f"Open ports: {open_count}"
        )
    
    def on_scan_progress(self, progress, current, total):
        """Handle scan progress update."""
        self.statusBar.showMessage(f"Scanning: {current}/{total} ({progress:.1f}%)")
    
    def closeEvent(self, event):
        """Handle window close event."""
        reply = QMessageBox.question(
            self,
            "Exit",
            "Are you sure you want to exit?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            if self.current_user:
                audit_logger.log_event("LOGOUT", self.current_user.username, {})
            app_logger.info("Application closing")
            event.accept()
        else:
            event.ignore()


# Import datetime for audit logging
from datetime import datetime
import sys
