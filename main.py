"""
Main entry point for Enterprise Port Scanner application.
"""

import sys
from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QIcon

from gui.main_window import MainWindow
from config import APP_NAME
from utils.logger import app_logger


def main():
    """Main application entry point."""
    app_logger.info(f"Starting {APP_NAME}")
    
    # Create QApplication
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName("Security Team")
    
    # Set application style
    app.setStyle("Fusion")
    
    # Create and show main window
    window = MainWindow()
    window.show()
    
    app_logger.info("Application started successfully")
    
    # Run application
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
