"""
Scan history dialog.
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QLabel, QHeaderView, QMessageBox
)
from PyQt6.QtCore import Qt

from core.database import Database


class HistoryDialog(QDialog):
    """Dialog for viewing scan history."""
    
    def __init__(self, db: Database, parent=None):
        super().__init__(parent)
        self.db = db
        self.init_ui()
        self.load_history()
    
    def init_ui(self):
        """Initialize UI."""
        self.setWindowTitle("Scan History")
        self.setMinimumSize(900, 600)
        
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Scan History")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #007bff;")
        layout.addWidget(title)
        
        # History table
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            "ID", "Name", "User", "Start Time", "Status", "Targets", "Open Ports"
        ])
        
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSortingEnabled(True)
        
        # Set column widths
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        
        layout.addWidget(self.table)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.load_history)
        button_layout.addWidget(refresh_btn)
        
        view_btn = QPushButton("View Details")
        view_btn.clicked.connect(self.view_details)
        button_layout.addWidget(view_btn)
        
        button_layout.addStretch()
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        button_layout.addWidget(close_btn)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def load_history(self):
        """Load scan history from database."""
        sessions = self.db.get_recent_scans(50)
        
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        
        for i, session in enumerate(sessions):
            self.table.insertRow(i)
            
            # ID
            id_item = QTableWidgetItem(str(session.id))
            id_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(i, 0, id_item)
            
            # Name
            name_item = QTableWidgetItem(session.name or f"Scan #{session.id}")
            self.table.setItem(i, 1, name_item)
            
            # User
            user_item = QTableWidgetItem(session.user)
            self.table.setItem(i, 2, user_item)
            
            # Start time
            time_item = QTableWidgetItem(session.start_time.strftime("%Y-%m-%d %H:%M:%S"))
            self.table.setItem(i, 3, time_item)
            
            # Status
            status_item = QTableWidgetItem(session.status)
            status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(i, 4, status_item)
            
            # Targets
            targets_item = QTableWidgetItem(str(session.total_hosts))
            targets_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(i, 5, targets_item)
            
            # Open ports
            open_item = QTableWidgetItem(str(session.open_count))
            open_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(i, 6, open_item)
        
        self.table.setSortingEnabled(True)
    
    def view_details(self):
        """View details of selected scan."""
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.information(self, "No Selection", "Please select a scan to view")
            return
        
        row = selected_rows[0].row()
        scan_id = int(self.table.item(row, 0).text())
        
        # Get scan session
        session = self.db.get_scan_session(scan_id)
        if session:
            details = f"Scan ID: {session.id}\n"
            details += f"Name: {session.name}\n"
            details += f"User: {session.user}\n"
            details += f"Profile: {session.profile_name}\n"
            details += f"Start: {session.start_time}\n"
            if session.end_time:
                details += f"End: {session.end_time}\n"
            details += f"Status: {session.status}\n"
            details += f"Targets: {', '.join(session.targets[:5])}"
            if len(session.targets) > 5:
                details += f" ... ({len(session.targets)} total)"
            details += f"\n\nResults:\n"
            details += f"Total Hosts: {session.total_hosts}\n"
            details += f"Total Ports: {session.total_ports}\n"
            details += f"Open: {session.open_count}\n"
            details += f"Closed: {session.closed_count}\n"
            details += f"Filtered: {session.filtered_count}\n"
            if session.justification:
                details += f"\nJustification:\n{session.justification}"
            
            QMessageBox.information(self, "Scan Details", details)
