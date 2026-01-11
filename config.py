"""
Configuration constants for Enterprise Port Scanner.
"""

import os
from pathlib import Path

# Application Info
APP_NAME = "Enterprise Port Scanner"
APP_VERSION = "1.0.0"
APP_AUTHOR = "Security Team"

# Paths
BASE_DIR = Path(__file__).parent
RESOURCES_DIR = BASE_DIR / "resources"
PRESETS_DIR = RESOURCES_DIR / "presets"
REPORTS_DIR = BASE_DIR / "reports"
LOGS_DIR = BASE_DIR / "logs"
DB_DIR = BASE_DIR / "data"

# Ensure directories exist
for directory in [REPORTS_DIR, LOGS_DIR, DB_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# Database
DATABASE_PATH = DB_DIR / "scanner.db"
AUDIT_LOG_PATH = LOGS_DIR / "audit_log.txt"

# Scanner Defaults
DEFAULT_TIMEOUT = 2.0  # seconds
DEFAULT_MAX_THREADS = 100
DEFAULT_RETRIES = 1
DEFAULT_SCAN_SPEED = "Normal"

# Port Ranges
MIN_PORT = 1
MAX_PORT = 65535
COMMON_PORTS = {
    "Web": [80, 443, 8080, 8443],
    "Remote": [22, 23, 3389, 5900],
    "Databases": [3306, 5432, 1433, 27017],
    "Mail": [25, 110, 143, 587],
}

# Scan Speed Profiles
SCAN_SPEED_PROFILES = {
    "Very Slow": {"timeout": 5.0, "threads": 10, "delay": 0.5},
    "Slow": {"timeout": 4.0, "threads": 25, "delay": 0.2},
    "Normal": {"timeout": 2.0, "threads": 50, "delay": 0.1},
    "Fast": {"timeout": 1.0, "threads": 100, "delay": 0.05},
    "Very Fast": {"timeout": 0.5, "threads": 200, "delay": 0.01},
}

# Port States
PORT_STATE_OPEN = "Open"
PORT_STATE_CLOSED = "Closed"
PORT_STATE_FILTERED = "Filtered"
PORT_STATE_TIMEOUT = "Timeout"
PORT_STATE_RESET = "Reset"
PORT_STATE_UNKNOWN = "Unknown"

# Risk Levels
RISK_CRITICAL = "Critical"
RISK_HIGH = "High"
RISK_MEDIUM = "Medium"
RISK_LOW = "Low"
RISK_INFO = "Info"

# Risk Colors (for UI)
RISK_COLORS = {
    RISK_CRITICAL: "#DC143C",  # Crimson
    RISK_HIGH: "#FF6347",      # Tomato
    RISK_MEDIUM: "#FFA500",    # Orange
    RISK_LOW: "#FFD700",       # Gold
    RISK_INFO: "#32CD32",      # LimeGreen
}

# Port State Colors
STATE_COLORS = {
    PORT_STATE_OPEN: "#00FF00",      # Green
    PORT_STATE_CLOSED: "#FF0000",    # Red
    PORT_STATE_FILTERED: "#FFFF00",  # Yellow
    PORT_STATE_TIMEOUT: "#FFA500",   # Orange
    PORT_STATE_RESET: "#FF4500",     # OrangeRed
    PORT_STATE_UNKNOWN: "#808080",   # Gray
}

# Security Settings
REQUIRE_PERMISSION_ACK = True
ENABLE_AUDIT_LOGGING = True
ENABLE_SCOPE_VALIDATION = True
MAX_SCAN_TARGETS = 1000

# Network Validation
PRIVATE_IP_RANGES = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
]

# External IP warning threshold
WARN_ON_EXTERNAL_IP = True

# User Roles
ROLE_VIEWER = "Viewer"
ROLE_OPERATOR = "Operator"
ROLE_SECURITY_ADMIN = "Security Admin"
ROLE_SYSTEM_ADMIN = "System Admin"

# Role Permissions
ROLE_PERMISSIONS = {
    ROLE_VIEWER: ["view_results", "export_results"],
    ROLE_OPERATOR: ["view_results", "export_results", "run_scan", "save_profile"],
    ROLE_SECURITY_ADMIN: ["view_results", "export_results", "run_scan", "save_profile", 
                          "advanced_scan", "manage_exclusions"],
    ROLE_SYSTEM_ADMIN: ["*"],  # All permissions
}

# Export Formats
EXPORT_FORMAT_CSV = "CSV"
EXPORT_FORMAT_JSON = "JSON"
EXPORT_FORMAT_XML = "XML"
EXPORT_FORMAT_PDF = "PDF"
EXPORT_FORMAT_HTML = "HTML"

# Service Detection
SERVICE_TIMEOUT = 5.0
BANNER_MAX_BYTES = 1024
ENABLE_VERSION_DETECTION = True

# High-risk services (require special attention)
HIGH_RISK_SERVICES = [
    "telnet", "ftp", "http", "smb", "netbios", "rpc", "vnc",
    "rdp-unencrypted", "mysql-root", "postgresql-default"
]

# Admin services (exposed = high risk)
ADMIN_SERVICES = [
    "ssh", "rdp", "telnet", "vnc", "mysql", "postgresql", 
    "mssql", "mongodb", "redis"
]

# Legacy protocols (unencrypted)
LEGACY_PROTOCOLS = [
    "telnet", "ftp", "http", "pop3", "imap", "smtp-plain"
]

# Logging
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_MAX_BYTES = 10 * 1024 * 1024  # 10MB
LOG_BACKUP_COUNT = 5

# UI Settings
WINDOW_MIN_WIDTH = 1024
WINDOW_MIN_HEIGHT = 768
TABLE_ROW_HEIGHT = 30
PROGRESS_UPDATE_INTERVAL = 100  # ms

# Notification Settings
ENABLE_EMAIL_ALERTS = False
ENABLE_WEBHOOK_ALERTS = False
SMTP_SERVER = ""
SMTP_PORT = 587
SMTP_USE_TLS = True
WEBHOOK_URL = ""

# History & Retention
SCAN_HISTORY_RETENTION_DAYS = 90
AUTO_CLEANUP_ENABLED = True
