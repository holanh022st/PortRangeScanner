"""
Database layer for Enterprise Port Scanner.

Handles SQLite database operations for:
- Scan history
- User accounts
- Scan profiles
- Audit logs
"""

import sqlite3
from datetime import datetime, timedelta
from typing import List, Optional, Dict
from pathlib import Path

from config import DATABASE_PATH, SCAN_HISTORY_RETENTION_DAYS
from models.scan_result import ScanResult, ScanSession
from models.user import User
from models.scan_profile import ScanProfile
from utils.logger import app_logger


class Database:
    """SQLite database manager for the port scanner."""
    
    def __init__(self, db_path: str = None):
        """
        Initialize database connection.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(db_path) if db_path else DATABASE_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = None
        self.init_database()
    
    def connect(self) -> sqlite3.Connection:
        """Create and return database connection."""
        return sqlite3.connect(str(self.db_path))
    
    def init_database(self) -> None:
        """Initialize database schema."""
        conn = self.connect()
        cursor = conn.cursor()
        
        # Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                email TEXT,
                full_name TEXT,
                is_active INTEGER DEFAULT 1,
                created_at TEXT NOT NULL,
                last_login TEXT,
                failed_login_attempts INTEGER DEFAULT 0
            )
        """)
        
        # Scan sessions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                targets TEXT NOT NULL,
                ports TEXT NOT NULL,
                profile_name TEXT,
                user TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT,
                total_hosts INTEGER DEFAULT 0,
                total_ports INTEGER DEFAULT 0,
                open_count INTEGER DEFAULT 0,
                closed_count INTEGER DEFAULT 0,
                filtered_count INTEGER DEFAULT 0,
                status TEXT DEFAULT 'Running',
                justification TEXT,
                results_hash TEXT
            )
        """)
        
        # Scan results table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                state TEXT NOT NULL,
                service TEXT,
                version TEXT,
                banner TEXT,
                risk_level TEXT DEFAULT 'Low',
                response_time REAL DEFAULT 0.0,
                timestamp TEXT NOT NULL,
                protocol TEXT DEFAULT 'TCP',
                notes TEXT,
                FOREIGN KEY (scan_id) REFERENCES scan_sessions(id)
            )
        """)
        
        # Scan profiles table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_profiles (
                name TEXT PRIMARY KEY,
                description TEXT,
                scan_type TEXT DEFAULT 'TCP',
                speed TEXT DEFAULT 'Normal',
                timeout REAL DEFAULT 2.0,
                max_threads INTEGER DEFAULT 50,
                retries INTEGER DEFAULT 1,
                enable_service_detection INTEGER DEFAULT 1,
                enable_banner_grabbing INTEGER DEFAULT 1,
                enable_version_detection INTEGER DEFAULT 1,
                rescan_open_ports INTEGER DEFAULT 0,
                port_ranges TEXT,
                is_locked INTEGER DEFAULT 0,
                created_by TEXT DEFAULT 'System',
                is_default INTEGER DEFAULT 0
            )
        """)
        
        conn.commit()
        conn.close()
        
        app_logger.info("Database initialized successfully")
        
        # Create default admin user if not exists
        self.create_default_admin()
        
        # Create default profiles if not exist
        self.create_default_profiles()
    
    def create_default_admin(self) -> None:
        """Create default admin user if not exists."""
        if not self.get_user("admin"):
            admin = User.create_default_admin()
            self.save_user(admin)
            app_logger.info("Default admin user created (username: admin, password: admin123)")
    
    def create_default_profiles(self) -> None:
        """Create default scan profiles if not exist."""
        profiles = ScanProfile.create_default_profiles()
        for profile in profiles:
            if not self.get_profile(profile.name):
                self.save_profile(profile)
        app_logger.info("Default scan profiles created")
    
    # User operations
    def save_user(self, user: User) -> None:
        """Save or update a user."""
        conn = self.connect()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO users 
            (username, password_hash, role, email, full_name, is_active, 
             created_at, last_login, failed_login_attempts)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user.username, user.password_hash, user.role, user.email, user.full_name,
            1 if user.is_active else 0, user.created_at.isoformat(),
            user.last_login.isoformat() if user.last_login else None,
            user.failed_login_attempts
        ))
        
        conn.commit()
        conn.close()
        app_logger.info(f"User saved: {user.username}")
    
    def get_user(self, username: str) -> Optional[User]:
        """Get a user by username."""
        conn = self.connect()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return User(
                username=row[0],
                password_hash=row[1],
                role=row[2],
                email=row[3] or "",
                full_name=row[4] or "",
                is_active=bool(row[5]),
                created_at=datetime.fromisoformat(row[6]),
                last_login=datetime.fromisoformat(row[7]) if row[7] else None,
                failed_login_attempts=row[8] or 0,
            )
        return None
    
    def get_all_users(self) -> List[User]:
        """Get all users."""
        conn = self.connect()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM users")
        rows = cursor.fetchall()
        conn.close()
        
        users = []
        for row in rows:
            users.append(User(
                username=row[0],
                password_hash=row[1],
                role=row[2],
                email=row[3] or "",
                full_name=row[4] or "",
                is_active=bool(row[5]),
                created_at=datetime.fromisoformat(row[6]),
                last_login=datetime.fromisoformat(row[7]) if row[7] else None,
                failed_login_attempts=row[8] or 0,
            ))
        
        return users
    
    # Scan session operations
    def save_scan_session(self, session: ScanSession) -> int:
        """Save a scan session and return its ID."""
        conn = self.connect()
        cursor = conn.cursor()
        
        if session.id:
            # Update existing
            cursor.execute("""
                UPDATE scan_sessions SET
                name = ?, targets = ?, ports = ?, profile_name = ?, user = ?,
                start_time = ?, end_time = ?, total_hosts = ?, total_ports = ?,
                open_count = ?, closed_count = ?, filtered_count = ?, status = ?,
                justification = ?, results_hash = ?
                WHERE id = ?
            """, (
                session.name, ','.join(session.targets), session.ports, session.profile_name,
                session.user, session.start_time.isoformat(),
                session.end_time.isoformat() if session.end_time else None,
                session.total_hosts, session.total_ports, session.open_count,
                session.closed_count, session.filtered_count, session.status,
                session.justification, session.results_hash, session.id
            ))
            session_id = session.id
        else:
            # Insert new
            cursor.execute("""
                INSERT INTO scan_sessions
                (name, targets, ports, profile_name, user, start_time, end_time,
                 total_hosts, total_ports, open_count, closed_count, filtered_count,
                 status, justification, results_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session.name, ','.join(session.targets), session.ports, session.profile_name,
                session.user, session.start_time.isoformat(),
                session.end_time.isoformat() if session.end_time else None,
                session.total_hosts, session.total_ports, session.open_count,
                session.closed_count, session.filtered_count, session.status,
                session.justification, session.results_hash
            ))
            session_id = cursor.lastrowid
        
        conn.commit()
        conn.close()
        app_logger.info(f"Scan session saved: ID {session_id}")
        return session_id
    
    def get_scan_session(self, session_id: int) -> Optional[ScanSession]:
        """Get a scan session by ID."""
        conn = self.connect()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM scan_sessions WHERE id = ?", (session_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return ScanSession(
                id=row[0],
                name=row[1] or "",
                targets=row[2].split(','),
                ports=row[3],
                profile_name=row[4],
                user=row[5],
                start_time=datetime.fromisoformat(row[6]),
                end_time=datetime.fromisoformat(row[7]) if row[7] else None,
                total_hosts=row[8],
                total_ports=row[9],
                open_count=row[10],
                closed_count=row[11],
                filtered_count=row[12],
                status=row[13],
                justification=row[14] or "",
                results_hash=row[15] or "",
            )
        return None
    
    def get_recent_scans(self, limit: int = 50) -> List[ScanSession]:
        """Get recent scan sessions."""
        conn = self.connect()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM scan_sessions 
            ORDER BY start_time DESC 
            LIMIT ?
        """, (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        sessions = []
        for row in rows:
            sessions.append(ScanSession(
                id=row[0],
                name=row[1] or "",
                targets=row[2].split(','),
                ports=row[3],
                profile_name=row[4],
                user=row[5],
                start_time=datetime.fromisoformat(row[6]),
                end_time=datetime.fromisoformat(row[7]) if row[7] else None,
                total_hosts=row[8],
                total_ports=row[9],
                open_count=row[10],
                closed_count=row[11],
                filtered_count=row[12],
                status=row[13],
                justification=row[14] or "",
                results_hash=row[15] or "",
            ))
        
        return sessions
    
    # Scan results operations
    def save_scan_result(self, result: ScanResult) -> None:
        """Save a scan result."""
        conn = self.connect()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO scan_results
            (scan_id, host, port, state, service, version, banner, risk_level,
             response_time, timestamp, protocol, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result.scan_id, result.host, result.port, result.state, result.service,
            result.version, result.banner, result.risk_level, result.response_time,
            result.timestamp.isoformat(), result.protocol, result.notes
        ))
        
        conn.commit()
        conn.close()
    
    def get_scan_results(self, scan_id: int) -> List[ScanResult]:
        """Get all results for a scan session."""
        conn = self.connect()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM scan_results WHERE scan_id = ?", (scan_id,))
        rows = cursor.fetchall()
        conn.close()
        
        results = []
        for row in rows:
            results.append(ScanResult(
                scan_id=row[1],
                host=row[2],
                port=row[3],
                state=row[4],
                service=row[5],
                version=row[6],
                banner=row[7],
                risk_level=row[8],
                response_time=row[9],
                timestamp=datetime.fromisoformat(row[10]),
                protocol=row[11],
                notes=row[12] or "",
            ))
        
        return results
    
    # Profile operations
    def save_profile(self, profile: ScanProfile) -> None:
        """Save a scan profile."""
        conn = self.connect()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO scan_profiles
            (name, description, scan_type, speed, timeout, max_threads, retries,
             enable_service_detection, enable_banner_grabbing, enable_version_detection,
             rescan_open_ports, port_ranges, is_locked, created_by, is_default)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            profile.name, profile.description, profile.scan_type, profile.speed,
            profile.timeout, profile.max_threads, profile.retries,
            1 if profile.enable_service_detection else 0,
            1 if profile.enable_banner_grabbing else 0,
            1 if profile.enable_version_detection else 0,
            1 if profile.rescan_open_ports else 0,
            ','.join(profile.port_ranges),
            1 if profile.is_locked else 0,
            profile.created_by,
            1 if profile.is_default else 0,
        ))
        
        conn.commit()
        conn.close()
        app_logger.info(f"Profile saved: {profile.name}")
    
    def get_profile(self, name: str) -> Optional[ScanProfile]:
        """Get a scan profile by name."""
        conn = self.connect()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM scan_profiles WHERE name = ?", (name,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return ScanProfile(
                name=row[0],
                description=row[1] or "",
                scan_type=row[2],
                speed=row[3],
                timeout=row[4],
                max_threads=row[5],
                retries=row[6],
                enable_service_detection=bool(row[7]),
                enable_banner_grabbing=bool(row[8]),
                enable_version_detection=bool(row[9]),
                rescan_open_ports=bool(row[10]),
                port_ranges=row[11].split(',') if row[11] else [],
                is_locked=bool(row[12]),
                created_by=row[13],
                is_default=bool(row[14]),
            )
        return None
    
    def get_all_profiles(self) -> List[ScanProfile]:
        """Get all scan profiles."""
        conn = self.connect()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM scan_profiles ORDER BY is_default DESC, name")
        rows = cursor.fetchall()
        conn.close()
        
        profiles = []
        for row in rows:
            profiles.append(ScanProfile(
                name=row[0],
                description=row[1] or "",
                scan_type=row[2],
                speed=row[3],
                timeout=row[4],
                max_threads=row[5],
                retries=row[6],
                enable_service_detection=bool(row[7]),
                enable_banner_grabbing=bool(row[8]),
                enable_version_detection=bool(row[9]),
                rescan_open_ports=bool(row[10]),
                port_ranges=row[11].split(',') if row[11] else [],
                is_locked=bool(row[12]),
                created_by=row[13],
                is_default=bool(row[14]),
            ))
        
        return profiles
    
    def cleanup_old_scans(self, retention_days: int = None) -> int:
        """
        Clean up old scan records.
        
        Args:
            retention_days: Number of days to retain (default from config)
            
        Returns:
            Number of records deleted
        """
        if retention_days is None:
            retention_days = SCAN_HISTORY_RETENTION_DAYS
        
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        
        conn = self.connect()
        cursor = conn.cursor()
        
        # Get scan IDs to delete
        cursor.execute("""
            SELECT id FROM scan_sessions 
            WHERE start_time < ?
        """, (cutoff_date.isoformat(),))
        
        scan_ids = [row[0] for row in cursor.fetchall()]
        
        if scan_ids:
            # Delete results
            placeholders = ','.join('?' * len(scan_ids))
            cursor.execute(f"""
                DELETE FROM scan_results 
                WHERE scan_id IN ({placeholders})
            """, scan_ids)
            
            # Delete sessions
            cursor.execute(f"""
                DELETE FROM scan_sessions 
                WHERE id IN ({placeholders})
            """, scan_ids)
        
        conn.commit()
        conn.close()
        
        app_logger.info(f"Cleaned up {len(scan_ids)} old scan sessions")
        return len(scan_ids)
