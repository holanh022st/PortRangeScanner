"""
User model for authentication and authorization.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import bcrypt


@dataclass
class User:
    """
    Represents a user account.
    
    Attributes:
        username: Unique username
        password_hash: Bcrypt hashed password
        role: User role (Viewer, Operator, Security Admin, System Admin)
        email: User email
        full_name: Full name
        is_active: Whether account is active
        created_at: Account creation timestamp
        last_login: Last login timestamp
        failed_login_attempts: Count of failed login attempts
    """
    username: str
    password_hash: str
    role: str = "Viewer"
    email: str = ""
    full_name: str = ""
    is_active: bool = True
    created_at: datetime = field(default_factory=datetime.now)
    last_login: Optional[datetime] = None
    failed_login_attempts: int = 0
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using bcrypt."""
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def verify_password(self, password: str) -> bool:
        """Verify a password against the hash."""
        return bcrypt.checkpw(
            password.encode('utf-8'),
            self.password_hash.encode('utf-8')
        )
    
    def has_permission(self, permission: str) -> bool:
        """Check if user has a specific permission."""
        from config import ROLE_PERMISSIONS
        
        permissions = ROLE_PERMISSIONS.get(self.role, [])
        return "*" in permissions or permission in permissions
    
    def to_dict(self) -> dict:
        """Convert to dictionary (excluding password hash)."""
        return {
            "username": self.username,
            "role": self.role,
            "email": self.email,
            "full_name": self.full_name,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat(),
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "failed_login_attempts": self.failed_login_attempts,
        }
    
    @classmethod
    def create_default_admin(cls) -> 'User':
        """Create default admin user."""
        return cls(
            username="admin",
            password_hash=cls.hash_password("admin123"),
            role="System Admin",
            full_name="System Administrator",
            email="admin@example.com",
        )
