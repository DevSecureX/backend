from datetime import datetime, timezone
from hashlib import sha256
import secrets
import base64
from typing import Optional, Union
from fastapi import HTTPException

class PasswordResetTokenGenerator:
    def __init__(self):
        self.secret = secrets.token_urlsafe(32)
        self.timeout_seconds = 3600  # 1 hour

    def make_token(self, user):
        timestamp = int(datetime.now(timezone.utc).timestamp())
        data = f"{user.id}:{timestamp}:{self.secret}"
        token = sha256(data.encode()).hexdigest()
        return f"{base64.urlsafe_b64encode(str(user.id).encode()).decode()}:{base64.urlsafe_b64encode(str(timestamp).encode()).decode()}:{token}"

    def check_token(self, user, token):
        try:
            user_id_b64, timestamp_b64, token_hash = token.split(":")
            user_id = base64.urlsafe_b64decode(user_id_b64).decode()
            timestamp = int(base64.urlsafe_b64decode(timestamp_b64).decode())
            if user.id != int(user_id):
                return False
            if (datetime.now(timezone.utc).timestamp() - timestamp) > self.timeout_seconds:
                return False
            data = f"{user.id}:{timestamp}:{self.secret}"
            expected_hash = sha256(data.encode()).hexdigest()
            return token_hash == expected_hash
        except Exception:
            return False

password_reset_token_generator = PasswordResetTokenGenerator()


# UTC Timestamp Utility Functions
def utc_now() -> datetime:
    """
    Get the current UTC datetime with timezone information.
    
    This replaces datetime.now() and datetime.utcnow() to ensure
    consistent UTC timestamps across the application.
    
    Returns:
        datetime: Current UTC datetime with timezone info
    """
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    """
    Get the current UTC datetime as ISO 8601 formatted string.
    
    Returns:
        str: ISO 8601 formatted UTC timestamp (e.g., "2024-01-15T10:30:45+00:00")
    """
    return utc_now().isoformat()


def to_utc_iso(dt: Optional[datetime]) -> Optional[str]:
    """
    Convert a datetime object to UTC ISO 8601 string.
    
    Args:
        dt: Datetime object to convert (can be None)
        
    Returns:
        Optional[str]: ISO 8601 formatted UTC timestamp or None
    """
    if dt is None:
        return None
    
    # If datetime is naive, assume it's UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    
    # Convert to UTC if not already
    if dt.tzinfo != timezone.utc:
        dt = dt.astimezone(timezone.utc)
    
    return dt.isoformat()


def ensure_utc_datetime(dt: Union[datetime, str, None]) -> Optional[datetime]:
    """
    Ensure a datetime is timezone-aware and in UTC.
    
    Args:
        dt: Input datetime (datetime object, ISO string, or None)
        
    Returns:
        Optional[datetime]: UTC datetime with timezone info or None
    """
    if dt is None:
        return None
    
    if isinstance(dt, str):
        # Parse ISO formatted string
        if dt.endswith('Z'):
            dt = dt[:-1] + '+00:00'  # Replace Z with explicit UTC offset
        dt = datetime.fromisoformat(dt)
    
    # If datetime is naive, assume it's UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    
    # Convert to UTC if not already
    if dt.tzinfo != timezone.utc:
        dt = dt.astimezone(timezone.utc)
    
    return dt


def format_datetime_response(dt: Optional[datetime]) -> Optional[str]:
    """
    Format datetime for API responses in consistent UTC ISO format.
    
    This is the standard function to use when returning datetime values
    in API responses to ensure frontend compatibility.
    
    Args:
        dt: Datetime object to format
        
    Returns:
        Optional[str]: Formatted datetime string or None
    """
    return to_utc_iso(dt)