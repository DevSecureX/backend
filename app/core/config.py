import os
import logging
from cryptography.fernet import Fernet
import base64

# Set up logger early
logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL") or os.getenv("LOCAL_POSTGRES_URL")
REDIS_URL = os.getenv("REDIS_URL") or os.getenv("LOCAL_REDIS_URL")
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable not set")
ALGORITHM = "HS256"

# Testing Configuration
TESTING_MODE = os.getenv("TESTING_MODE", "false").lower() == "true"
APP_ENV = os.getenv("APP_ENV", "production")

# JWT Configuration - Environment-based token expiration
if APP_ENV in ["local", "development"] or TESTING_MODE:
    # Local/Development: 8 hours (full work day)
    ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "480"))
else:
    # Production: 1 hour (more secure)
    ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

# Rate Limiting Configuration (higher limits for testing)
if TESTING_MODE or APP_ENV == "testing":
    # Testing mode: Much higher rate limits
    RATE_LIMIT_LOGIN_ATTEMPTS = int(os.getenv("RATE_LIMIT_LOGIN_ATTEMPTS", "100"))
    RATE_LIMIT_LOGIN_WINDOW = int(os.getenv("RATE_LIMIT_LOGIN_WINDOW", "60"))  # minutes
    RATE_LIMIT_SIGNUP_ATTEMPTS = int(os.getenv("RATE_LIMIT_SIGNUP_ATTEMPTS", "50"))
    RATE_LIMIT_SIGNUP_WINDOW = int(os.getenv("RATE_LIMIT_SIGNUP_WINDOW", "60"))  # minutes
    RATE_LIMIT_PASSWORD_RESET_ATTEMPTS = int(os.getenv("RATE_LIMIT_PASSWORD_RESET_ATTEMPTS", "30"))
    RATE_LIMIT_PASSWORD_RESET_WINDOW = int(os.getenv("RATE_LIMIT_PASSWORD_RESET_WINDOW", "60"))  # minutes
    RATE_LIMIT_MAIL_LIST_ATTEMPTS = int(os.getenv("RATE_LIMIT_MAIL_LIST_ATTEMPTS", "100"))
    RATE_LIMIT_MAIL_LIST_WINDOW = int(os.getenv("RATE_LIMIT_MAIL_LIST_WINDOW", "60"))  # minutes
else:
    # Production mode: Standard security limits
    RATE_LIMIT_LOGIN_ATTEMPTS = int(os.getenv("RATE_LIMIT_LOGIN_ATTEMPTS", "10"))
    RATE_LIMIT_LOGIN_WINDOW = int(os.getenv("RATE_LIMIT_LOGIN_WINDOW", "15"))  # minutes
    RATE_LIMIT_SIGNUP_ATTEMPTS = int(os.getenv("RATE_LIMIT_SIGNUP_ATTEMPTS", "5"))
    RATE_LIMIT_SIGNUP_WINDOW = int(os.getenv("RATE_LIMIT_SIGNUP_WINDOW", "60"))  # minutes
    RATE_LIMIT_PASSWORD_RESET_ATTEMPTS = int(os.getenv("RATE_LIMIT_PASSWORD_RESET_ATTEMPTS", "3"))
    RATE_LIMIT_PASSWORD_RESET_WINDOW = int(os.getenv("RATE_LIMIT_PASSWORD_RESET_WINDOW", "60"))  # minutes
    RATE_LIMIT_MAIL_LIST_ATTEMPTS = int(os.getenv("RATE_LIMIT_MAIL_LIST_ATTEMPTS", "10"))
    RATE_LIMIT_MAIL_LIST_WINDOW = int(os.getenv("RATE_LIMIT_MAIL_LIST_WINDOW", "60"))  # minutes
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    logger.warning("OPENAI_API_KEY not set - AI features will be disabled")
    OPENAI_API_KEY = None
EXACT_MATCH_ONLY = os.getenv("EXACT_MATCH_ONLY", "true").lower() == "true"
# OAuth settings
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
GITHUB_REDIRECT_URI = os.getenv("GITHUB_REDIRECT_URI")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")  # For testing/dev use
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USERINFO_URL = "https://api.github.com/user"
# Dynamic frontend redirect URLs based on APP_ENV
if APP_ENV == "local":
    GOOGLE_REDIRECT_URI = os.getenv("LOCAL_GOOGLE_REDIRECT_URI") or os.getenv("GOOGLE_REDIRECT_URI")
    GITHUB_REDIRECT_URI = os.getenv("LOCAL_GITHUB_REDIRECT_URI") or os.getenv("GITHUB_REDIRECT_URI")
    FRONTEND_GOOGLE_REDIRECT_URL = os.getenv("LOCAL_FRONTEND_GOOGLE_REDIRECT_URL") or os.getenv("FRONTEND_GOOGLE_REDIRECT_URL")
    FRONTEND_GITHUB_REDIRECT_URL = os.getenv("LOCAL_FRONTEND_GITHUB_REDIRECT_URL") or os.getenv("FRONTEND_GITHUB_REDIRECT_URL")
    FRONTEND_URI = os.getenv("LOCAL_FRONTEND_URL") or os.getenv("FRONTEND_URI")
else:
    GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")
    GITHUB_REDIRECT_URI = os.getenv("GITHUB_REDIRECT_URI")
    FRONTEND_GOOGLE_REDIRECT_URL = os.getenv("FRONTEND_GOOGLE_REDIRECT_URL")
    FRONTEND_GITHUB_REDIRECT_URL = os.getenv("FRONTEND_GITHUB_REDIRECT_URL")
    FRONTEND_URI = os.getenv("FRONTEND_URI")
# Razorpay settings
RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET")

ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
logger.debug("ENCRYPTION_KEY loaded from environment")  # Secure logging

if not ENCRYPTION_KEY:
    raise ValueError("ENCRYPTION_KEY environment variable not set")
try:
    cipher = Fernet(ENCRYPTION_KEY)  # Validate key here
except ValueError as e:
    raise ValueError(f"Invalid ENCRYPTION_KEY: {str(e)}")

# Database Configuration Settings (NEW - for advanced pooling)
DB_POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "40"))
DB_MAX_OVERFLOW = int(os.getenv("DB_MAX_OVERFLOW", "60"))
DB_POOL_TIMEOUT = int(os.getenv("DB_POOL_TIMEOUT", "60"))
DB_POOL_RECYCLE = int(os.getenv("DB_POOL_RECYCLE", "3600"))
DB_POOL_PRE_PING = os.getenv("DB_POOL_PRE_PING", "true").lower() == "true"
DB_HEALTH_CHECK_INTERVAL = int(os.getenv("DB_HEALTH_CHECK_INTERVAL", "30"))
DB_MAX_RETRIES = int(os.getenv("DB_MAX_RETRIES", "3"))
DB_RETRY_DELAY = float(os.getenv("DB_RETRY_DELAY", "0.5"))
DB_QUERY_TIMEOUT = int(os.getenv("DB_QUERY_TIMEOUT", "30"))
DB_ENABLE_QUERY_CACHE = os.getenv("DB_ENABLE_QUERY_CACHE", "true").lower() == "true"

# Helper function for migrations
def get_database_url():
    """Get database URL for migrations and other uses"""
    return DATABASE_URL

# Export cipher for use in dependencies
__all__ = ['cipher', 'DATABASE_URL', 'REDIS_URL', 'SECRET_KEY', 'ALGORITHM', 'ACCESS_TOKEN_EXPIRE_MINUTES',
           'OPENAI_API_KEY', 'EXACT_MATCH_ONLY', 'GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'GOOGLE_REDIRECT_URI',
           'GOOGLE_TOKEN_URL', 'GOOGLE_USERINFO_URL', 'GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET', 'GITHUB_REDIRECT_URI',
           'GITHUB_TOKEN_URL', 'GITHUB_USERINFO_URL', 'FRONTEND_GOOGLE_REDIRECT_URL', 'FRONTEND_GITHUB_REDIRECT_URL',
           'FRONTEND_URI', 'RAZORPAY_KEY_ID', 'RAZORPAY_KEY_SECRET', 'ENCRYPTION_KEY', 'get_database_url',
           'DB_POOL_SIZE', 'DB_MAX_OVERFLOW', 'DB_POOL_TIMEOUT', 'DB_POOL_RECYCLE', 'DB_POOL_PRE_PING',
           'DB_HEALTH_CHECK_INTERVAL', 'DB_MAX_RETRIES', 'DB_RETRY_DELAY', 'DB_QUERY_TIMEOUT', 'DB_ENABLE_QUERY_CACHE']