from fastapi import Depends, HTTPException, status, Request, Header
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, insert, update, and_, or_
from sqlalchemy.orm import selectinload
from core.database import get_db
from core.cache import cache, RateLimitCache
from core.config import (
    SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, GOOGLE_CLIENT_ID, GOOGLE_REDIRECT_URI, 
    GOOGLE_CLIENT_SECRET, GOOGLE_TOKEN_URL, GOOGLE_USERINFO_URL, 
    GITHUB_REDIRECT_URI, GITHUB_CLIENT_SECRET, GITHUB_CLIENT_ID, cipher
)
from auth.models import User, BlacklistedToken, LoginAttempt
import secrets
import uuid
import httpx
import logging
from datetime import datetime, timedelta, timezone
import jwt
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError, DecodeError
from typing import Optional
import hashlib
import asyncio

logger = logging.getLogger(__name__)

# Security constants
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=30)
TOKEN_BLACKLIST_CLEANUP_INTERVAL = timedelta(hours=1)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# GitHub URLs
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USERINFO_URL = "https://api.github.com/user"


def hash_password(password: str) -> str:
    """Hash password with bcrypt"""
    if not password:
        raise ValueError("Password cannot be empty")
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash with null safety"""
    if not plain_password or not hashed_password:
        logger.debug("Password verification failed: empty password or hash")
        return False
    
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        logger.error(f"Password verification error: {str(e)}")
        return False


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token with proper expiration and JTI"""
    to_encode = data.copy()
    utc_now = datetime.now(timezone.utc)
    
    if expires_delta:
        expire = utc_now + expires_delta
    else:
        # Use configured expiration time instead of hardcoded 1 hour
        expire = utc_now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    # Add standard JWT claims
    to_encode.update({
        "exp": expire,
        "iat": utc_now,
        "jti": secrets.token_urlsafe(16),
        "type": "access"
    })
    
    try:
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    except Exception as e:
        logger.error(f"Token creation error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token creation failed"
        )


def encrypt_token(token: str) -> str:
    """Encrypt token for secure storage"""
    if not token:
        raise ValueError("Token cannot be empty")
    
    try:
        return cipher.encrypt(token.encode()).decode()
    except Exception as e:
        logger.error(f"Token encryption error: {str(e)}")
        raise ValueError("Token encryption failed")


def decrypt_token(encrypted: str) -> str:
    """Decrypt token with error handling"""
    if not encrypted:
        raise ValueError("Encrypted token cannot be empty")
    
    try:
        return cipher.decrypt(encrypted.encode()).decode()
    except Exception as e:
        logger.error(f"Token decryption error: {str(e)}")
        raise ValueError("Invalid or corrupted token")


async def check_account_lockout(username: str, db: AsyncSession) -> bool:
    """Check if account is locked due to failed login attempts"""
    from sqlalchemy import func
    normalized_username = username.lower().strip()
    
    user = await db.execute(select(User).where(
        func.lower(User.username) == normalized_username,
        User.is_deleted == False
    ))
    user = user.scalar_one_or_none()
    
    if not user:
        return False
    
    # Check if account is currently locked
    if user.locked_until and user.locked_until > datetime.now(timezone.utc):
        return True
    
    # Reset lock if expired
    if user.locked_until and user.locked_until <= datetime.now(timezone.utc):
        await db.execute(
            update(User)
            .where(User.id == user.id)
            .values(locked_until=None, failed_login_attempts=0)
        )
        await db.commit()
    
    return False


async def record_login_attempt(
    username: str, 
    success: bool, 
    ip_address: str, 
    user_agent: str, 
    db: AsyncSession
) -> None:
    """Record login attempt for security monitoring"""
    try:
        # Record attempt
        login_attempt = LoginAttempt(
            username_or_email=username,
            ip_address=ip_address,
            user_agent=user_agent[:500] if user_agent else None,  # Truncate long user agents
            success=success
        )
        db.add(login_attempt)
        
        # Update user's failed attempts if login failed
        if not success:
            from sqlalchemy import func
            normalized_username = username.lower().strip()
            user = await db.execute(select(User).where(
        func.lower(User.username) == normalized_username,
        User.is_deleted == False
    ))
            user = user.scalar_one_or_none()
            
            if user:
                new_attempts = user.failed_login_attempts + 1
                
                # Lock account if too many failures
                if new_attempts >= MAX_LOGIN_ATTEMPTS:
                    lock_until = datetime.now(timezone.utc) + LOCKOUT_DURATION
                    await db.execute(
                        update(User)
                        .where(User.id == user.id)
                        .values(
                            failed_login_attempts=new_attempts,
                            locked_until=lock_until
                        )
                    )
                    logger.warning(f"Account locked for user: {username} until {lock_until}")
                else:
                    await db.execute(
                        update(User)
                        .where(User.id == user.id)
                        .values(failed_login_attempts=new_attempts)
                    )
        else:
            # Reset failed attempts on successful login
            from sqlalchemy import func
            normalized_username = username.lower().strip()
            user = await db.execute(select(User).where(
        func.lower(User.username) == normalized_username,
        User.is_deleted == False
    ))
            user = user.scalar_one_or_none()
            
            if user:
                await db.execute(
                    update(User)
                    .where(User.id == user.id)
                    .values(
                        failed_login_attempts=0,
                        locked_until=None,
                        last_login=datetime.now(timezone.utc)
                    )
                )
        
        await db.commit()
        
    except Exception as e:
        logger.error(f"Error recording login attempt: {str(e)}")
        # Don't fail the login process due to logging errors
        await db.rollback()


async def get_current_user(
    token: str = Depends(oauth2_scheme), 
    db: AsyncSession = Depends(get_db)
) -> User:
    """Get current user from JWT token with comprehensive validation and caching"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        # Decode and validate token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        # Validate required claims
        username: str = payload.get("sub")
        jti: str = payload.get("jti")
        token_type: str = payload.get("type")
        
        if not username or not jti:
            logger.error("Invalid token: missing required claims")
            raise credentials_exception
        
        if token_type != "access":
            logger.error(f"Invalid token type: {token_type}")
            raise credentials_exception
        
        # Skip caching for now to avoid SQLAlchemy model issues
        # TODO: Implement proper user caching with model serialization later
        
        # Check if token is blacklisted
        blacklisted = await db.execute(
            select(BlacklistedToken).where(BlacklistedToken.jti == jti)
        )
        if blacklisted.scalar_one_or_none():
            logger.error("Token is blacklisted")
            raise credentials_exception
        
        # Get user with case-insensitive lookup, excluding soft-deleted users
        from sqlalchemy import func
        normalized_username = username.lower().strip()
        user = await db.execute(
            select(User).where(
                func.lower(User.username) == normalized_username,
                User.is_deleted == False  # Exclude soft-deleted users
            )
        )
        user = user.scalar_one_or_none()
        
        if not user:
            logger.error(f"User not found or deleted: {username}")
            raise credentials_exception
        
        # Check if account is locked
        if user.locked_until and user.locked_until > datetime.now(timezone.utc):
            logger.error(f"Account locked for user: {username}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is temporarily locked due to multiple failed login attempts"
            )
        
        # Update premium status if expired
        if user.is_premium and user.premium_expiry and user.premium_expiry < datetime.now(timezone.utc):
            user.is_premium = False
            await db.commit()
            await db.refresh(user)
        
        # Skip user caching for now to avoid model serialization issues
        # TODO: Implement proper user caching later
        
        return user
        
    except (InvalidTokenError, ExpiredSignatureError, DecodeError) as e:
        logger.error(f"Token validation error: {str(e)}")
        raise credentials_exception
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in token validation: {str(e)}")
        raise credentials_exception


async def blacklist_token(token: str, db: AsyncSession, user_id: int = None) -> None:
    """Add token to blacklist with expiration"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        jti = payload.get("jti")
        exp = payload.get("exp")
        
        if not jti or not exp:
            logger.warning("Cannot blacklist token: missing jti or exp")
            return
        
        # Convert exp to datetime
        expires_at = datetime.fromtimestamp(exp, tz=timezone.utc)
        
        # Add to blacklist with optional user_id for account deletion tracking
        blacklisted_token = BlacklistedToken(
            jti=jti,
            expires_at=expires_at,
            user_id=user_id
        )
        db.add(blacklisted_token)
        await db.commit()
        
    except Exception as e:
        logger.error(f"Error blacklisting token: {str(e)}")
        raise


async def cleanup_expired_blacklisted_tokens(db: AsyncSession) -> None:
    """Remove expired tokens from blacklist"""
    try:
        from sqlalchemy import delete
        
        now = datetime.now(timezone.utc)
        result = await db.execute(
            delete(BlacklistedToken).where(BlacklistedToken.expires_at < now)
        )
        
        deleted_count = result.rowcount
        await db.commit()
        
        if deleted_count > 0:
            logger.info(f"Cleaned up {deleted_count} expired blacklisted tokens")
            
    except Exception as e:
        logger.error(f"Error cleaning up blacklisted tokens: {str(e)}")
        await db.rollback()


async def get_google_user_info(code: str) -> dict:
    """Get user info from Google OAuth with timeout and error handling"""
    timeout = httpx.Timeout(30.0)  # 30 second timeout
    
    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            logger.debug(f"Exchanging Google code: {code[:10]}...")
            
            # Exchange code for token
            token_response = await client.post(
                GOOGLE_TOKEN_URL,
                data={
                    "code": code,
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "redirect_uri": GOOGLE_REDIRECT_URI,
                    "grant_type": "authorization_code",
                },
                headers={"Accept": "application/json"}
            )
            
            if token_response.status_code != 200:
                logger.error(f"Google token exchange failed: {token_response.status_code} - {token_response.text}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Google authentication failed"
                )
            
            token_data = token_response.json()
            access_token = token_data.get("access_token")
            
            if not access_token:
                logger.error("No access token in Google response")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to obtain Google access token"
                )
            
            # Get user info
            user_response = await client.get(
                GOOGLE_USERINFO_URL,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            
            user_response.raise_for_status()
            user_info = user_response.json()
            
            # Validate required fields
            if not user_info.get("email"):
                logger.error("No email in Google user info")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email not provided by Google"
                )
            
            # Validate email format
            email = user_info["email"]
            if not email or "@" not in email:
                logger.error(f"Invalid email from Google: {email}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid email from Google"
                )
            
            return user_info
            
        except httpx.TimeoutException:
            logger.error("Google API timeout")
            raise HTTPException(
                status_code=status.HTTP_408_REQUEST_TIMEOUT,
                detail="Google authentication timed out"
            )
        except httpx.HTTPStatusError as e:
            logger.error(f"Google API HTTP error: {e.response.status_code} - {e.response.text}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Google API error"
            )
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Unexpected error during Google OAuth: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Google authentication failed"
            )


async def create_or_update_google_user(user_info: dict, db: AsyncSession) -> User:
    """Create or update user from Google OAuth data with transaction safety"""
    try:
        email = user_info["email"].lower().strip()  # Normalize email
        first_name = (user_info.get("given_name", "") or "").strip()[:100]
        last_name = (user_info.get("family_name", "") or "").strip()[:100]
        
        # Generate unique username
        base_username = email.split("@")[0]
        username = f"{base_username}_{str(uuid.uuid4())[:8]}"
        
        logger.debug(f"Processing Google user: email={email}")
        
        # Check if user exists (including soft-deleted)
        result = await db.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()
        
        if user:
            # If user was soft-deleted, restore them
            if user.is_deleted:
                logger.info(f"Restoring soft-deleted Google user: {email}")
                await db.execute(
                    update(User)
                    .where(User.email == email)
                    .values(
                        first_name=first_name,
                        last_name=last_name,
                        is_deleted=False,
                        deleted_at=None,
                        deletion_reason=None,
                        updated_at=datetime.now(timezone.utc)
                    )
                )
            else:
                # Update existing active user
                await db.execute(
                    update(User)
                    .where(User.email == email)
                    .values(
                        first_name=first_name,
                        last_name=last_name,
                        updated_at=datetime.now(timezone.utc)
                    )
                )
            logger.info(f"Updated existing Google user: {email}")
        else:
            # Create new user
            await db.execute(
                insert(User).values(
                    username=username,
                    email=email,
                    first_name=first_name,
                    last_name=last_name,
                    hashed_password=None,  # OAuth users don't have passwords
                    is_github_connected=False
                )
            )
            logger.info(f"Created new Google user: {email}")
        
        # Commit the transaction
        await db.commit()
        
        # Get the user (refresh after transaction)
        result = await db.execute(select(User).where(User.email == email))
        return result.scalar_one()
        
    except Exception as e:
        logger.error(f"Database error in create_or_update_google_user: {str(e)}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process Google user"
        )


async def get_github_user_info(code: str) -> dict:
    """Get user info from GitHub OAuth with comprehensive error handling"""
    timeout = httpx.Timeout(30.0)
    
    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            logger.debug(f"Exchanging GitHub code: {code[:10]}...")
            
            # Exchange code for token
            token_response = await client.post(
                GITHUB_TOKEN_URL,
                data={
                    "code": code,
                    "client_id": GITHUB_CLIENT_ID,
                    "client_secret": GITHUB_CLIENT_SECRET,
                    "redirect_uri": GITHUB_REDIRECT_URI,
                },
                headers={"Accept": "application/json"}
            )
            
            if token_response.status_code != 200:
                logger.error(f"GitHub token exchange failed: {token_response.status_code} - {token_response.text}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="GitHub authentication failed"
                )
            
            token_data = token_response.json()
            access_token = token_data.get("access_token")
            
            if not access_token:
                logger.error("No access token in GitHub response")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to obtain GitHub access token"
                )
            
            # Get user info
            user_response = await client.get(
                GITHUB_USERINFO_URL,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            
            user_response.raise_for_status()
            user_info = user_response.json()
            
            # Get email if not in user info
            if not user_info.get("email"):
                email_response = await client.get(
                    "https://api.github.com/user/emails",
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                
                if email_response.status_code == 200:
                    emails = email_response.json()
                    primary_email = next((e['email'] for e in emails if e.get('primary')), None)
                    if primary_email:
                        user_info["email"] = primary_email
            
            # Validate email
            if not user_info.get("email"):
                logger.error("No email available from GitHub")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email not available from GitHub"
                )
            
            # Add access token to user info
            user_info["access_token"] = access_token
            return user_info
            
        except httpx.TimeoutException:
            logger.error("GitHub API timeout")
            raise HTTPException(
                status_code=status.HTTP_408_REQUEST_TIMEOUT,
                detail="GitHub authentication timed out"
            )
        except httpx.HTTPStatusError as e:
            logger.error(f"GitHub API HTTP error: {e.response.status_code} - {e.response.text}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="GitHub API error"
            )
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Unexpected error during GitHub OAuth: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="GitHub authentication failed"
            )


async def create_or_update_github_user(user_info: dict, db: AsyncSession) -> User:
    """Create or update user from GitHub OAuth data"""
    try:
        email = user_info["email"].lower().strip()
        
        # Parse name safely
        full_name = (user_info.get("name") or "").strip()
        if full_name and " " in full_name:
            name_parts = full_name.split(" ", 1)
            first_name = name_parts[0][:100]
            last_name = name_parts[1][:100]
        else:
            first_name = full_name[:100] if full_name else ""
            last_name = ""
        
        logger.debug(f"Processing GitHub user: email={email}")
        
        # Encrypt access token
        access_token_enc = encrypt_token(user_info["access_token"])
        
        # Check if user exists (including soft-deleted)
        result = await db.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()
        
        if user:
            # If user was soft-deleted, restore them
            if user.is_deleted:
                logger.info(f"Restoring soft-deleted GitHub user: {email}")
                await db.execute(
                    update(User)
                    .where(User.email == email)
                    .values(
                        first_name=first_name,
                        last_name=last_name,
                        github_access_token=access_token_enc,
                        is_github_connected=True,
                        is_deleted=False,
                        deleted_at=None,
                        deletion_reason=None,
                        updated_at=datetime.now(timezone.utc)
                    )
                )
            else:
                # Update existing active user
                await db.execute(
                    update(User)
                    .where(User.email == email)
                    .values(
                        first_name=first_name,
                        last_name=last_name,
                        github_access_token=access_token_enc,
                        is_github_connected=True,
                        updated_at=datetime.now(timezone.utc)
                    )
                )
            logger.info(f"Updated GitHub user: {email}")
        else:
            # Generate unique username
            base_username = user_info.get("login", email.split("@")[0])
            username = base_username
            suffix = 1
            
            # Ensure username uniqueness
            while True:
                existing = await db.execute(select(User).where(User.username == username))
                if not existing.scalar_one_or_none():
                    break
                username = f"{base_username}_{suffix}"
                suffix += 1
            
            # Create new user
            await db.execute(
                insert(User).values(
                    username=username,
                    email=email,
                    first_name=first_name,
                    last_name=last_name,
                    hashed_password=None,
                    github_access_token=access_token_enc,
                    is_github_connected=True
                )
            )
            logger.info(f"Created GitHub user: {username}")
        
        # Commit the transaction
        await db.commit()
        
        # Get the user (refresh after transaction)
        result = await db.execute(select(User).where(User.email == email))
        return result.scalar_one()
        
    except Exception as e:
        logger.error(f"Database error in create_or_update_github_user: {str(e)}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process GitHub user"
        )


async def generate_reset_token(username: str, db: AsyncSession) -> str:
    """Generate secure password reset token"""
    try:
        logger.info(f"Generating reset token for user: {username}")
        
        # Use case-insensitive lookup
        from sqlalchemy import func
        normalized_username = username.lower().strip()
        user = await db.execute(select(User).where(
        func.lower(User.username) == normalized_username,
        User.is_deleted == False
    ))
        user = user.scalar_one_or_none()
        
        if not user:
            logger.warning(f"User not found for reset: {username}")
            raise HTTPException(status_code=404, detail="User not found")
        
        # Generate secure token
        reset_token = secrets.token_urlsafe(32)
        expires = datetime.now(timezone.utc) + timedelta(hours=1)
        
        # Update user with reset token
        await db.execute(
            update(User)
            .where(User.id == user.id)
            .values(
                reset_password_token=reset_token,
                reset_password_expires=expires
            )
        )
        await db.commit()
        
        logger.info(f"Reset token generated for user: {username}")
        return reset_token
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error generating reset token: {str(e)}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate reset token"
        )


async def verify_reset_token(token: str, db: AsyncSession) -> User:
    """Verify password reset token"""
    try:
        logger.info(f"Verifying reset token: {token[:10]}...")
        
        now = datetime.now(timezone.utc)
        user = await db.execute(
            select(User).where(
                and_(
                    User.reset_password_token == token,
                    User.reset_password_expires > now
                )
            )
        )
        user = user.scalar_one_or_none()
        
        if not user:
            logger.warning(f"Invalid or expired reset token: {token[:10]}...")
            raise HTTPException(status_code=400, detail="Invalid or expired token")
        
        return user
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error verifying reset token: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token verification failed"
        )


def get_client_ip(request: Request) -> str:
    """Extract client IP address from request headers"""
    # Check for forwarded headers (common in load balancers/proxies)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # X-Forwarded-For can contain multiple IPs, take the first one
        return forwarded_for.split(",")[0].strip()
    
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    
    # Fallback to direct connection IP
    return request.client.host if request.client else "unknown"


def get_user_agent(request: Request) -> str:
    """Extract user agent from request headers"""
    return request.headers.get("User-Agent", "unknown")[:500]  # Truncate long user agents


async def rate_limit_check(ip_address: str, db: AsyncSession, window_minutes: int = 15, max_attempts: int = 10) -> bool:
    """Check if IP address is rate limited for login attempts with caching"""
    try:
        # Try cache first for performance
        rate_key = f"rate_limit:login:{ip_address}"
        cached_count = await RateLimitCache.get_counter(rate_key)
        
        if cached_count >= max_attempts:
            return True
        
        # If cache miss or low count, check database for accuracy
        cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        
        from sqlalchemy import func
        result = await db.execute(
            select(func.count(LoginAttempt.id))
            .where(
                and_(
                    LoginAttempt.ip_address == ip_address,
                    LoginAttempt.success == False,
                    LoginAttempt.created_at > cutoff_time
                )
            )
        )
        
        attempt_count = result.scalar() or 0
        
        # Update cache with accurate count
        await cache.set(rate_key, attempt_count, window_minutes * 60)
        
        return attempt_count >= max_attempts
        
    except Exception as e:
        logger.error(f"Error checking rate limit: {str(e)}")
        # Fail open - don't block on rate limit errors
        return False


async def get_current_user_from_token(token: str) -> Optional[User]:
    """Get current user from token string (for Socket.IO authentication)"""
    try:
        from core.database import get_db
        
        # Decode and validate token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        # Validate required claims
        username: str = payload.get("sub")
        jti: str = payload.get("jti")
        token_type: str = payload.get("type")
        
        if not username or not jti or token_type != "access":
            return None
        
        # Get database session
        async for db in get_db():
            try:
                # Check if token is blacklisted
                blacklisted = await db.execute(
                    select(BlacklistedToken).where(BlacklistedToken.jti == jti)
                )
                if blacklisted.scalar_one_or_none():
                    return None
                
                # Get user with case-insensitive lookup
                from sqlalchemy import func
                normalized_username = username.lower().strip()
                user = await db.execute(select(User).where(
        func.lower(User.username) == normalized_username,
        User.is_deleted == False
    ))
                user = user.scalar_one_or_none()
                
                if not user:
                    return None
                
                # Check if account is locked
                if user.locked_until and user.locked_until > datetime.now(timezone.utc):
                    return None
                
                return user
                
            finally:
                await db.close()
        
        return None
        
    except Exception as e:
        logger.error(f"Socket token validation error: {str(e)}")
        return None


def get_api_key_from_header(request: Request) -> Optional[str]:
    """Extract API key from request headers"""
    # Try X-API-Key header first
    api_key = request.headers.get("X-API-Key")
    if api_key:
        return api_key
    
    # Try Authorization header with Bearer format
    authorization = request.headers.get("Authorization")
    if authorization and authorization.startswith("Bearer "):
        return authorization[7:]  # Remove "Bearer " prefix
    
    return None


async def get_current_user_and_api_key(
    x_api_key: str = Header(None, alias="X-API-Key"),
    authorization: str = Header(None),
    db: AsyncSession = Depends(get_db)
) -> tuple[User, Optional[int]]:
    """Get current user and API key ID from API key header"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "API-Key"},
    )
    
    # Extract API key from X-API-Key header or Authorization header
    api_key = None
    if x_api_key:
        api_key = x_api_key
    elif authorization and authorization.startswith("Bearer "):
        api_key = authorization[7:]  # Remove "Bearer " prefix
    
    if not api_key:
        raise credentials_exception
    
    # Validate API key format
    if not api_key.startswith("dsx_"):
        raise credentials_exception
    
    try:
        import hashlib
        from .models import ApiKey
        
        # Hash the provided API key
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        # Look up API key in database
        result = await db.execute(
            select(ApiKey).where(
                and_(
                    ApiKey.key_hash == key_hash,
                    ApiKey.is_active == True,
                    or_(
                        ApiKey.expires_at.is_(None),
                        ApiKey.expires_at > datetime.now(timezone.utc)
                    )
                )
            ).options(selectinload(ApiKey.user))
        )
        
        api_key_record = result.scalar_one_or_none()
        if not api_key_record:
            raise credentials_exception
        
        user = api_key_record.user
        if not user or user.is_deleted:
            raise credentials_exception
        
        # Update last used timestamp
        api_key_record.last_used_at = datetime.now(timezone.utc)
        await db.commit()
        
        return user, api_key_record.id
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"API key validation error: {str(e)}")
        raise credentials_exception


async def get_current_user_from_api_key(
    x_api_key: str = Header(None, alias="X-API-Key"),
    authorization: str = Header(None),
    db: AsyncSession = Depends(get_db)
) -> User:
    """Get current user from API key header"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "API-Key"},
    )
    
    # Extract API key from X-API-Key header or Authorization header
    api_key = None
    if x_api_key:
        api_key = x_api_key
    elif authorization and authorization.startswith("Bearer "):
        # Support Bearer format for API keys
        api_key = authorization[7:]  # Remove "Bearer " prefix
    
    if not api_key:
        raise credentials_exception
    
    # Validate API key format
    if not api_key.startswith("dsx_"):
        raise credentials_exception
    
    try:
        import hashlib
        from .models import ApiKey
        
        # Hash the provided API key
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        # Look up API key in database
        result = await db.execute(
            select(ApiKey).where(
                and_(
                    ApiKey.key_hash == key_hash,
                    ApiKey.is_active == True,
                    or_(
                        ApiKey.expires_at.is_(None),
                        ApiKey.expires_at > datetime.now(timezone.utc)
                    )
                )
            ).options(selectinload(ApiKey.user))
        )
        
        api_key_record = result.scalar_one_or_none()
        if not api_key_record:
            raise credentials_exception
        
        user = api_key_record.user
        if not user or user.is_deleted:
            raise credentials_exception
        
        # Update last used timestamp
        api_key_record.last_used_at = datetime.now(timezone.utc)
        await db.commit()
        
        return user
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"API key validation error: {str(e)}")
        raise credentials_exception