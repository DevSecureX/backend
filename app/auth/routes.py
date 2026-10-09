from fastapi import APIRouter, Depends, HTTPException, status, Request, Body
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, EmailStr, field_validator, validator
from sqlalchemy import select, update, text, and_, func, delete
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta, timezone
import os
import json
import jwt
from jwt.exceptions import PyJWTError as JWTError

import razorpay
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, TrackingSettings, ClickTracking
import urllib.parse
import re
import secrets
import logging
from typing import Optional

from core.database import get_db
from core.config import (
    ACCESS_TOKEN_EXPIRE_MINUTES, GOOGLE_CLIENT_ID, GOOGLE_REDIRECT_URI, 
    FRONTEND_GOOGLE_REDIRECT_URL, RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET, 
    GITHUB_CLIENT_ID, GITHUB_REDIRECT_URI, SECRET_KEY, ALGORITHM,
    TESTING_MODE, APP_ENV, RATE_LIMIT_LOGIN_ATTEMPTS, RATE_LIMIT_LOGIN_WINDOW,
    RATE_LIMIT_SIGNUP_ATTEMPTS, RATE_LIMIT_SIGNUP_WINDOW,
    RATE_LIMIT_PASSWORD_RESET_ATTEMPTS, RATE_LIMIT_PASSWORD_RESET_WINDOW,
    RATE_LIMIT_MAIL_LIST_ATTEMPTS, RATE_LIMIT_MAIL_LIST_WINDOW
)
from auth.models import User, BlacklistedToken, Feedback, MailList, LoginAttempt, ApiKey
from auth.models import DataExportRequest as DataExportRequestModel
from auth.dependencies import (
    hash_password, verify_password, create_access_token, get_current_user,
    oauth2_scheme, get_google_user_info, create_or_update_google_user,
    get_github_user_info, create_or_update_github_user, verify_reset_token,
    encrypt_token, decrypt_token, check_account_lockout, record_login_attempt,
    blacklist_token, get_client_ip, get_user_agent, rate_limit_check,
    cleanup_expired_blacklisted_tokens, get_current_user_from_api_key
)

logger = logging.getLogger(__name__)

# Initialize Razorpay client with error handling
try:
    razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
except Exception as e:
    logger.error(f"Failed to initialize Razorpay client: {str(e)}")
    razorpay_client = None

auth_router = APIRouter(prefix="/auth", tags=["auth"])
frontend_url = os.getenv("FRONTEND_URI")

# Enhanced Pydantic models with better validation
class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str
    
    @field_validator("token")
    @classmethod
    def validate_token(cls, v: str) -> str:
        if not v or len(v) < 10:
            raise ValueError("Invalid token format")
        return v
    
    @field_validator("new_password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"[0-9]", v):
            raise ValueError("Password must contain at least one digit")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError("Password must contain at least one special character")
        return v

class UserCreate(BaseModel):
    username: str
    password: str
    email: EmailStr
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    mobile_no: Optional[str] = None
    
    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not (3 <= len(v) <= 50):
            raise ValueError("Username must be between 3 and 50 characters")
        
        # Allow alphanumeric, underscore, hyphen, and dots
        if not re.match(r"^[a-zA-Z0-9._-]+$", v):
            raise ValueError("Username can only contain letters, numbers, dots, underscores, and hyphens")
        
        # Don't allow only dots/underscores/hyphens
        if re.match(r"^[._-]+$", v):
            raise ValueError("Username must contain at least one letter or number")
        
        return v.lower()  # Normalize to lowercase
    
    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if len(v) > 128:  # Reasonable upper limit
            raise ValueError("Password must be less than 128 characters")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"[0-9]", v):
            raise ValueError("Password must contain at least one digit")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError("Password must contain at least one special character")
        
        # Check for common weak patterns
        if v.lower() in ["password", "123456789", "qwertyuiop"]:
            raise ValueError("Password is too common")
        
        return v
    
    @field_validator("mobile_no")
    @classmethod
    def validate_mobile_no(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        
        # Remove any spaces or hyphens
        cleaned = re.sub(r"[\s-]", "", v)
        
        if not re.match(r"^\+?[1-9]\d{6,14}$", cleaned):
            raise ValueError("Mobile number must be 7-15 digits, optionally starting with '+'")
        
        return cleaned
    
    @field_validator("first_name", "last_name")
    @classmethod
    def validate_names(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        
        cleaned = v.strip()
        if len(cleaned) > 100:
            raise ValueError("Name must be less than 100 characters")
        
        # Allow letters, spaces, hyphens, apostrophes
        if not re.match(r"^[a-zA-Z\s'-]*$", cleaned):
            raise ValueError("Name can only contain letters, spaces, hyphens, and apostrophes")
        
        return cleaned

class MemberDetails(BaseModel):
    id: int
    username: str
    first_name: str
    last_name: str
    email: str
    mobile_no: Optional[str]
    is_premium: bool
    premium_expiry: Optional[datetime]

class Token(BaseModel):
    access_token: str
    token_type: str
    member_details: MemberDetails

class ProfileUpdate(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    mobile_no: Optional[str] = None
    
    @field_validator("mobile_no")
    @classmethod
    def validate_mobile_no(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        
        cleaned = re.sub(r"[\s-]", "", v)
        if not re.match(r"^\+?[1-9]\d{6,14}$", cleaned):
            raise ValueError("Mobile number must be 7-15 digits, optionally starting with '+'")
        
        return cleaned
    
    @field_validator("first_name", "last_name")
    @classmethod
    def validate_names(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        
        cleaned = v.strip()
        if len(cleaned) > 100:
            raise ValueError("Name must be less than 100 characters")
        
        if not re.match(r"^[a-zA-Z\s'-]*$", cleaned):
            raise ValueError("Name can only contain letters, spaces, hyphens, and apostrophes")
        
        return cleaned

class MailCreate(BaseModel):
    email: EmailStr

class FeedbackCreate(BaseModel):
    feedback: str
    priority: Optional[str] = "medium"
    
    @field_validator("feedback")
    @classmethod
    def validate_feedback(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Feedback cannot be empty")
        if len(cleaned) < 10:
            raise ValueError("Feedback must be at least 10 characters long")
        if len(cleaned) > 5000:
            raise ValueError("Feedback must be less than 5000 characters")
        return cleaned
    
    @field_validator("priority")
    @classmethod
    def validate_priority(cls, v: str) -> str:
        allowed_priorities = ["low", "medium", "high", "critical"]
        if v not in allowed_priorities:
            raise ValueError(f"Priority must be one of: {', '.join(allowed_priorities)}")
        return v

class CreateOrderRequest(BaseModel):
    plan: str
    amount: int
    
    @field_validator("plan")
    @classmethod
    def validate_plan(cls, v: str) -> str:
        if v not in ["monthly", "premium", "annual"]:
            raise ValueError("Plan must be either 'monthly', 'premium', or 'annual'")
        return v
    
    @field_validator("amount")
    @classmethod
    def validate_amount(cls, v: int) -> int:
        if v not in [9900, 29900, 99900]:  # ₹99, ₹299 and ₹999 in paise
            raise ValueError("Invalid amount")
        return v

class VerifyPaymentRequest(BaseModel):
    razorpay_order_id: str
    razorpay_payment_id: str
    razorpay_signature: str
    
    @field_validator("razorpay_order_id", "razorpay_payment_id", "razorpay_signature")
    @classmethod
    def validate_razorpay_fields(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Razorpay field cannot be empty")
        return v.strip()

class UserDetailsResponse(BaseModel):
    username: str
    email: str
    is_premium: bool
    premium_expiry: Optional[datetime]
    is_github_connected: bool

class TimezonePreferencesResponse(BaseModel):
    timezone: str
    date_format: str
    time_format: str
    show_relative_dates: bool
    show_timezone_abbreviations: bool
    preferences_updated_at: Optional[datetime]

class TimezonePreferencesUpdate(BaseModel):
    timezone: Optional[str] = None
    date_format: Optional[str] = None  
    time_format: Optional[str] = None
    show_relative_dates: Optional[bool] = None
    show_timezone_abbreviations: Optional[bool] = None
    
    @field_validator("timezone")
    @classmethod
    def validate_timezone(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        # Basic timezone validation - could be enhanced with pytz
        if not v or len(v) < 3 or len(v) > 50:
            raise ValueError("Invalid timezone format")
        return v
    
    @field_validator("time_format")
    @classmethod
    def validate_time_format(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        if v not in ["12h", "24h"]:
            raise ValueError("Time format must be '12h' or '24h'")
        return v


class NotificationPreferencesResponse(BaseModel):
    email_notifications: bool
    security_alerts: bool
    scan_completion_notifications: bool
    weekly_reports: bool
    marketing_emails: bool
    notification_preferences_updated_at: Optional[datetime]


class NotificationPreferencesUpdate(BaseModel):
    email_notifications: Optional[bool] = None
    security_alerts: Optional[bool] = None
    scan_completion_notifications: Optional[bool] = None
    weekly_reports: Optional[bool] = None
    marketing_emails: Optional[bool] = None


class ApiKeyCreate(BaseModel):
    name: str
    scopes: Optional[list[str]] = ["read"]
    expires_in_days: Optional[int] = None  # Optional expiration
    
    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not v or len(v.strip()) < 3:
            raise ValueError("API key name must be at least 3 characters")
        if len(v) > 100:
            raise ValueError("API key name must be less than 100 characters")
        return v.strip()
    
    @field_validator("scopes")
    @classmethod
    def validate_scopes(cls, v: Optional[list[str]]) -> list[str]:
        if not v:
            return ["read"]
        valid_scopes = {"read", "write", "scan", "admin"}
        for scope in v:
            if scope not in valid_scopes:
                raise ValueError(f"Invalid scope: {scope}. Valid scopes: {', '.join(valid_scopes)}")
        return v


class ApiKeyResponse(BaseModel):
    id: int
    name: str
    key_prefix: str
    scopes: list[str]
    is_active: bool
    last_used_at: Optional[datetime]
    usage_count: int
    created_at: datetime
    expires_at: Optional[datetime]


class ApiKeyCreateResponse(BaseModel):
    id: int
    name: str
    key: str  # Full key shown only once
    key_prefix: str
    scopes: list[str]
    created_at: datetime
    expires_at: Optional[datetime]


class AccountDeletionRequest(BaseModel):
    deletion_reason: Optional[str] = None
    
    @field_validator("deletion_reason")
    @classmethod
    def validate_deletion_reason(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v = v.strip()
            if len(v) > 255:
                raise ValueError("Deletion reason must be 255 characters or less")
        return v


class DataExportRequestInput(BaseModel):
    export_type: str = "full"
    file_format: str = "json"
    include_personal_data: bool = True
    include_scan_data: bool = True
    include_repository_data: bool = True
    
    @field_validator("export_type")
    @classmethod
    def validate_export_type(cls, v: str) -> str:
        valid_types = {"full", "personal_only", "scans_only", "repositories_only"}
        if v not in valid_types:
            raise ValueError(f"Invalid export type. Valid types: {', '.join(valid_types)}")
        return v
    
    @field_validator("file_format")
    @classmethod
    def validate_file_format(cls, v: str) -> str:
        valid_formats = {"json", "csv", "xml"}
        if v not in valid_formats:
            raise ValueError(f"Invalid file format. Valid formats: {', '.join(valid_formats)}")
        return v


class DataExportResponse(BaseModel):
    id: int
    export_type: str
    status: str
    file_format: str
    include_personal_data: bool
    include_scan_data: bool
    include_repository_data: bool
    total_records: Optional[int]
    exported_records: Optional[int]
    file_size_bytes: Optional[int]
    requested_at: datetime
    processing_started_at: Optional[datetime]
    completed_at: Optional[datetime]
    download_expires_at: Optional[datetime]
    error_message: Optional[str]


# Enhanced signup endpoint with rate limiting and validation
@auth_router.post("/signup", response_model=dict)
async def signup(
    user: UserCreate, 
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    logger.info(f"Signup attempt for username: {user.username}")
    
    # Rate limiting by IP
    client_ip = get_client_ip(request)
    if await rate_limit_check(client_ip, db, window_minutes=RATE_LIMIT_SIGNUP_WINDOW, max_attempts=RATE_LIMIT_SIGNUP_ATTEMPTS):
        logger.warning(f"Signup rate limit exceeded for IP: {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many signup attempts. Please try again later."
        )
    
    try:
        # Check for existing user with case-insensitive username lookup
        from sqlalchemy import func
        normalized_username = user.username.lower().strip()
        
        existing = await db.execute(
            select(User).where(
                and_(
                    ((func.lower(User.username) == normalized_username) | 
                     (func.lower(User.email) == user.email.lower())),
                    User.is_deleted == False
                )
            )
        )
        existing_user = existing.scalar_one_or_none()
        
        if existing_user:
            if existing_user.username.lower() == normalized_username:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT, 
                    detail="Username already exists"
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT, 
                    detail="Email already exists"
                )
        
        # Create user
        hashed_password = hash_password(user.password)
        
        db_user = User(
            username=normalized_username,  # Use normalized username for consistency
            hashed_password=hashed_password,
            first_name=user.first_name or "",
            last_name=user.last_name or "",
            email=user.email.lower(),  # Normalize email
            mobile_no=user.mobile_no
        )
        
        db.add(db_user)
        await db.commit()
        await db.refresh(db_user)
        
        logger.info(f"User created successfully: {user.username}")
        return {"message": "User created successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating user: {str(e)}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user"
        )


# Enhanced login endpoint with security features
@auth_router.post("/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(), 
    request: Request = None,
    db: AsyncSession = Depends(get_db)
):
    client_ip = get_client_ip(request)
    user_agent = get_user_agent(request)
    
    logger.info(f"Login attempt for user: {form_data.username} from IP: {client_ip}")
    
    # Rate limiting by IP
    if await rate_limit_check(client_ip, db, window_minutes=RATE_LIMIT_LOGIN_WINDOW, max_attempts=RATE_LIMIT_LOGIN_ATTEMPTS):
        logger.warning(f"Login rate limit exceeded for IP: {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please try again later."
        )
    
    # Check account lockout
    if await check_account_lockout(form_data.username, db):
        await record_login_attempt(form_data.username, False, client_ip, user_agent, db)
        logger.warning(f"Login attempt on locked account: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is temporarily locked due to multiple failed login attempts"
        )
    
    try:
        # Get user with case-insensitive lookup
        from sqlalchemy import func
        normalized_username = form_data.username.lower().strip()
        
        user = await db.execute(
            select(User).where(
                and_(
                    ((func.lower(User.username) == normalized_username) | 
                     (func.lower(User.email) == normalized_username)),
                    User.is_deleted == False
                )
            )
        )
        user = user.scalar_one_or_none()
        
        # Verify credentials
        if not user or not verify_password(form_data.password, user.hashed_password):
            await record_login_attempt(form_data.username, False, client_ip, user_agent, db)
            logger.warning(f"Invalid login attempt for: {form_data.username}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Record successful login
        await record_login_attempt(form_data.username, True, client_ip, user_agent, db)
        
        # Create token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={
                "sub": user.username, 
                "user_id": user.id,
                "is_github_connected": user.is_github_connected
            },
            expires_delta=access_token_expires
        )
        
        logger.info(f"User logged in successfully: {form_data.username}")
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "member_details": {
                "id": user.id,
                "username": user.username,
                "first_name": user.first_name or "",
                "last_name": user.last_name or "",
                "email": user.email,
                "mobile_no": user.mobile_no,
                "is_premium": user.is_premium,
                "premium_expiry": user.premium_expiry
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error for {form_data.username}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed"
        )


# Enhanced logout endpoint
@auth_router.post("/logout", response_model=dict)
async def logout(
    token: str = Depends(oauth2_scheme), 
    db: AsyncSession = Depends(get_db)
):
    logger.info("Logout attempt")
    
    try:
        await blacklist_token(token, db)
        logger.info("User logged out successfully")
        return {"message": "Logout successful"}
        
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        # Don't fail logout on blacklist errors
        return {"message": "Logout completed"}


# Token validation endpoint
@auth_router.get("/validate-token", response_model=MemberDetails)
async def validate_token(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "first_name": current_user.first_name or "",
        "last_name": current_user.last_name or "",
        "email": current_user.email,
        "mobile_no": current_user.mobile_no,
        "is_premium": current_user.is_premium,
        "premium_expiry": current_user.premium_expiry,
    }


# API Key validation endpoint
@auth_router.get("/validate-api-key", response_model=MemberDetails)
async def validate_api_key(current_user: User = Depends(get_current_user_from_api_key)):
    """Validate API key and return user details"""
    return {
        "id": current_user.id,
        "username": current_user.username,
        "first_name": current_user.first_name or "",
        "last_name": current_user.last_name or "",
        "email": current_user.email,
        "mobile_no": current_user.mobile_no,
        "is_premium": current_user.is_premium,
        "premium_expiry": current_user.premium_expiry,
        "scopes": ["read", "scan", "write"] if current_user.is_premium else ["read"],
        "expires_at": None  # Could be enhanced to show API key expiry
    }


# Google OAuth endpoints (enhanced error handling)
@auth_router.get("/google/login")
async def google_login():
    if not GOOGLE_CLIENT_ID or not GOOGLE_REDIRECT_URI:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Google OAuth not configured"
        )
    
    google_auth_url = (
        f"https://accounts.google.com/o/oauth2/v2/auth?"
        f"client_id={GOOGLE_CLIENT_ID}&"
        f"redirect_uri={urllib.parse.quote(GOOGLE_REDIRECT_URI)}&"
        f"response_type=code&"
        f"scope=openid%20email%20profile&"
        f"access_type=offline&"
        f"prompt=select_account"  # Force account selection
    )
    
    logger.debug("Redirecting to Google OAuth")
    return RedirectResponse(url=google_auth_url)


@auth_router.get("/google/callback")
async def google_callback(
    code: str = None, 
    state: str = None, 
    error: str = None,
    request: Request = None, 
    db: AsyncSession = Depends(get_db)
):
    logger.info(f"Google callback: code={'present' if code else 'missing'}, error={error}")
    
    if error:
        logger.error(f"Google OAuth error: {error}")
        error_url = f"{frontend_url}/login?error={urllib.parse.quote('Google authentication failed')}"
        return RedirectResponse(error_url)
    
    if not code:
        logger.error("Missing authorization code in Google callback")
        error_url = f"{frontend_url}/login?error={urllib.parse.quote('Authorization failed')}"
        return RedirectResponse(error_url)
    
    try:
        # Get user info from Google
        user_info = await get_google_user_info(code)
        user = await create_or_update_google_user(user_info, db)
        
        # Create token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={
                "sub": user.username, 
                "user_id": user.id,
                "is_github_connected": user.is_github_connected
            },
            expires_delta=access_token_expires
        )
        
        logger.info(f"Google OAuth successful for user: {user.username}")
        
        # Prepare member details
        member_details = {
            "id": user.id,
            "username": user.username,
            "first_name": user.first_name or "",
            "last_name": user.last_name or "",
            "email": user.email,
            "mobile_no": user.mobile_no or "",
            "is_premium": str(user.is_premium).lower(),
            "premium_expiry": user.premium_expiry.isoformat() if user.premium_expiry else "",
        }
        
        # Redirect to frontend
        frontend_callback_url = FRONTEND_GOOGLE_REDIRECT_URL
        if not frontend_callback_url:
            raise HTTPException(status_code=500, detail="Frontend redirect URL not configured")
        
        query_params = {
            "access_token": access_token,
            "token_type": "bearer",
            **member_details,
            "state": state or ""
        }
        
        redirect_url = f"{frontend_callback_url}?{urllib.parse.urlencode(query_params, safe='')}"
        return RedirectResponse(redirect_url)
        
    except HTTPException as e:
        logger.error(f"HTTP error in Google callback: {e.detail}")
        error_url = f"{frontend_url}/login?error={urllib.parse.quote(str(e.detail))}"
        return RedirectResponse(error_url)
    except Exception as e:
        logger.error(f"Unexpected error in Google callback: {str(e)}")
        error_url = f"{frontend_url}/login?error={urllib.parse.quote('Authentication failed')}"
        return RedirectResponse(error_url)


# GitHub OAuth endpoints (similar enhancements)
@auth_router.get("/github/login")
async def github_login():
    # Debug logging for GitHub OAuth configuration
    logger.debug(f"GitHub OAuth Debug - GITHUB_CLIENT_ID: {'SET' if GITHUB_CLIENT_ID else 'NOT SET'}")
    logger.debug(f"GitHub OAuth Debug - GITHUB_REDIRECT_URI: {'SET' if GITHUB_REDIRECT_URI else 'NOT SET'}")
    logger.debug(f"GitHub OAuth Debug - GITHUB_CLIENT_ID value: {GITHUB_CLIENT_ID}")
    logger.debug(f"GitHub OAuth Debug - GITHUB_REDIRECT_URI value: {GITHUB_REDIRECT_URI}")
    
    if not GITHUB_CLIENT_ID or not GITHUB_REDIRECT_URI:
        error_msg = f"GitHub OAuth not configured - CLIENT_ID: {'SET' if GITHUB_CLIENT_ID else 'NOT SET'}, REDIRECT_URI: {'SET' if GITHUB_REDIRECT_URI else 'NOT SET'}"
        logger.error(error_msg)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="GitHub OAuth not configured"
        )
    
    # Generate state for CSRF protection
    state = secrets.token_urlsafe(32)
    
    github_auth_url = (
        f"https://github.com/login/oauth/authorize?"
        f"client_id={GITHUB_CLIENT_ID}&"
        f"redirect_uri={urllib.parse.quote(GITHUB_REDIRECT_URI)}&"
        f"scope=user%20repo&"
        f"state={state}"
    )
    
    logger.debug("Redirecting to GitHub OAuth")
    return RedirectResponse(url=github_auth_url)


@auth_router.get("/github/callback")
async def github_callback(
    code: str = None, 
    state: str = None, 
    error: str = None,
    request: Request = None, 
    db: AsyncSession = Depends(get_db)
):
    logger.info(f"GitHub callback: code={'present' if code else 'missing'}, error={error}")
    
    if error:
        logger.error(f"GitHub OAuth error: {error}")
        error_url = f"{frontend_url}/login?error={urllib.parse.quote('GitHub authentication failed')}"
        return RedirectResponse(error_url)
    
    if not code:
        logger.error("Missing authorization code in GitHub callback")
        error_url = f"{frontend_url}/login?error={urllib.parse.quote('Authorization failed')}"
        return RedirectResponse(error_url)
    
    try:
        # Get user info from GitHub
        user_info = await get_github_user_info(code)
        user = await create_or_update_github_user(user_info, db)
        
        # Create token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={
                "sub": user.username, 
                "user_id": user.id,
                "is_github_connected": user.is_github_connected
            },
            expires_delta=access_token_expires
        )
        
        logger.info(f"GitHub OAuth successful for user: {user.username}")
        
        # Redirect to frontend (similar to Google callback)
        frontend_callback_url = os.getenv("FRONTEND_GITHUB_REDIRECT_URL")
        if not frontend_callback_url:
            raise HTTPException(status_code=500, detail="Frontend redirect URL not configured")
        
        member_details = {
            "id": user.id,
            "username": user.username,
            "first_name": user.first_name or "",
            "last_name": user.last_name or "",
            "email": user.email,
            "mobile_no": user.mobile_no or "",
            "is_premium": str(user.is_premium).lower(),
            "premium_expiry": user.premium_expiry.isoformat() if user.premium_expiry else "",
            "is_github_connected": "true",
            "github_connected": "true"  # For backward compatibility
        }
        
        query_params = {
            "access_token": access_token,
            "token_type": "bearer",
            **member_details,
            "state": state or ""
        }
        
        redirect_url = f"{frontend_callback_url}?{urllib.parse.urlencode(query_params, safe='')}"
        return RedirectResponse(redirect_url)
        
    except HTTPException as e:
        logger.error(f"HTTP error in GitHub callback: {e.detail}")
        error_url = f"{frontend_url}/login?error={urllib.parse.quote(str(e.detail))}"
        return RedirectResponse(error_url)
    except Exception as e:
        logger.error(f"Unexpected error in GitHub callback: {str(e)}")
        error_url = f"{frontend_url}/login?error={urllib.parse.quote('Authentication failed')}"
        return RedirectResponse(error_url)


# Health check endpoint with enhanced checks
@auth_router.get("/health", response_model=dict)
async def health_check(db: AsyncSession = Depends(get_db)):
    status = {
        "status": "ok", 
        "database": False, 
        "services": {},
        "jwt_expire_minutes": ACCESS_TOKEN_EXPIRE_MINUTES,
        "app_env": APP_ENV,
        "hot_reload_auth_test": "Auth route hot reload verified! ✅"
    }
    
    try:
        # Test database connection
        await db.execute(text("SELECT 1"))
        status["database"] = True
        
        # Test Razorpay connection
        if razorpay_client:
            try:
                # This will throw an error if credentials are invalid
                razorpay_client.utility.verify_webhook_signature('{}', 'test', 'test')
            except razorpay.errors.SignatureVerificationError:
                # Expected error for test data
                status["services"]["razorpay"] = True
            except Exception:
                status["services"]["razorpay"] = False
        else:
            status["services"]["razorpay"] = False
        
        # Cleanup expired tokens periodically
        await cleanup_expired_blacklisted_tokens(db)
        
        logger.info("Health check passed")
        return status
        
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        status["status"] = "error"
        return status


# Enhanced password reset endpoints
@auth_router.post("/forgot-password", response_model=dict)
async def forgot_password(
    request_data: PasswordResetRequest, 
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    client_ip = get_client_ip(request)
    
    # Rate limiting for password reset requests
    if await rate_limit_check(client_ip, db, window_minutes=RATE_LIMIT_PASSWORD_RESET_WINDOW, max_attempts=RATE_LIMIT_PASSWORD_RESET_ATTEMPTS):
        logger.warning(f"Password reset rate limit exceeded for IP: {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many password reset requests. Please try again later."
        )
    
    try:
        result = await db.execute(select(User).where(
            and_(
                User.email == request_data.email.lower(),
                User.is_deleted == False
            )
        ))
        user = result.scalar_one_or_none()
        
        if not user:
            # Don't reveal whether email exists - return success anyway
            logger.info(f"Password reset requested for non-existent email: {request_data.email}")
            return {"message": "If this email is registered, you will receive a password reset link"}
        
        # Generate reset token
        token = secrets.token_urlsafe(32)
        expires = datetime.now(timezone.utc) + timedelta(hours=1)
        
        await db.execute(
            update(User)
            .where(User.id == user.id)
            .values(
                reset_password_token=token,
                reset_password_expires=expires
            )
        )
        await db.commit()
        
        # Send reset email
        reset_link = f"https://www.devsecurex.com/auth/reset-password?token={token}"
        
        message = Mail(
            from_email="support@devsecurex.com",
            to_emails=user.email,
            subject="Password Reset Request - DevSecureX",
            html_content=(
                f"<div style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;'>"
                f"<h2 style='color: #333;'>Password Reset Request</h2>"
                f"<p>Hi {user.first_name or 'there'},</p>"
                f"<p>You requested a password reset for your DevSecureX account. Click the button below to reset your password:</p>"
                f"<div style='text-align: center; margin: 30px 0;'>"
                f"<a href='{reset_link}' style='background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;'>Reset Password</a>"
                f"</div>"
                f"<p><strong>This link will expire in 1 hour.</strong></p>"
                f"<p>If you did not request this password reset, please ignore this email. Your password will remain unchanged.</p>"
                f"<p>For security reasons, this link can only be used once.</p>"
                f"<hr style='margin: 30px 0; border: none; border-top: 1px solid #eee;'>"
                f"<p style='color: #666; font-size: 12px;'>Best regards,<br>DevSecureX Security Team<br>Contact: support@devsecurex.com</p>"
                f"</div>"
            )
        )
        
        # Disable click tracking for security
        tracking_settings = TrackingSettings()
        tracking_settings.click_tracking = ClickTracking(enable=False, enable_text=False)
        message.tracking_settings = tracking_settings
        
        sendgrid_client = SendGridAPIClient(os.getenv("SENDGRID_API_KEY"))
        response = sendgrid_client.send(message)
        
        if response.status_code not in (200, 202):
            logger.error(f"SendGrid error: {response.status_code} - {response.body}")
            raise Exception(f"Email service error: {response.status_code}")
        
        logger.info(f"Password reset email sent to {user.email}")
        return {"message": "If this email is registered, you will receive a password reset link"}
        
    except Exception as e:
        logger.error(f"Password reset error: {str(e)}")
        # Don't expose internal errors
        return {"message": "If this email is registered, you will receive a password reset link"}


@auth_router.post("/reset-password", response_model=dict)
async def reset_password(
    request_data: PasswordResetConfirm, 
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    client_ip = get_client_ip(request)
    
    # Rate limiting for password reset attempts
    if await rate_limit_check(client_ip, db, window_minutes=RATE_LIMIT_PASSWORD_RESET_WINDOW, max_attempts=RATE_LIMIT_PASSWORD_RESET_ATTEMPTS):
        logger.warning(f"Password reset rate limit exceeded for IP: {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many password reset attempts. Please try again later."
        )
    
    try:
        # Verify reset token
        user = await verify_reset_token(request_data.token, db)
        
        # Check if new password is different from current
        if user.hashed_password and verify_password(request_data.new_password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New password must be different from your current password"
            )
        
        # Update password and clear reset token
        new_hashed_password = hash_password(request_data.new_password)
        
        await db.execute(
            update(User)
            .where(User.id == user.id)
            .values(
                hashed_password=new_hashed_password,
                reset_password_token=None,
                reset_password_expires=None,
                failed_login_attempts=0,  # Reset failed attempts
                locked_until=None,  # Unlock account
                updated_at=datetime.now(timezone.utc)
            )
        )
        await db.commit()
        
        logger.info(f"Password reset successful for user: {user.username}")
        return {"message": "Password reset successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password reset error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password reset failed"
        )


# Enhanced profile update endpoint
@auth_router.post("/update-profile", response_model=MemberDetails)
async def update_profile(
    profile: ProfileUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    logger.info(f"Profile update for user: {current_user.username}")
    
    try:
        # Prepare update values
        update_values = {"updated_at": datetime.now(timezone.utc)}
        
        if profile.first_name is not None:
            update_values["first_name"] = profile.first_name
        if profile.last_name is not None:
            update_values["last_name"] = profile.last_name
        if profile.mobile_no is not None:
            update_values["mobile_no"] = profile.mobile_no
        
        if len(update_values) == 1:  # Only updated_at
            logger.info(f"No fields to update for user: {current_user.username}")
        else:
            # Update user
            await db.execute(
                update(User)
                .where(User.id == current_user.id)
                .values(**update_values)
            )
            await db.commit()
            await db.refresh(current_user)
            logger.info(f"Profile updated for user: {current_user.username}")
        
        return {
            "id": current_user.id,
            "username": current_user.username,
            "first_name": current_user.first_name or "",
            "last_name": current_user.last_name or "",
            "email": current_user.email,
            "mobile_no": current_user.mobile_no,
            "is_premium": current_user.is_premium,
            "premium_expiry": current_user.premium_expiry
        }
        
    except Exception as e:
        logger.error(f"Profile update error for {current_user.username}: {str(e)}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update profile"
        )


# Enhanced mail list endpoint
@auth_router.post("/mail-list", response_model=dict)
async def add_to_mail_list(
    mail: MailCreate, 
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    client_ip = get_client_ip(request)
    
    # Rate limiting for mail list subscriptions
    if await rate_limit_check(client_ip, db, window_minutes=RATE_LIMIT_MAIL_LIST_WINDOW, max_attempts=RATE_LIMIT_MAIL_LIST_ATTEMPTS):
        logger.warning(f"Mail list rate limit exceeded for IP: {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many subscription attempts. Please try again later."
        )
    
    logger.info(f"Adding email to mail list: {mail.email}")
    
    try:
        email_normalized = mail.email.lower()
        
        # Check if email already exists
        result = await db.execute(
            select(MailList).where(MailList.email == email_normalized)
        )
        existing_email = result.scalar_one_or_none()
        
        if existing_email:
            if existing_email.is_active:
                logger.info(f"Email already subscribed: {mail.email}")
                return {"message": "Email is already subscribed to our mailing list"}
            else:
                # Reactivate subscription
                await db.execute(
                    update(MailList)
                    .where(MailList.email == email_normalized)
                    .values(is_active=True, unsubscribed_at=None)
                )
                await db.commit()
                logger.info(f"Reactivated email subscription: {mail.email}")
                return {"message": "Email subscription reactivated successfully"}
        
        # Add new email
        db_mail = MailList(email=email_normalized)
        db.add(db_mail)
        await db.commit()
        await db.refresh(db_mail)
        
        logger.info(f"Email added to mail list: {mail.email}")
        return {"message": "Email added to mailing list successfully"}
        
    except Exception as e:
        logger.error(f"Mail list error: {str(e)}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to subscribe to mailing list"
        )


# Enhanced feedback endpoint
@auth_router.post("/feedback", response_model=dict)
async def submit_feedback(
    feedback: FeedbackCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    logger.info(f"Feedback submission from user: {current_user.username}")
    
    try:
        db_feedback = Feedback(
            feedback=feedback.feedback,
            priority=feedback.priority,
            user_id=current_user.id
        )
        
        db.add(db_feedback)
        await db.commit()
        await db.refresh(db_feedback)
        
        logger.info(f"Feedback submitted successfully: ID {db_feedback.id}")
        return {"message": "Feedback submitted successfully", "feedback_id": db_feedback.id}
        
    except Exception as e:
        logger.error(f"Feedback submission error: {str(e)}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to submit feedback"
        )


# Enhanced payment endpoints
@auth_router.post("/create-order", response_model=dict)
async def create_order(
    order_request: CreateOrderRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    logger.info(f"Creating order for user: {current_user.username}, plan: {order_request.plan}")
    
    if not razorpay_client:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Payment service unavailable"
        )
    
    # Validate plan and amount match
    valid_plans = {"monthly": 9900, "premium": 29900, "annual": 99900}
    if order_request.amount != valid_plans[order_request.plan]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid plan and amount combination"
        )
    
    # Check if user already has active premium
    if current_user.is_premium and current_user.premium_expiry and current_user.premium_expiry > datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already has an active premium subscription"
        )
    
    try:
        order_data = {
            "amount": order_request.amount,
            "currency": "INR",
            "receipt": f"order_{current_user.id}_{int(datetime.now(timezone.utc).timestamp())}",
            "payment_capture": 1,
            "notes": {
                "user_id": str(current_user.id),
                "plan": order_request.plan,
                "email": current_user.email
            }
        }
        
        order = razorpay_client.order.create(data=order_data)
        logger.info(f"Razorpay order created: {order['id']}")
        
        return {
            "order_id": order["id"],
            "amount": order["amount"],
            "currency": order["currency"],
            "key": RAZORPAY_KEY_ID  # Frontend needs this
        }
        
    except Exception as e:
        logger.error(f"Order creation error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create payment order"
        )


@auth_router.post("/verify-payment", response_model=dict)
async def verify_payment(
    payment_data: VerifyPaymentRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    logger.info(f"Verifying payment for user: {current_user.username}")
    
    if not razorpay_client:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Payment service unavailable"
        )
    
    try:
        # Verify payment signature
        razorpay_client.utility.verify_payment_signature({
            "razorpay_order_id": payment_data.razorpay_order_id,
            "razorpay_payment_id": payment_data.razorpay_payment_id,
            "razorpay_signature": payment_data.razorpay_signature
        })
        
        # Get payment details
        payment = razorpay_client.payment.fetch(payment_data.razorpay_payment_id)
        
        if payment["status"] != "captured":
            logger.warning(f"Payment not captured: {payment_data.razorpay_payment_id}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Payment was not successful"
            )
        
        # Check if user already has premium (race condition protection)
        await db.refresh(current_user)
        if current_user.is_premium and current_user.premium_expiry and current_user.premium_expiry > datetime.now(timezone.utc):
            logger.warning(f"User already has premium during payment verification: {current_user.username}")
            return {"message": "Payment processed, but you already have an active subscription", "is_premium": True}
        
        # Determine subscription duration
        amount = payment["amount"]
        if amount == 9900:  # Monthly
            duration = timedelta(days=30)
        elif amount == 99900:  # Annual
            duration = timedelta(days=365)
        else:
            logger.error(f"Invalid payment amount: {amount}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid payment amount"
            )
        
        # Update user subscription
        new_expiry = datetime.now(timezone.utc) + duration
        
        await db.execute(
            update(User)
            .where(User.id == current_user.id)
            .values(
                is_premium=True,
                premium_expiry=new_expiry,
                updated_at=datetime.now(timezone.utc)
            )
        )
        await db.commit()
        await db.refresh(current_user)
        
        logger.info(f"Premium subscription activated for user: {current_user.username}, expires: {new_expiry}")
        
        return {
            "message": "Payment verified and premium subscription activated",
            "is_premium": True,
            "premium_expiry": new_expiry.isoformat()
        }
        
    except razorpay.errors.SignatureVerificationError:
        logger.error("Payment signature verification failed")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payment verification failed"
        )
    except razorpay.errors.BadRequestError as e:
        logger.error(f"Razorpay bad request: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid payment data"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Payment verification error: {str(e)}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Payment verification failed"
        )


# User details endpoint
@auth_router.get("/me", response_model=UserDetailsResponse)
async def get_user_details(current_user: User = Depends(get_current_user)):
    return {
        "username": current_user.username,
        "email": current_user.email,
        "is_premium": current_user.is_premium,
        "premium_expiry": current_user.premium_expiry,
        "is_github_connected": current_user.is_github_connected
    }


# User details endpoint for API key authentication (CLI compatible)
@auth_router.get("/me/api-key", response_model=UserDetailsResponse)
async def get_user_details_api_key(current_user: User = Depends(get_current_user_from_api_key)):
    """
    Get user details using API key authentication (CLI compatible)
    
    This endpoint provides the same user information as /me but supports
    API key authentication for CLI tools and headless applications.
    """
    return {
        "username": current_user.username,
        "email": current_user.email,
        "is_premium": current_user.is_premium,
        "premium_expiry": current_user.premium_expiry,
        "is_github_connected": current_user.is_github_connected
    }


# GitHub connect endpoint for existing users
@auth_router.get("/github/connect")
async def github_connect(current_user: User = Depends(get_current_user)):
    """Initiate GitHub connection for logged-in users"""
    if not GITHUB_CLIENT_ID or not GITHUB_REDIRECT_URI:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="GitHub integration not configured"
        )
    
    # Generate state with user ID for security
    state = f"{current_user.id}_{secrets.token_urlsafe(16)}"
    
    github_auth_url = (
        f"https://github.com/login/oauth/authorize?"
        f"client_id={GITHUB_CLIENT_ID}&"
        f"redirect_uri={urllib.parse.quote(GITHUB_REDIRECT_URI)}&"
        f"scope=user%20repo&"
        f"state={state}"
    )
    
    logger.debug(f"GitHub connect initiated for user: {current_user.username}")
    return {"auth_url": github_auth_url}


# GitHub disconnect endpoint for existing users
@auth_router.delete("/github/disconnect")
async def github_disconnect(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Disconnect GitHub integration for logged-in users"""
    
    logger.info(f"GitHub disconnect request for user: {current_user.username} (ID: {current_user.id})")
    
    try:
        # Check if user has GitHub connected
        if not current_user.is_github_connected:
            logger.warning(f"User {current_user.username} attempted to disconnect GitHub but no connection exists")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No GitHub integration found to disconnect"
            )
        
        # Clear GitHub integration data
        await db.execute(
            update(User)
            .where(User.id == current_user.id)
            .values(
                github_access_token=None,
                is_github_connected=False,
                updated_at=datetime.now(timezone.utc)
            )
        )
        await db.commit()
        
        logger.info(f"GitHub integration successfully disconnected for user: {current_user.username}")
        
        return {
            "message": "GitHub integration disconnected successfully",
            "is_github_connected": False,
            "status": "disconnected",
            "disconnected_at": datetime.now(timezone.utc).isoformat()
        }
        
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        logger.error(f"Error disconnecting GitHub for user {current_user.username}: {str(e)}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to disconnect GitHub integration"
        )


# User account deletion endpoint
@auth_router.delete("/account", response_model=dict)
async def delete_user_account(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    request: Optional[AccountDeletionRequest] = Body(None)
):
    """Soft delete user account with 30-day retention period"""
    
    logger.info(f"Account deletion request for user {current_user.id}")
    
    try:
        # Check if user is already soft-deleted
        if current_user.is_deleted:
            logger.warning(f"User {current_user.id} is already deleted")
            return {
                "message": "Account has already been deleted",
                "deleted_data": {
                    "user_id": current_user.id,
                    "deleted_at": current_user.deleted_at.isoformat() if current_user.deleted_at else None
                }
            }
        
        # Safety check - handle test users differently
        if current_user.username in ['harshaltribhuwan', 'harshaltedgsdst123']:
            logger.info(f"Test mode: soft delete for test user {current_user.username}")
            test_mode = True
        else:
            test_mode = False
        
        # Import required modules
        import jwt
        from sqlalchemy import func, update, and_
        from repos.models import Repo
        from scans.models import Scan
        
        # Get data counts for logging
        repo_count_result = await db.execute(
            select(func.count(Repo.id)).where(Repo.user_id == current_user.id)
        )
        repo_count = repo_count_result.scalar() or 0
        
        # Get scan count through repo ownership
        if repo_count > 0:
            user_repos_result = await db.execute(
                select(Repo.full_name).where(Repo.user_id == current_user.id)
            )
            user_repos = [row[0] for row in user_repos_result.fetchall()]
            
            scan_count_result = await db.execute(
                select(func.count(Scan.id)).where(Scan.repo_full_name.in_(user_repos))
            )
            scan_count = scan_count_result.scalar() or 0
        else:
            scan_count = 0
        
        # Blacklist the current user's token to prevent further use
        try:
            await blacklist_token(token, db, current_user.id)
            logger.info(f"Blacklisted current token for user {current_user.id}")
        except Exception as e:
            logger.warning(f"Failed to blacklist token during account deletion: {str(e)}")
            # Continue with soft deletion even if token blacklisting fails
        
        # Prepare deletion reason
        deletion_reason = "User requested account deletion"
        if request and request.deletion_reason:
            deletion_reason = f"User requested: {request.deletion_reason}"
        
        # Perform soft delete
        deletion_timestamp = datetime.now(timezone.utc)
        await db.execute(
            update(User)
            .where(User.id == current_user.id)
            .values(
                is_deleted=True,
                deleted_at=deletion_timestamp,
                deletion_reason=deletion_reason,
                updated_at=deletion_timestamp
            )
        )
        await db.commit()
        
        logger.info(f"Successfully soft-deleted user account {current_user.id} (repos: {repo_count}, scans: {scan_count})")
        
        return {
            "message": "Account deletion completed successfully" + (" (test mode)" if test_mode else ""),
            "deleted_data": {
                "repositories": repo_count,
                "scans": scan_count,
                "user_id": current_user.id,
                "deletion_timestamp": deletion_timestamp.isoformat(),
                "retention_period_days": 30
            }
        }
            
    except Exception as e:
        logger.error(f"Account deletion error for user {current_user.id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete account. Please contact support."
        )


# Database integrity check endpoint
@auth_router.get("/admin/integrity-check", response_model=dict)
async def database_integrity_check(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Check database integrity and identify potential FK constraint issues"""
    
    logger.info(f"Database integrity check initiated by user {current_user.id}")
    
    try:
        integrity_issues = []
        
        # Check for orphaned records
        from repos.models import Repo
        from scans.models import Scan, ScanSummary, ComplianceMapping, IssueFeedback, PRSecurityComment, PRSecurityReview, ScanJob
        
        # 1. Check for scans referencing non-existent repos
        orphaned_scans_result = await db.execute(
            text("""
                SELECT s.id, s.repo_full_name
                FROM scans s
                LEFT JOIN repos r ON s.repo_full_name = r.full_name AND s.user_id = r.user_id
                WHERE r.id IS NULL
                LIMIT 100
            """)
        )
        orphaned_scans = orphaned_scans_result.fetchall()
        if orphaned_scans:
            integrity_issues.append({
                "type": "orphaned_scans",
                "count": len(orphaned_scans),
                "description": "Scans referencing non-existent repositories",
                "sample_ids": [row[0] for row in orphaned_scans[:10]]
            })
        
        # 2. Check for scan summaries referencing non-existent scans
        orphaned_summaries_result = await db.execute(
            text("""
                SELECT ss.id, ss.scan_id
                FROM scan_summaries ss
                LEFT JOIN scans s ON ss.scan_id = s.id
                WHERE s.id IS NULL
                LIMIT 100
            """)
        )
        orphaned_summaries = orphaned_summaries_result.fetchall()
        if orphaned_summaries:
            integrity_issues.append({
                "type": "orphaned_scan_summaries",
                "count": len(orphaned_summaries),
                "description": "Scan summaries referencing non-existent scans",
                "sample_ids": [row[0] for row in orphaned_summaries[:10]]
            })
        
        # 3. Check for blacklisted tokens with invalid user references
        orphaned_tokens_result = await db.execute(
            text("""
                SELECT bt.id, bt.user_id
                FROM blacklisted_tokens bt
                LEFT JOIN users u ON bt.user_id = u.id
                WHERE bt.user_id IS NOT NULL AND u.id IS NULL
                LIMIT 100
            """)
        )
        orphaned_tokens = orphaned_tokens_result.fetchall()
        if orphaned_tokens:
            integrity_issues.append({
                "type": "orphaned_blacklisted_tokens",
                "count": len(orphaned_tokens),
                "description": "Blacklisted tokens referencing non-existent users",
                "sample_ids": [row[0] for row in orphaned_tokens[:10]]
            })
        
        # 4. Check for scan jobs with invalid scan references
        invalid_scan_jobs_result = await db.execute(
            text("""
                SELECT sj.id, sj.scan_id
                FROM scan_jobs sj
                LEFT JOIN scans s ON sj.scan_id = s.id
                WHERE sj.scan_id IS NOT NULL AND s.id IS NULL
                LIMIT 100
            """)
        )
        invalid_scan_jobs = invalid_scan_jobs_result.fetchall()
        if invalid_scan_jobs:
            integrity_issues.append({
                "type": "invalid_scan_job_references",
                "count": len(invalid_scan_jobs),
                "description": "Scan jobs referencing non-existent scans",
                "sample_ids": [row[0] for row in invalid_scan_jobs[:10]]
            })
        
        # 5. Get overall statistics
        stats_result = await db.execute(
            text("""
                SELECT 
                    (SELECT COUNT(*) FROM users) as total_users,
                    (SELECT COUNT(*) FROM repos) as total_repos,
                    (SELECT COUNT(*) FROM scans) as total_scans,
                    (SELECT COUNT(*) FROM scan_summaries) as total_summaries,
                    (SELECT COUNT(*) FROM blacklisted_tokens) as total_blacklisted_tokens,
                    (SELECT COUNT(*) FROM scan_jobs) as total_scan_jobs
            """)
        )
        stats = stats_result.first()
        
        return {
            "status": "completed",
            "integrity_issues": integrity_issues,
            "total_issues": len(integrity_issues),
            "database_stats": {
                "total_users": stats[0],
                "total_repos": stats[1], 
                "total_scans": stats[2],
                "total_summaries": stats[3],
                "total_blacklisted_tokens": stats[4],
                "total_scan_jobs": stats[5]
            },
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "message": "Database integrity check completed" if not integrity_issues else f"Found {len(integrity_issues)} types of integrity issues"
        }
        
    except Exception as e:
        logger.error(f"Database integrity check error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Integrity check failed"
        )


# Helper function to clean timezone/format data
def clean_preference_string(value: str, default: str) -> str:
    """Remove extra quotes and normalize timezone values"""
    if not value:
        return default
    
    # Remove extra quotes that might be stored in database
    cleaned = value.strip("'\"")
    
    # Normalize common timezone values
    if cleaned == "UTC":
        return "Etc/UTC"
    
    return cleaned

# Timezone Preferences API Endpoints
@auth_router.get("/profile/timezone-preferences", response_model=TimezonePreferencesResponse)
async def get_timezone_preferences(
    current_user: User = Depends(get_current_user)
):
    """Get user's timezone preferences"""
    return TimezonePreferencesResponse(
        timezone=clean_preference_string(current_user.timezone, "Etc/UTC"),
        date_format=clean_preference_string(current_user.date_format, "MMM dd, yyyy"),
        time_format=clean_preference_string(current_user.time_format, "12h"),
        show_relative_dates=current_user.show_relative_dates if current_user.show_relative_dates is not None else True,
        show_timezone_abbreviations=current_user.show_timezone_abbreviations if current_user.show_timezone_abbreviations is not None else False,
        preferences_updated_at=current_user.preferences_updated_at
    )

@auth_router.put("/profile/timezone-preferences", response_model=TimezonePreferencesResponse)
async def update_timezone_preferences(
    preferences: TimezonePreferencesUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Update user's timezone preferences"""
    try:
        # Update only provided fields
        update_data = {}
        if preferences.timezone is not None:
            update_data['timezone'] = preferences.timezone
        if preferences.date_format is not None:
            update_data['date_format'] = preferences.date_format
        if preferences.time_format is not None:
            update_data['time_format'] = preferences.time_format
        if preferences.show_relative_dates is not None:
            update_data['show_relative_dates'] = preferences.show_relative_dates
        if preferences.show_timezone_abbreviations is not None:
            update_data['show_timezone_abbreviations'] = preferences.show_timezone_abbreviations
        
        if update_data:
            # Add timestamp for tracking
            update_data['preferences_updated_at'] = datetime.now(timezone.utc)
            
            # Update user preferences
            stmt = (
                update(User)
                .where(User.id == current_user.id)
                .values(**update_data)
            )
            await db.execute(stmt)
            await db.commit()
            
            # Refresh user object to get updated values
            await db.refresh(current_user)
            
        logger.info(f"Updated timezone preferences for user {current_user.id}")
        
        return TimezonePreferencesResponse(
            timezone=current_user.timezone or "UTC",
            date_format=current_user.date_format or "MMM dd, yyyy", 
            time_format=current_user.time_format or "12h",
            show_relative_dates=current_user.show_relative_dates if current_user.show_relative_dates is not None else True,
            show_timezone_abbreviations=current_user.show_timezone_abbreviations if current_user.show_timezone_abbreviations is not None else False,
            preferences_updated_at=current_user.preferences_updated_at
        )
        
    except Exception as e:
        logger.error(f"Error updating timezone preferences for user {current_user.id}: {str(e)}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update timezone preferences"
        )


# Admin endpoint for cleanup (could be called by a cron job)
@auth_router.post("/admin/cleanup", response_model=dict)
async def admin_cleanup(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Clean up expired tokens and old login attempts"""
    # This should have proper admin authentication in production
    # For now, just allowing any authenticated user
    
    try:
        # Cleanup expired blacklisted tokens
        await cleanup_expired_blacklisted_tokens(db)
        
        # Cleanup old login attempts (keep last 30 days)
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=30)
        
        result = await db.execute(
            delete(LoginAttempt).where(LoginAttempt.created_at < cutoff_date)
        )
        
        deleted_attempts = result.rowcount
        await db.commit()
        
        logger.info(f"Cleanup completed: {deleted_attempts} old login attempts removed")
        
        return {
            "message": "Cleanup completed successfully",
            "login_attempts_removed": deleted_attempts
        }
        
    except Exception as e:
        logger.error(f"Cleanup error: {str(e)}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Cleanup failed"
        )


# Notification Preferences API Endpoints
@auth_router.get("/profile/notification-preferences", response_model=NotificationPreferencesResponse)
async def get_notification_preferences(
    current_user: User = Depends(get_current_user)
):
    """Get user's notification preferences"""
    return NotificationPreferencesResponse(
        email_notifications=current_user.email_notifications if current_user.email_notifications is not None else True,
        security_alerts=current_user.security_alerts if current_user.security_alerts is not None else True,
        scan_completion_notifications=current_user.scan_completion_notifications if current_user.scan_completion_notifications is not None else True,
        weekly_reports=current_user.weekly_reports if current_user.weekly_reports is not None else False,
        marketing_emails=current_user.marketing_emails if current_user.marketing_emails is not None else False,
        notification_preferences_updated_at=current_user.notification_preferences_updated_at
    )


@auth_router.put("/profile/notification-preferences", response_model=NotificationPreferencesResponse)
async def update_notification_preferences(
    preferences: NotificationPreferencesUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Update user's notification preferences"""
    try:
        # Update only provided fields
        update_data = {}
        if preferences.email_notifications is not None:
            update_data['email_notifications'] = preferences.email_notifications
        if preferences.security_alerts is not None:
            update_data['security_alerts'] = preferences.security_alerts
        if preferences.scan_completion_notifications is not None:
            update_data['scan_completion_notifications'] = preferences.scan_completion_notifications
        if preferences.weekly_reports is not None:
            update_data['weekly_reports'] = preferences.weekly_reports
        if preferences.marketing_emails is not None:
            update_data['marketing_emails'] = preferences.marketing_emails
        
        if update_data:
            # Add timestamp for tracking
            update_data['notification_preferences_updated_at'] = datetime.now(timezone.utc)
            
            # Update user preferences
            stmt = (
                update(User)
                .where(User.id == current_user.id)
                .values(**update_data)
            )
            await db.execute(stmt)
            await db.commit()
            
            # Refresh user object to get updated values
            await db.refresh(current_user)
            
        logger.info(f"Updated notification preferences for user {current_user.id}")
        
        return NotificationPreferencesResponse(
            email_notifications=current_user.email_notifications if current_user.email_notifications is not None else True,
            security_alerts=current_user.security_alerts if current_user.security_alerts is not None else True,
            scan_completion_notifications=current_user.scan_completion_notifications if current_user.scan_completion_notifications is not None else True,
            weekly_reports=current_user.weekly_reports if current_user.weekly_reports is not None else False,
            marketing_emails=current_user.marketing_emails if current_user.marketing_emails is not None else False,
            notification_preferences_updated_at=current_user.notification_preferences_updated_at
        )
        
    except Exception as e:
        logger.error(f"Error updating notification preferences for user {current_user.id}: {str(e)}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update notification preferences"
        )

# API Keys Management Endpoints
@auth_router.get("/api-keys", response_model=list[ApiKeyResponse])
async def get_api_keys(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get all API keys for the current user"""
    try:
        result = await db.execute(
            select(ApiKey)
            .where(ApiKey.user_id == current_user.id)
            .order_by(ApiKey.created_at.desc())
        )
        api_keys = result.scalars().all()
        
        return [
            ApiKeyResponse(
                id=key.id,
                name=key.name,
                key_prefix=key.key_prefix,
                scopes=json.loads(key.scopes) if key.scopes else ["read"],
                is_active=key.is_active,
                last_used_at=key.last_used_at,
                usage_count=key.usage_count,
                created_at=key.created_at,
                expires_at=key.expires_at
            )
            for key in api_keys
        ]
        
    except Exception as e:
        logger.error(f"Error retrieving API keys for user {current_user.id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve API keys"
        )


@auth_router.post("/api-keys", response_model=ApiKeyCreateResponse)
async def create_api_key(
    key_data: ApiKeyCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Create a new API key"""
    try:
        import hashlib
        import secrets as crypto_secrets
        
        # Check API key limits (e.g., max 10 keys per user)
        existing_keys = await db.execute(
            select(func.count(ApiKey.id))
            .where(and_(ApiKey.user_id == current_user.id, ApiKey.is_active == True))
        )
        key_count = existing_keys.scalar() or 0
        
        if key_count >= 10:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Maximum number of API keys reached (10)"
            )
        
        # Generate secure API key
        key_bytes = crypto_secrets.token_bytes(32)  # 256-bit key
        api_key = f"dsx_{crypto_secrets.token_urlsafe(32)}"
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        key_prefix = api_key[:10]  # First 10 chars for display
        
        # Set expiration if requested
        expires_at = None
        if key_data.expires_in_days:
            expires_at = datetime.now(timezone.utc) + timedelta(days=key_data.expires_in_days)
        
        # Create API key record
        new_key = ApiKey(
            user_id=current_user.id,
            name=key_data.name,
            key_hash=key_hash,
            key_prefix=key_prefix,
            scopes=json.dumps(key_data.scopes),
            expires_at=expires_at
        )
        
        db.add(new_key)
        await db.commit()
        await db.refresh(new_key)
        
        logger.info(f"Created API key '{key_data.name}' for user {current_user.id}")
        
        return ApiKeyCreateResponse(
            id=new_key.id,
            name=new_key.name,
            key=api_key,  # Full key shown only once
            key_prefix=key_prefix,
            scopes=key_data.scopes,
            created_at=new_key.created_at,
            expires_at=expires_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating API key for user {current_user.id}: {str(e)}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create API key"
        )


@auth_router.delete("/api-keys/{key_id}")
async def delete_api_key(
    key_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Delete an API key"""
    try:
        # Find and verify ownership
        result = await db.execute(
            select(ApiKey)
            .where(and_(ApiKey.id == key_id, ApiKey.user_id == current_user.id))
        )
        api_key = result.scalar_one_or_none()
        
        if not api_key:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="API key not found"
            )
        
        # Delete the key
        await db.delete(api_key)
        await db.commit()
        
        logger.info(f"Deleted API key {key_id} for user {current_user.id}")
        
        return {"message": "API key deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting API key {key_id} for user {current_user.id}: {str(e)}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete API key"
        )


async def process_data_export(export_request: DataExportRequestModel, user: User, db: AsyncSession):
    """Process data export request and generate export file"""
    try:
        # Mark as processing started
        export_request.status = "processing"
        export_request.processing_started_at = datetime.now(timezone.utc)
        await db.commit()
        
        # Simulate data collection and export generation
        export_data = {
            "user_profile": {
                "id": user.id,
                "username": user.username,
                "email": user.email if export_request.include_personal_data else "[redacted]",
                "first_name": user.first_name if export_request.include_personal_data else "[redacted]",
                "last_name": user.last_name if export_request.include_personal_data else "[redacted]",
                "mobile_no": user.mobile_no if export_request.include_personal_data else "[redacted]",
                "is_premium": user.is_premium,
                "created_at": user.created_at.isoformat() if user.created_at else None,
                "timezone": user.timezone,
                "preferences": {
                    "email_notifications": user.email_notifications,
                    "security_alerts": user.security_alerts,
                    "scan_completion_notifications": user.scan_completion_notifications
                } if export_request.include_personal_data else "[redacted]"
            },
            "api_keys": [],
            "scan_data": [],
            "repository_data": [],
            "export_metadata": {
                "export_id": export_request.id,
                "export_type": export_request.export_type,
                "requested_at": export_request.requested_at.isoformat(),
                "processed_at": datetime.now(timezone.utc).isoformat(),
                "includes_personal_data": export_request.include_personal_data,
                "includes_scan_data": export_request.include_scan_data,
                "includes_repository_data": export_request.include_repository_data
            }
        }
        
        # Get API keys if requested
        if export_request.include_personal_data:
            api_keys_result = await db.execute(
                select(ApiKey).where(ApiKey.user_id == user.id)
            )
            api_keys = api_keys_result.scalars().all()
            export_data["api_keys"] = [
                {
                    "id": key.id,
                    "name": key.name,
                    "key_prefix": key.key_prefix,
                    "scopes": json.loads(key.scopes) if key.scopes else [],
                    "created_at": key.created_at.isoformat() if key.created_at else None,
                    "last_used_at": key.last_used_at.isoformat() if key.last_used_at else None,
                    "usage_count": key.usage_count
                }
                for key in api_keys
            ]
        
        # Generate export file content based on format
        if export_request.file_format == "json":
            export_content = json.dumps(export_data, indent=2, default=str)
            content_type = "application/json"
        elif export_request.file_format == "csv":
            # For CSV, we'll create a simplified flat structure
            import csv
            import io
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["Category", "Key", "Value"])
            
            # Flatten the data for CSV
            def flatten_dict(d, parent_key='', sep='_'):
                items = []
                for k, v in d.items():
                    new_key = f"{parent_key}{sep}{k}" if parent_key else k
                    if isinstance(v, dict):
                        items.extend(flatten_dict(v, new_key, sep=sep).items())
                    elif isinstance(v, list):
                        items.append((new_key, json.dumps(v)))
                    else:
                        items.append((new_key, str(v)))
                return dict(items)
            
            flat_data = flatten_dict(export_data)
            for key, value in flat_data.items():
                category = key.split('_')[0]
                writer.writerow([category, key, value])
            
            export_content = output.getvalue()
            content_type = "text/csv"
        else:
            # Default to JSON
            export_content = json.dumps(export_data, indent=2, default=str)
            content_type = "application/json"
        
        # Calculate file size and record count
        file_size_bytes = len(export_content.encode('utf-8'))
        total_records = len(export_data.get("api_keys", [])) + 1  # +1 for user profile
        
        # Mark as completed
        export_request.status = "completed"
        export_request.completed_at = datetime.now(timezone.utc)
        export_request.total_records = total_records
        export_request.exported_records = total_records
        export_request.file_size_bytes = file_size_bytes
        
        await db.commit()
        
        logger.info(f"Data export {export_request.id} completed successfully for user {user.id}")
        
    except Exception as e:
        logger.error(f"Error processing data export {export_request.id}: {str(e)}")
        export_request.status = "failed"
        export_request.error_message = str(e)
        await db.commit()
        raise


# Data Export Endpoints
@auth_router.post("/data-export", response_model=DataExportResponse)
async def request_data_export(
    export_request: DataExportRequestInput,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Request data export for compliance (available for all users)"""
    try:
        # Check for existing pending/processing exports
        existing = await db.execute(
            select(DataExportRequestModel)
            .where(and_(
                DataExportRequestModel.user_id == current_user.id,
                DataExportRequestModel.status.in_(["pending", "processing"])
            ))
        )

        if existing.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="You already have a pending data export request"
            )

        # Create export request
        export_req = DataExportRequestModel(
            user_id=current_user.id,
            export_type=export_request.export_type,
            file_format=export_request.file_format,
            include_personal_data=export_request.include_personal_data,
            include_scan_data=export_request.include_scan_data,
            include_repository_data=export_request.include_repository_data,
            download_expires_at=datetime.now(timezone.utc) + timedelta(days=7)  # 7 days to download
        )
        
        db.add(export_req)
        await db.commit()
        await db.refresh(export_req)
        
        logger.info(f"Created data export request {export_req.id} for user {current_user.id}")
        
        # Process the export immediately (for now)
        # In production, this would be handled by a background worker
        await process_data_export(export_req, current_user, db)
        
        return DataExportResponse(
            id=export_req.id,
            export_type=export_req.export_type,
            status=export_req.status,
            file_format=export_req.file_format,
            include_personal_data=export_req.include_personal_data,
            include_scan_data=export_req.include_scan_data,
            include_repository_data=export_req.include_repository_data,
            total_records=export_req.total_records,
            exported_records=export_req.exported_records,
            file_size_bytes=export_req.file_size_bytes,
            requested_at=export_req.requested_at,
            processing_started_at=export_req.processing_started_at,
            completed_at=export_req.completed_at,
            download_expires_at=export_req.download_expires_at,
            error_message=export_req.error_message
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating data export request for user {current_user.id}: {str(e)}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create data export request"
        )


@auth_router.get("/data-export", response_model=list[DataExportResponse])
async def get_data_exports(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get all data export requests for the current user"""
    try:
        result = await db.execute(
            select(DataExportRequestModel)
            .where(DataExportRequestModel.user_id == current_user.id)
            .order_by(DataExportRequestModel.requested_at.desc())
        )
        exports = result.scalars().all()
        
        return [
            DataExportResponse(
                id=export.id,
                export_type=export.export_type,
                status=export.status,
                file_format=export.file_format,
                include_personal_data=export.include_personal_data,
                include_scan_data=export.include_scan_data,
                include_repository_data=export.include_repository_data,
                total_records=export.total_records,
                exported_records=export.exported_records,
                file_size_bytes=export.file_size_bytes,
                requested_at=export.requested_at,
                processing_started_at=export.processing_started_at,
                completed_at=export.completed_at,
                download_expires_at=export.download_expires_at,
                error_message=export.error_message
            )
            for export in exports
        ]
        
    except Exception as e:
        logger.error(f"Error retrieving data exports for user {current_user.id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve data export requests"
        )


@auth_router.post("/data-export/{export_id}/process")
async def process_pending_export(
    export_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Manually process a stuck data export request"""
    try:
        # Find the export request
        result = await db.execute(
            select(DataExportRequestModel)
            .where(and_(
                DataExportRequestModel.id == export_id,
                DataExportRequestModel.user_id == current_user.id
            ))
        )
        export_request = result.scalar_one_or_none()
        
        if not export_request:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Export request not found"
            )
        
        if export_request.status not in ["pending", "failed"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Export request is already {export_request.status}"
            )
        
        # Process the export
        await process_data_export(export_request, current_user, db)
        
        return {"message": "Export processed successfully", "export_id": export_id}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing export {export_id} for user {current_user.id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process export request"
        )


@auth_router.get("/data-export/{export_id}/download")
async def download_data_export(
    export_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Download completed data export"""
    from fastapi.responses import Response
    
    try:
        # Find the export request
        result = await db.execute(
            select(DataExportRequestModel)
            .where(and_(
                DataExportRequestModel.id == export_id,
                DataExportRequestModel.user_id == current_user.id
            ))
        )
        export_request = result.scalar_one_or_none()
        
        if not export_request:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Export request not found"
            )
        
        if export_request.status != "completed":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Export is not ready for download (status: {export_request.status})"
            )
        
        # Check if download has expired
        if export_request.download_expires_at and export_request.download_expires_at < datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_410_GONE,
                detail="Export download has expired"
            )
        
        # Regenerate export content on-demand for security
        export_data = {
            "user_profile": {
                "id": current_user.id,
                "username": current_user.username,
                "email": current_user.email if export_request.include_personal_data else "[redacted]",
                "first_name": current_user.first_name if export_request.include_personal_data else "[redacted]",
                "last_name": current_user.last_name if export_request.include_personal_data else "[redacted]",
                "mobile_no": current_user.mobile_no if export_request.include_personal_data else "[redacted]",
                "is_premium": current_user.is_premium,
                "created_at": current_user.created_at.isoformat() if current_user.created_at else None,
                "timezone": current_user.timezone,
                "preferences": {
                    "email_notifications": current_user.email_notifications,
                    "security_alerts": current_user.security_alerts,
                    "scan_completion_notifications": current_user.scan_completion_notifications
                } if export_request.include_personal_data else "[redacted]"
            },
            "api_keys": [],
            "scan_data": [],
            "repository_data": [],
            "export_metadata": {
                "export_id": export_request.id,
                "export_type": export_request.export_type,
                "requested_at": export_request.requested_at.isoformat(),
                "downloaded_at": datetime.now(timezone.utc).isoformat(),
                "includes_personal_data": export_request.include_personal_data,
                "includes_scan_data": export_request.include_scan_data,
                "includes_repository_data": export_request.include_repository_data
            }
        }
        
        # Get API keys if requested
        if export_request.include_personal_data:
            api_keys_result = await db.execute(
                select(ApiKey).where(ApiKey.user_id == current_user.id)
            )
            api_keys = api_keys_result.scalars().all()
            export_data["api_keys"] = [
                {
                    "id": key.id,
                    "name": key.name,
                    "key_prefix": key.key_prefix,
                    "scopes": json.loads(key.scopes) if key.scopes else [],
                    "created_at": key.created_at.isoformat() if key.created_at else None,
                    "last_used_at": key.last_used_at.isoformat() if key.last_used_at else None,
                    "usage_count": key.usage_count
                }
                for key in api_keys
            ]
        
        # Generate export content based on format
        if export_request.file_format == "json":
            export_content = json.dumps(export_data, indent=2, default=str)
            content_type = "application/json"
            filename = f"devsecurex-export-{export_id}.json"
        elif export_request.file_format == "csv":
            # Generate CSV format
            import csv
            import io
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["Category", "Key", "Value"])
            
            # Flatten the data for CSV
            def flatten_dict(d, parent_key='', sep='_'):
                items = []
                for k, v in d.items():
                    new_key = f"{parent_key}{sep}{k}" if parent_key else k
                    if isinstance(v, dict):
                        items.extend(flatten_dict(v, new_key, sep=sep).items())
                    elif isinstance(v, list):
                        items.append((new_key, json.dumps(v)))
                    else:
                        items.append((new_key, str(v)))
                return dict(items)
            
            flat_data = flatten_dict(export_data)
            for key, value in flat_data.items():
                category = key.split('_')[0]
                writer.writerow([category, key, value])
            
            export_content = output.getvalue()
            content_type = "text/csv"
            filename = f"devsecurex-export-{export_id}.csv"
        else:
            export_content = json.dumps(export_data, indent=2, default=str)
            content_type = "application/json"
            filename = f"devsecurex-export-{export_id}.json"
        
        # Update downloaded timestamp
        export_request.downloaded_at = datetime.now(timezone.utc)
        await db.commit()
        
        logger.info(f"Data export {export_id} downloaded by user {current_user.id}")
        
        # Return file as downloadable attachment
        return Response(
            content=export_content,
            media_type=content_type,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Length": str(len(export_content.encode('utf-8')))
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error downloading export {export_id} for user {current_user.id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to download export"
        )