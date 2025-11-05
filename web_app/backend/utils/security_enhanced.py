"""
Enhanced Security utilities for SecureOps AI
JWT tokens, MFA, password validation, and RBAC
"""

import jwt
import pyotp
import qrcode
import secrets
import string
import re
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List
from fastapi import HTTPException, status, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from io import BytesIO
import base64

from database import get_db
from models_enhanced import User, UserSession, AuditLog, RateLimit, UserRole, AuditEventType
from config import settings

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT Security
security = HTTPBearer(auto_error=False)

class SecurityConfig:
    """Security configuration constants"""
    
    # JWT Settings
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = 30
    REFRESH_TOKEN_EXPIRE_DAYS = 7
    
    # Password Policy
    MIN_PASSWORD_LENGTH = 12
    REQUIRE_UPPERCASE = True
    REQUIRE_LOWERCASE = True
    REQUIRE_NUMBERS = True
    REQUIRE_SPECIAL = True
    
    # Account Lockout Policy
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 30
    
    # Rate Limiting
    RATE_LIMIT_REQUESTS = 10
    RATE_LIMIT_WINDOW_MINUTES = 1
    RATE_LIMIT_BLOCK_MINUTES = 15
    
    # MFA Settings
    MFA_WINDOW = 1  # Allow 1 step drift for TOTP
    MFA_ISSUER = "SecureOps AI"

class PasswordValidator:
    """Validate password strength according to enterprise policy"""
    
    @staticmethod
    def validate_password(password: str) -> tuple[bool, List[str]]:
        """
        Validate password against security policy
        Returns (is_valid, list_of_errors)
        """
        errors = []
        
        # Length check
        if len(password) < SecurityConfig.MIN_PASSWORD_LENGTH:
            errors.append(f"Password must be at least {SecurityConfig.MIN_PASSWORD_LENGTH} characters long")
        
        # Character type checks
        if SecurityConfig.REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        if SecurityConfig.REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        if SecurityConfig.REQUIRE_NUMBERS and not re.search(r'\d', password):
            errors.append("Password must contain at least one number")
        
        if SecurityConfig.REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain at least one special character")
        
        # Common password checks
        common_passwords = [
            "password", "123456", "password123", "admin", "qwerty",
            "letmein", "welcome", "monkey", "dragon", "pass"
        ]
        if password.lower() in common_passwords:
            errors.append("Password is too common")
        
        # Sequential characters check
        if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def)', password.lower()):
            errors.append("Password cannot contain sequential characters")
        
        return len(errors) == 0, errors

class MFAService:
    """Multi-Factor Authentication service"""
    
    @staticmethod
    def generate_secret() -> str:
        """Generate a new TOTP secret"""
        return pyotp.random_base32()
    
    @staticmethod
    def get_totp_uri(secret: str, email: str) -> str:
        """Generate TOTP URI for QR code"""
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(
            email,
            issuer_name=SecurityConfig.MFA_ISSUER
        )
    
    @staticmethod
    def generate_qr_code(uri: str) -> str:
        """Generate QR code as base64 image"""
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        
        return base64.b64encode(buffer.getvalue()).decode()
    
    @staticmethod
    def verify_totp(secret: str, token: str) -> bool:
        """Verify TOTP token"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=SecurityConfig.MFA_WINDOW)
    
    @staticmethod
    def generate_backup_codes(count: int = 10) -> List[str]:
        """Generate backup codes"""
        codes = []
        for _ in range(count):
            code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
            # Format as XXXX-XXXX for readability
            formatted_code = f"{code[:4]}-{code[4:]}"
            codes.append(formatted_code)
        return codes

class TokenManager:
    """JWT token management"""
    
    @staticmethod
    def create_access_token(user_id: int, user_role: str, jti: str = None) -> str:
        """Create JWT access token"""
        if not jti:
            jti = secrets.token_urlsafe(32)
        
        expire = datetime.now(timezone.utc) + timedelta(minutes=SecurityConfig.ACCESS_TOKEN_EXPIRE_MINUTES)
        
        payload = {
            "sub": str(user_id),
            "role": user_role,
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "jti": jti,
            "type": "access"
        }
        
        return jwt.encode(payload, settings.jwt_secret_key, algorithm=SecurityConfig.ALGORITHM)
    
    @staticmethod
    def create_refresh_token(user_id: int, jti: str = None) -> str:
        """Create JWT refresh token"""
        if not jti:
            jti = secrets.token_urlsafe(32)
        
        expire = datetime.now(timezone.utc) + timedelta(days=SecurityConfig.REFRESH_TOKEN_EXPIRE_DAYS)
        
        payload = {
            "sub": str(user_id),
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "jti": jti,
            "type": "refresh"
        }
        
        return jwt.encode(payload, settings.jwt_secret_key, algorithm=SecurityConfig.ALGORITHM)
    
    @staticmethod
    def verify_token(token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(
                token,
                settings.jwt_secret_key,
                algorithms=[SecurityConfig.ALGORITHM]
            )
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.JWTError:
            return None

class RateLimiter:
    """Rate limiting for brute force protection"""
    
    @staticmethod
    def check_rate_limit(db: Session, ip_address: str, endpoint: str) -> bool:
        """Check if request is within rate limits"""
        now = datetime.utcnow()
        window_start = now - timedelta(minutes=SecurityConfig.RATE_LIMIT_WINDOW_MINUTES)
        
        # Get or create rate limit record
        rate_limit = db.query(RateLimit).filter(
            RateLimit.ip_address == ip_address,
            RateLimit.endpoint == endpoint
        ).first()
        
        if not rate_limit:
            # First request from this IP for this endpoint
            rate_limit = RateLimit(
                ip_address=ip_address,
                endpoint=endpoint,
                attempts=1,
                window_start=now
            )
            db.add(rate_limit)
            db.commit()
            return True
        
        # Check if IP is currently blocked
        if rate_limit.is_blocked():
            return False
        
        # Reset window if needed
        if rate_limit.window_start < window_start:
            rate_limit.attempts = 1
            rate_limit.window_start = now
        else:
            rate_limit.attempts += 1
        
        # Block if exceeded limit
        if rate_limit.attempts > SecurityConfig.RATE_LIMIT_REQUESTS:
            rate_limit.block(SecurityConfig.RATE_LIMIT_BLOCK_MINUTES)
            db.commit()
            return False
        
        db.commit()
        return True

class AccessControl:
    """Role-based access control decorators and functions"""
    
    @staticmethod
    def require_role(required_role: UserRole):
        """Decorator to require specific role"""
        def decorator(func):
            def wrapper(*args, **kwargs):
                # This is used with FastAPI dependencies
                return func(*args, **kwargs)
            wrapper._required_role = required_role
            return wrapper
        return decorator
    
    @staticmethod
    def check_permission(user: User, required_role: UserRole) -> bool:
        """Check if user has required permission"""
        if not user.is_active:
            return False
        
        return user.has_permission(required_role)

# FastAPI Dependencies
def get_client_ip(request: Request) -> str:
    """Extract client IP from request"""
    x_forwarded_for = request.headers.get('X-Forwarded-For')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    x_real_ip = request.headers.get('X-Real-IP')
    if x_real_ip:
        return x_real_ip
    return request.client.host if request.client else "unknown"

def get_user_agent(request: Request) -> str:
    """Extract user agent from request"""
    return request.headers.get('User-Agent', 'Unknown')

async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """Get current authenticated user"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    if not credentials:
        raise credentials_exception
    
    # Verify token
    payload = TokenManager.verify_token(credentials.credentials)
    if not payload:
        raise credentials_exception
    
    if payload.get("type") != "access":
        raise credentials_exception
    
    user_id = payload.get("sub")
    if not user_id:
        raise credentials_exception
    
    # Get user from database
    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        raise credentials_exception
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Inactive user"
        )
    
    # Check if session is still valid
    jti = payload.get("jti")
    if jti:
        session = db.query(UserSession).filter(
            UserSession.token_jti == jti,
            UserSession.user_id == user.id
        ).first()
        
        if not session or not session.is_valid():
            raise credentials_exception
        
        # Update last used
        session.last_used = datetime.utcnow()
        db.commit()
    
    return user

async def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Require admin role"""
    if not current_user.has_permission(UserRole.ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user

async def require_analyst(current_user: User = Depends(get_current_user)) -> User:
    """Require analyst role or higher"""
    if not current_user.has_permission(UserRole.ANALYST):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Analyst access required"
        )
    return current_user

def rate_limit(endpoint: str):
    """Rate limiting decorator"""
    def decorator(func):
        async def wrapper(request: Request, *args, **kwargs):
            db = next(get_db())
            client_ip = get_client_ip(request)
            
            if not RateLimiter.check_rate_limit(db, client_ip, endpoint):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded"
                )
            
            return await func(request, *args, **kwargs)
        return wrapper
    return decorator

# Password utilities
def hash_password(password: str) -> str:
    """Hash password with bcrypt"""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    return pwd_context.verify(plain_password, hashed_password)