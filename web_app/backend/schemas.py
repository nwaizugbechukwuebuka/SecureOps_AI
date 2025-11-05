"""
Pydantic schemas for SecureOps AI
Data validation and serialization models
"""

from pydantic import BaseModel, Field, EmailStr
from datetime import datetime
from typing import Optional, List, Dict, Any, TypeVar, Generic

T = TypeVar('T')

# Base schemas
class BaseResponse(BaseModel):
    success: bool = True
    message: str = "Operation completed successfully"

class ErrorResponse(BaseModel):
    success: bool = False
    message: str
    error_code: Optional[str] = None

# Authentication schemas
class UserLogin(BaseModel):
    """User login request model"""
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=1)

class LoginResponse(BaseModel):
    """Login response with token and user info"""
    access_token: str
    token_type: str = "bearer"
    user: "UserResponse"

# User schemas
class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    full_name: str = Field(..., min_length=1, max_length=100)
    role: str = Field(default="user")

class UserCreate(UserBase):
    password: str = Field(..., min_length=6, max_length=100)
    is_admin: bool = Field(default=False)

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    full_name: Optional[str] = Field(None, min_length=1, max_length=100)
    is_active: Optional[bool] = None
    role: Optional[str] = None

class UserLogin(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)

class UserResponse(UserBase):
    id: int
    is_admin: bool
    is_active: bool
    created_at: Optional[datetime] = None
    last_login: Optional[datetime] = None

    class Config:
        from_attributes = True

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

# Security Event schemas
class SecurityEventBase(BaseModel):
    event_type: str = Field(..., min_length=1, max_length=50)
    severity: str = Field(..., pattern="^(low|medium|high|critical)$")
    source_ip: str = Field(..., max_length=45)
    target_ip: str = Field(..., max_length=45)
    description: str = Field(..., min_length=1)
    affected_services: List[str] = Field(default_factory=list)
    event_metadata: Dict[str, Any] = Field(default_factory=dict)

class SecurityEventCreate(SecurityEventBase):
    pass

class SecurityEventUpdate(BaseModel):
    status: Optional[str] = Field(None, pattern="^(active|resolved|investigating)$")
    description: Optional[str] = None
    event_metadata: Optional[Dict[str, Any]] = None

class SecurityEventResponse(SecurityEventBase):
    id: int
    status: str
    created_at: datetime
    updated_at: datetime
    created_by: Optional[int] = None

    class Config:
        from_attributes = True

# Automation Task schemas
class AutomationTaskBase(BaseModel):
    task_name: str = Field(..., min_length=1, max_length=100)
    task_type: str = Field(..., min_length=1, max_length=50)
    parameters: Dict[str, Any] = Field(default_factory=dict)

class AutomationTaskCreate(AutomationTaskBase):
    pass

class AutomationTaskUpdate(BaseModel):
    status: Optional[str] = Field(None, pattern="^(pending|running|completed|failed)$")
    progress: Optional[float] = Field(None, ge=0.0, le=100.0)
    result: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None

class AutomationTaskResponse(BaseModel):
    id: int
    task_name: str
    task_type: str
    status: str
    user_id: int
    created_at: datetime
    scheduled_time: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    configuration: Dict[str, Any]
    result: Dict[str, Any]

    class Config:
        from_attributes = True

# Notification schemas
class NotificationBase(BaseModel):
    title: str = Field(..., min_length=1, max_length=100)
    message: str = Field(..., min_length=1, max_length=500)
    type: str = Field(default="info", pattern="^(info|warning|error|success)$")
    priority: str = Field(default="medium", pattern="^(low|medium|high)$")

class NotificationCreate(NotificationBase):
    user_id: Optional[int] = None  # null for broadcast

class NotificationUpdate(BaseModel):
    is_read: bool

class NotificationResponse(BaseModel):
    id: int
    title: str
    message: str
    notification_type: str
    priority: str
    read: bool
    user_id: int
    created_at: datetime

    class Config:
        from_attributes = True

# System Log schemas
class SystemLogBase(BaseModel):
    level: str = Field(..., pattern="^(INFO|WARNING|ERROR|DEBUG)$")
    source: str = Field(..., min_length=1, max_length=50)
    message: str = Field(..., min_length=1)
    category: str = Field(..., min_length=1, max_length=30)
    log_metadata: Dict[str, Any] = Field(default_factory=dict)

class SystemLogCreate(SystemLogBase):
    pass

class SystemLogResponse(SystemLogBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True

# Dashboard schemas
class DashboardStats(BaseModel):
    total_users: int = 0
    active_threats: int = 0
    system_health: str = "healthy"
    recent_alerts: int = 0

class SystemHealthResponse(BaseModel):
    status: str
    uptime: str
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    database_status: str
    services_status: Dict[str, str]

# Analytics schemas
class SecurityAnalytics(BaseModel):
    total_events: int = 0
    events_by_severity: Dict[str, int] = Field(default_factory=dict)
    events_by_type: Dict[str, int] = Field(default_factory=dict)
    recent_events: List[SecurityEventResponse] = Field(default_factory=list)
    threat_trends: List[Dict[str, Any]] = Field(default_factory=list)

# System Metrics schemas
class SystemMetricsResponse(BaseModel):
    """Real-time system metrics"""
    timestamp: datetime
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    network_in: float
    network_out: float
    active_connections: int
    uptime_seconds: int
    load_average: List[float]

class DashboardStatsResponse(BaseModel):
    """Dashboard statistics overview"""
    security_events_today: int
    critical_events_today: int
    automation_tasks_running: int
    automation_tasks_total: int
    unread_notifications: int
    system_uptime: str
    cpu_usage: float
    memory_usage: float
    disk_usage: float

class UserSearchFilters(BaseModel):
    """User search and filtering options"""
    search: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None

# Pagination schemas
class PaginationParams(BaseModel):
    skip: int = Field(0, ge=0)
    limit: int = Field(50, ge=1, le=100)

class PaginatedResponse(BaseModel, Generic[T]):
    """Generic paginated response model"""
    items: List[T]
    total: int
    page: int
    per_page: int
    total_pages: int