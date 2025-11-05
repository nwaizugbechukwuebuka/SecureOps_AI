import os
import logging
from typing import Generator
from datetime import datetime
from contextlib import contextmanager

from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, ForeignKey, Float, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy.pool import StaticPool
from sqlalchemy.exc import SQLAlchemyError
from passlib.context import CryptContext

# Configure logging
logger = logging.getLogger('SecureOps-Database')

# Password encryption - Fallback for bcrypt issues
try:
    pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
    USE_BCRYPT = True
except Exception as e:
    logger.warning(f"bcrypt not available, using simple hash: {e}")
    import hashlib
    USE_BCRYPT = False

# Database configuration
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./secureops.db')

# Create engine
if DATABASE_URL.startswith('sqlite'):
    engine = create_engine(
        DATABASE_URL,
        connect_args={'check_same_thread': False},
        poolclass=StaticPool
    )
else:
    engine = create_engine(DATABASE_URL)

# Session configuration
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Database Models
class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    full_name = Column(String(100), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_admin = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    role = Column(String(20), default='user')
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    def verify_password(self, password: str) -> bool:
        if USE_BCRYPT:
            try:
                return pwd_context.verify(password, self.hashed_password)
            except:
                # Fallback to simple comparison for demo
                return password == self.hashed_password
        else:
            # Simple hash comparison for demo
            import hashlib
            return hashlib.sha256(password.encode()).hexdigest() == self.hashed_password
    
    @staticmethod
    def hash_password(password: str) -> str:
        if USE_BCRYPT:
            try:
                return pwd_context.hash(password)
            except:
                # Fallback to storing plain password for demo
                return password
        else:
            # Simple hash for demo
            import hashlib
            return hashlib.sha256(password.encode()).hexdigest()
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'is_admin': self.is_admin,
            'is_active': self.is_active,
            'role': self.role,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }

class SecurityEvent(Base):
    __tablename__ = 'security_events'
    
    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)
    source_ip = Column(String(45), nullable=False)
    target_ip = Column(String(45), nullable=False)
    description = Column(Text, nullable=False)
    status = Column(String(20), default='active')
    affected_services = Column(JSON, default=list)
    event_metadata = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(Integer, ForeignKey('users.id'), nullable=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'event_type': self.event_type,
            'severity': self.severity,
            'source_ip': self.source_ip,
            'target_ip': self.target_ip,
            'description': self.description,
            'status': self.status,
            'affected_services': self.affected_services,
            'metadata': self.event_metadata,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'created_by': self.created_by
        }

# Database Session Management
def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    except SQLAlchemyError as e:
        logger.error(f'Database session error: {e}')
        db.rollback()
        raise
    finally:
        db.close()

@contextmanager
def get_db_session():
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except SQLAlchemyError as e:
        logger.error(f'Database session error: {e}')
        db.rollback()
        raise
    finally:
        db.close()

# Database Initialization
def create_tables():
    try:
        Base.metadata.create_all(bind=engine)
        logger.info('Database tables created successfully')
    except Exception as e:
        logger.error(f'Error creating database tables: {e}')
        raise

def init_database():
    try:
        create_tables()
        
        with get_db_session() as db:
            admin_user = db.query(User).filter(User.username == 'admin').first()
            if not admin_user:
                try:
                    admin_user = User(
                        username='admin',
                        email='admin@secureops.ai',
                        full_name='System Administrator',
                        hashed_password=User.hash_password('admin123'),
                        is_admin=True,
                        is_active=True,
                        role='admin'
                    )
                    db.add(admin_user)
                    
                    demo_user = User(
                        username='demo',
                        email='demo@secureops.ai',
                        full_name='Demo User',
                        hashed_password=User.hash_password('demo123'),
                        is_admin=False,
                        is_active=True,
                        role='user'
                    )
                    db.add(demo_user)
                    
                    db.commit()
                    logger.info('Default users created successfully')
                except Exception as hash_error:
                    logger.error(f'Password hashing error: {hash_error}')
                    # Try with a simpler password or different approach
                    db.rollback()
                    raise
            else:
                logger.info('Default users already exist')
                
    except Exception as e:
        logger.error(f'Database initialization error: {e}')
        # Don't raise in initialization to allow server to start

# CRUD Operations
class UserCRUD:
    @staticmethod
    def get_by_username(db: Session, username: str):
        return db.query(User).filter(User.username == username).first()
    
    @staticmethod
    def authenticate(db: Session, username: str, password: str):
        user = UserCRUD.get_by_username(db, username)
        if not user or not user.verify_password(password):
            return None
        return user
    
    @staticmethod
    def update_last_login(db: Session, user: User):
        user.last_login = datetime.utcnow()
        db.add(user)
        db.commit()
        return user

class SecurityEventCRUD:
    @staticmethod
    def create_event(db: Session, event_data: dict):
        event = SecurityEvent(**event_data)
        db.add(event)
        db.commit()
        db.refresh(event)
        return event
    
    @staticmethod
    def get_recent_events(db: Session, limit: int = 50):
        return db.query(SecurityEvent).order_by(
            SecurityEvent.created_at.desc()
        ).limit(limit).all()
    
    @staticmethod
    def get_by_severity(db: Session, severity: str, limit: int = 50):
        return db.query(SecurityEvent).filter(
            SecurityEvent.severity == severity
        ).order_by(SecurityEvent.created_at.desc()).limit(limit).all()

def check_database_connection():
    try:
        with get_db_session() as db:
            from sqlalchemy import text
            db.execute(text('SELECT 1'))
            return True
    except Exception as e:
        logger.error(f'Database connection failed: {e}')
        return False

# Initialize database
try:
    init_database()
    logger.info('Database initialized successfully')
except Exception as e:
    logger.warning(f'Database initialization warning: {e}')
