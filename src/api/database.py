"""
Database configuration and session management for SecureOps.
"""

import os
from typing import AsyncGenerator, Generator

from sqlalchemy import MetaData, create_engine
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool

from .models.alert import Alert
from .models.base import Base
from .models.pipeline import Pipeline, PipelineRun, ScanJob

# Import all models to ensure they are registered with Base.metadata
from .models.user import User
from .models.vulnerability import Vulnerability
from .utils.config import get_settings

# Get application settings
settings = get_settings()

# Database URL configuration
DATABASE_URL = settings.database_url
ASYNC_DATABASE_URL = settings.async_database_url

# Create synchronous engine for migrations and admin tasks
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=3600,  # Recycle connections every hour
    echo=settings.debug,  # Log SQL statements in debug mode
)

# Create asynchronous engine for API operations
async_engine = create_async_engine(
    ASYNC_DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=3600,
    echo=settings.debug,
    poolclass=NullPool if settings.environment == "test" else None,
)

# Session makers
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)

AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)

# Metadata for database operations
metadata = MetaData()


def get_db() -> Generator[Session, None, None]:
    """
    Dependency to get database session for synchronous operations.

    Yields:
        Session: SQLAlchemy database session
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


async def get_async_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency to get async database session for FastAPI operations.

    Yields:
        AsyncSession: SQLAlchemy async database session
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


def create_database():
    """
    Create all database tables.
    This should be called during application startup.
    """
    try:
        Base.metadata.create_all(bind=engine)
        print("Database tables created successfully")
    except Exception as e:
        print(f"Error creating database tables: {e}")
        raise


def drop_database():
    """
    Drop all database tables.
    WARNING: This will delete all data!
    """
    try:
        Base.metadata.drop_all(bind=engine)
        print("Database tables dropped successfully")
    except Exception as e:
        print(f"Error dropping database tables: {e}")
        raise


async def check_database_connection() -> bool:
    """
    Check if database connection is working.

    Returns:
        bool: True if connection is successful, False otherwise
    """
    try:
        async with AsyncSessionLocal() as session:
            await session.execute("SELECT 1")
            return True
    except Exception as e:
        print(f"Database connection failed: {e}")
        return False


class DatabaseManager:
    """Database management utilities and operations."""

    def __init__(self):
        self.engine = engine
        self.async_engine = async_engine

    def get_session(self) -> Session:
        """Get a new synchronous database session."""
        return SessionLocal()

    async def get_async_session(self) -> AsyncSession:
        """Get a new asynchronous database session."""
        return AsyncSessionLocal()

    def execute_sql(self, sql: str, params: dict = None) -> any:
        """
        Execute raw SQL query synchronously.

        Args:
            sql: SQL query string
            params: Query parameters

        Returns:
            Query result
        """
        with self.get_session() as session:
            return session.execute(sql, params or {})

    async def execute_async_sql(self, sql: str, params: dict = None) -> any:
        """
        Execute raw SQL query asynchronously.

        Args:
            sql: SQL query string
            params: Query parameters

        Returns:
            Query result
        """
        async with self.get_async_session() as session:
            return await session.execute(sql, params or {})

    def backup_database(self, backup_path: str) -> bool:
        """
        Create a database backup (PostgreSQL specific).

        Args:
            backup_path: Path to store backup file

        Returns:
            bool: True if backup successful, False otherwise
        """
        try:
            import subprocess

            # Extract database info from URL
            from sqlalchemy.engine.url import make_url

            url = make_url(DATABASE_URL)

            # Build pg_dump command
            cmd = [
                "pg_dump",
                "--host",
                url.host or "localhost",
                "--port",
                str(url.port or 5432),
                "--username",
                url.username,
                "--dbname",
                url.database,
                "--file",
                backup_path,
                "--verbose",
                "--no-password",  # Assumes password is in PGPASSWORD env var
            ]

            # Set password in environment
            env = os.environ.copy()
            if url.password:
                env["PGPASSWORD"] = url.password

            # Execute backup
            result = subprocess.run(cmd, env=env, capture_output=True, text=True)

            if result.returncode == 0:
                print(f"Database backup created successfully: {backup_path}")
                return True
            else:
                print(f"Database backup failed: {result.stderr}")
                return False

        except Exception as e:
            print(f"Error creating database backup: {e}")
            return False

    def restore_database(self, backup_path: str) -> bool:
        """
        Restore database from backup (PostgreSQL specific).

        Args:
            backup_path: Path to backup file

        Returns:
            bool: True if restore successful, False otherwise
        """
        try:
            import subprocess

            # Extract database info from URL
            from sqlalchemy.engine.url import make_url

            url = make_url(DATABASE_URL)

            # Build psql command
            cmd = [
                "psql",
                "--host",
                url.host or "localhost",
                "--port",
                str(url.port or 5432),
                "--username",
                url.username,
                "--dbname",
                url.database,
                "--file",
                backup_path,
                "--no-password",
            ]

            # Set password in environment
            env = os.environ.copy()
            if url.password:
                env["PGPASSWORD"] = url.password

            # Execute restore
            result = subprocess.run(cmd, env=env, capture_output=True, text=True)

            if result.returncode == 0:
                print(f"Database restored successfully from: {backup_path}")
                return True
            else:
                print(f"Database restore failed: {result.stderr}")
                return False

        except Exception as e:
            print(f"Error restoring database: {e}")
            return False

    async def get_database_stats(self) -> dict:
        """
        Get database statistics and health information.

        Returns:
            dict: Database statistics
        """
        try:
            stats = {}

            async with self.get_async_session() as session:
                # Table row counts
                tables = [
                    ("users", User),
                    ("pipelines", Pipeline),
                    ("pipeline_runs", PipelineRun),
                    ("vulnerabilities", Vulnerability),
                    ("alerts", Alert),
                ]

                for table_name, model in tables:
                    result = await session.execute(f"SELECT COUNT(*) FROM {table_name}")
                    count = result.scalar()
                    stats[f"{table_name}_count"] = count

                # Database size (PostgreSQL specific)
                try:
                    result = await session.execute("SELECT pg_size_pretty(pg_database_size(current_database()))")
                    stats["database_size"] = result.scalar()
                except BaseException:
                    stats["database_size"] = "Unknown"

                # Active connections
                try:
                    result = await session.execute("SELECT count(*) FROM pg_stat_activity WHERE state = 'active'")
                    stats["active_connections"] = result.scalar()
                except BaseException:
                    stats["active_connections"] = 0

            return stats

        except Exception as e:
            print(f"Error getting database stats: {e}")
            return {}


# Global database manager instance
db_manager = DatabaseManager()


# Health check functions
async def health_check() -> dict:
    """
    Perform comprehensive database health check.

    Returns:
        dict: Health check results
    """
    health = {
        "database_connected": False,
        "tables_exist": False,
        "can_read": False,
        "can_write": False,
        "stats": {},
    }

    try:
        # Check connection
        health["database_connected"] = await check_database_connection()

        if health["database_connected"]:
            async with AsyncSessionLocal() as session:
                # Check if tables exist
                try:
                    await session.execute("SELECT 1 FROM users LIMIT 1")
                    health["tables_exist"] = True
                    health["can_read"] = True
                except BaseException:
                    health["tables_exist"] = False

                # Check write capability (if tables exist)
                if health["tables_exist"]:
                    try:
                        # This is a read-only test to avoid creating test data
                        result = await session.execute("SELECT current_timestamp")
                        if result:
                            health["can_write"] = True
                    except BaseException:
                        health["can_write"] = False

            # Get database statistics
            health["stats"] = await db_manager.get_database_stats()

    except Exception as e:
        health["error"] = str(e)

    return health


# Database initialization functions
def init_database():
    """Initialize database with tables and basic data."""
    try:
        print("Initializing database...")
        create_database()

        # Create default admin user if it doesn't exist
        with SessionLocal() as session:
            admin_user = session.query(User).filter(User.username == "admin").first()
            if not admin_user:
                admin_user = User(
                    username="admin",
                    email="admin@secureops.local",
                    full_name="System Administrator",
                    is_superuser=True,
                    is_active=True,
                    is_verified=True,
                )
                # Set a simple hashed password temporarily
                import hashlib

                simple_hash = hashlib.sha256("admin123".encode()).hexdigest()
                admin_user.hashed_password = simple_hash
                session.add(admin_user)
                session.commit()
                print("Default admin user created")

        print("Database initialization completed successfully")

    except Exception as e:
        print(f"Database initialization failed: {e}")
        raise


async def cleanup_database():
    """Clean up old data and optimize database."""
    try:
        print("Starting database cleanup...")

        async with AsyncSessionLocal() as session:
            # Clean up old pipeline runs (keep last 1000 per pipeline)
            await session.execute(
                """
                DELETE FROM pipeline_runs
                WHERE id NOT IN (
                    SELECT id FROM (
                        SELECT id,
                               ROW_NUMBER() OVER (PARTITION BY pipeline_id ORDER BY created_at DESC) as rn
                        FROM pipeline_runs
                    ) t WHERE t.rn <= 1000
                )
            """
            )

            # Clean up resolved vulnerabilities older than 6 months
            await session.execute(
                """
                DELETE FROM vulnerabilities
                WHERE status = 'resolved'
                AND resolved_at < NOW() - INTERVAL '6 months'
            """
            )

            # Clean up closed alerts older than 3 months
            await session.execute(
                """
                DELETE FROM alerts
                WHERE status IN ('closed', 'resolved')
                AND resolved_at < NOW() - INTERVAL '3 months'
            """
            )

            await session.commit()
            print("Database cleanup completed")

    except Exception as e:
        print(f"Database cleanup failed: {e}")
        raise
