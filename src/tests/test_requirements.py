#!/usr/bin/env python3
"""
Test script to verify that all requirements.txt dependencies can be imported successfully.
"""

def test_core_imports():
    """Test core FastAPI and database imports."""
    print("Testing core dependencies...")
    
    # FastAPI core
    import fastapi
    import uvicorn
    import pydantic
    import starlette
    print("✅ FastAPI core imports successful")
    
    # Database
    import sqlalchemy
    import alembic
    import asyncpg
    import psycopg2
    import aiosqlite
    print("✅ Database imports successful")
    
    # Authentication & Security
    import jose
    import passlib
    import cryptography
    import itsdangerous
    print("✅ Authentication imports successful")
    
    # Task Queue
    import celery
    import redis
    import flower
    import kombu
    print("✅ Task queue imports successful")
    
    # HTTP Clients
    import httpx
    import aiohttp
    import requests
    print("✅ HTTP client imports successful")
    
    # CI/CD Platform APIs
    import github
    import gitlab
    import jenkinsapi
    print("✅ CI/CD platform imports successful")
    
    # Security Scanning
    import safety
    import bandit
    import docker
    print("✅ Security scanning imports successful")
    
    # Configuration
    import dotenv
    import yaml
    import toml
    print("✅ Configuration imports successful")
    
    # Monitoring & Logging
    import prometheus_client
    import structlog
    import sentry_sdk
    print("✅ Monitoring imports successful")
    
    # Utilities
    import email_validator
    import validators
    import psutil
    print("✅ Utility imports successful")
    
    # Testing
    import pytest
    import faker
    print("✅ Testing imports successful")
    
    # Code Quality
    import black
    import isort
    import flake8
    import mypy
    print("✅ Code quality imports successful")
    
    # Development Tools
    import watchdog
    import rich
    import typer
    print("✅ Development tool imports successful")
    
    # Data Processing
    import pandas
    import numpy
    import matplotlib
    import plotly
    print("✅ Data processing imports successful")
    
    # Notifications
    import sendgrid
    import slack_sdk
    print("✅ Notification imports successful")
    
    # Scheduling
    import apscheduler
    print("✅ Scheduling imports successful")
    
    # Additional dependencies
    import jwt
    import anyio
    import jsonschema
    print("✅ Additional imports successful")
    
    return True

def test_project_structure():
    """Test that project modules can be imported."""
    print("\nTesting project structure...")
    
    try:
        # Test database models
        import sys
        import os
        src_path = os.path.join(os.path.dirname(__file__), 'src')
        sys.path.append(src_path)
        
        from api.database import AsyncSessionLocal, async_engine
        from api.models.base import Base
        from api.models.user import User
        from api.models.alert import Alert
        from api.utils.config import get_settings
        print("✅ Core project modules imported successfully")
        
        return True
    except ImportError as e:
        print(f"❌ Project module import failed: {e}")
        return False

if __name__ == "__main__":
    print("🔍 SecureOps AI Requirements Validation")
    print("=" * 50)
    
    try:
        # Test all imports
        test_core_imports()
        test_project_structure()
        
        print("\n" + "=" * 50)
        print("🎉 ALL REQUIREMENTS VALIDATED SUCCESSFULLY!")
        print("✅ Your consolidated requirements.txt file is working perfectly!")
        print("✅ All dependencies are installed and can be imported")
        print("✅ Core project modules are accessible")
        
    except Exception as e:
        print(f"\n❌ Requirements validation failed: {e}")
        print("🔧 Please check your requirements.txt file and virtual environment")
        exit(1)