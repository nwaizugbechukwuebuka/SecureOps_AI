#!/usr/bin/env python3
"""
Test script to verify that all requirements.txt dependencies can be imported successfully.
"""

import pytest


def test_core_imports():
    """Test core FastAPI and database imports."""
    print("Testing core dependencies...")

    # FastAPI core
    import fastapi
    import pydantic
    import starlette
    import uvicorn

    print("✅ FastAPI core imports successful")

    # Database
    import aiosqlite
    import alembic
    import asyncpg
    import psycopg2
    import sqlalchemy

    print("✅ Database imports successful")

    # Authentication & Security
    import cryptography
    import itsdangerous
    import jose
    import passlib

    print("✅ Authentication imports successful")

    # Task Queue
    import celery
    import flower
    import kombu
    import redis

    print("✅ Task queue imports successful")

    # HTTP Clients
    import aiohttp
    import httpx
    import requests

    print("✅ HTTP client imports successful")

    # CI/CD Platform APIs
    import github
    import gitlab
    import jenkinsapi

    print("✅ CI/CD platform imports successful")

    # Security Scanning
    import bandit
    import docker
    import safety

    print("✅ Security scanning imports successful")

    # Configuration
    import dotenv
    import toml
    import yaml

    print("✅ Configuration imports successful")

    # Monitoring & Logging
    import prometheus_client
    import sentry_sdk
    import structlog

    print("✅ Monitoring imports successful")

    # Utilities
    import email_validator
    import psutil
    import validators

    print("✅ Utility imports successful")

    # Testing
    import faker
    import pytest

    print("✅ Testing imports successful")

    # Code Quality
    import black
    import flake8
    import isort
    import mypy

    print("✅ Code quality imports successful")

    # Development Tools
    import rich
    import typer
    import watchdog

    print("✅ Development tool imports successful")

    # Data Processing
    import matplotlib
    import numpy
    import pandas
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
    import anyio
    import jsonschema
    import jwt

    print("✅ Additional imports successful")

    # Use assertions to ensure all imports succeeded
    assert fastapi is not None
    assert pydantic is not None
    assert aiosqlite is not None
    assert cryptography is not None
    assert celery is not None
    assert aiohttp is not None
    assert github is not None
    assert bandit is not None
    assert dotenv is not None
    assert prometheus_client is not None
    assert email_validator is not None
    assert faker is not None
    assert black is not None
    assert rich is not None
    assert matplotlib is not None
    assert sendgrid is not None
    assert apscheduler is not None
    assert anyio is not None


def test_project_structure():
    """Test that project modules can be imported."""
    print("\nTesting project structure...")

    try:
        # Test database models
        import os
        import sys

        # Add the src directory to Python path (parent of tests directory)
        src_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if src_path not in sys.path:
            sys.path.insert(0, src_path)

        from api.database import AsyncSessionLocal, async_engine
        from api.models.alert import Alert
        from api.models.base import Base
        from api.models.user import User
        from api.utils.config import get_settings

        print("✅ Core project modules imported successfully")

        # Use assertions instead of returning True
        assert AsyncSessionLocal is not None
        assert async_engine is not None
        assert Alert is not None
        assert Base is not None
        assert User is not None
        assert get_settings is not None

    except ImportError as e:
        print(f"❌ Project module import failed: {e}")
        # Use pytest.fail() instead of returning False
        pytest.fail(f"Project module import failed: {e}")


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
