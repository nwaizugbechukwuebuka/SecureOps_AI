#!/usr/bin/env python3
"""
Simple startup script for SecureOps AI Backend
Handles basic initialization and starts the server
"""

import os
import sys
import logging
from pathlib import Path

# Add backend directory to path
backend_dir = Path(__file__).parent
sys.path.insert(0, str(backend_dir))

# Set environment variables
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("DEBUG", "true")
os.environ.setdefault("HOST", "0.0.0.0")
os.environ.setdefault("PORT", "8000")

# Configure basic logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("SecureOps-Startup")


def main():
    """Main startup function"""
    try:
        logger.info("Starting SecureOps AI Backend...")

        # Import and run the application
        from main import app
        import uvicorn

        # Get configuration
        host = os.getenv("HOST", "0.0.0.0")
        port = int(os.getenv("PORT", "8000"))
        debug = os.getenv("DEBUG", "true").lower() == "true"

        logger.info(f"Configuration: host={host}, port={port}, debug={debug}")

        # Run the server
        uvicorn.run("main:app", host=host, port=port, reload=debug, access_log=True, log_level="info")

    except ImportError as e:
        logger.error(f"Import error: {e}")
        logger.error("Make sure all dependencies are installed: pip install -r requirements.txt")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Startup error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
