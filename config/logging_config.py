"""
Unified logging configuration for SecureOps.
"""

import logging
import sys
from config.settings import settings

LOG_LEVEL = getattr(logging, settings.log_level.upper(), logging.INFO)

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)
