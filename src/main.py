from __future__ import annotations

from api.fastapi_app import create_app  # noqa: E402
import uvicorn  # noqa: E402

import asyncio
import logging
import sys
from pathlib import Path

"""
UVicorn-ready entry point for SecureOps_AI.

Usage:
    python -m src.main
    uvicorn api.fastapi_app:create_app --factory
"""



def _ensure_src_on_path() -> None:
    root = Path(__file__).resolve().parent
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))


def _setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def main() -> None:
    _ensure_src_on_path()
    _setup_logging()
    logging.getLogger("secureops").info("Starting SecureOps_AI...")

    try:
        # Lazy imports (intentional) â€” prevent startup failure if deps missing


        app = create_app()
        uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")
    except Exception:
        logging.getLogger("secureops").exception("Failed to start uvicorn â€” falling back to run loop")
        loop = asyncio.get_event_loop()
        try:
            loop.run_forever()
        finally:
            loop.close()


if __name__ == "__main__":
    main()
