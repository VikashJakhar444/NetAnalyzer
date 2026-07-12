"""
Logger module for Network Analyzer & Security Scanner.
Sets up file and console log streams.
"""
import logging
from logging.handlers import RotatingFileHandler
import os
import sys
from pathlib import Path

# Try importing constants. If it fails (during unit tests), use fallback values
try:
    from core.constants import LOG_FILE, LOGS_DIR
except ImportError:
    BASE_DIR = Path(__file__).resolve().parent.parent
    LOGS_DIR = BASE_DIR / "logs"
    LOG_FILE = LOGS_DIR / "scanner.log"


def setup_logger(name: str = "NetworkScanner", level: int = logging.INFO) -> logging.Logger:
    """
    Initializes and configures the logger.
    Creates logs directory if it does not exist.
    """
    # Ensure logs directory exists
    try:
        os.makedirs(LOGS_DIR, exist_ok=True)
    except Exception as e:
        print(f"Error creating logs directory: {e}", file=sys.stderr)

    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Avoid duplicate handlers if setup_logger is called multiple times
    if logger.handlers:
        return logger

    # Log Formatter
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # Rotating File Handler (5 MB per file, keep 3 backups)
    try:
        file_handler = RotatingFileHandler(LOG_FILE, maxBytes=5*1024*1024, backupCount=3, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except Exception as e:
        print(f"Failed to initialize file logger: {e}", file=sys.stderr)

    return logger


# Global application logger
logger = setup_logger()
