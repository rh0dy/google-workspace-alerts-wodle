"""
Logging configuration for Google Workspace Alerts Wodle.
"""
import logging
import sys
from pathlib import Path
from typing import Optional

def setup_logger(name: str, log_file: str, log_level: int) -> logging.Logger:
    """
    Set up and configure logger with file and console handlers.

    Args:
        name: The name of the logger
        log_file: Path to the log file
        log_level: Logging level (from logging module)

    Returns:
        logging.Logger: Configured logger instance

    Raises:
        PermissionError: If the log file cannot be created due to permissions
        IOError: If there is an I/O error when creating the log file
    """
    logger = logging.getLogger(name)
    logger.setLevel(log_level)

    # Clear existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Create formatters and handlers
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    # Ensure log directory exists
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # File handler
    try:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except (PermissionError, IOError) as e:
        sys.stderr.write(f"Warning: Could not set up file logging: {str(e)}\n")

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger

def cleanup_logger(logger: Optional[logging.Logger]) -> None:
    """
    Close and remove all log handlers safely.

    Args:
        logger: The logger instance to clean up

    Returns:
        None

    Raises:
        Exception: For any errors during handler cleanup
    """
    if logger:
        logger.info("Cleaning up resources...")
        for handler in logger.handlers[:]:
            try:
                handler.close()
            except Exception as e:
                sys.stderr.write(f"Error during handler cleanup: {str(e)}\n")
            finally:
                logger.removeHandler(handler)