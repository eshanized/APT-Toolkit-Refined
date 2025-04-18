"""
Logging utility for the application.
"""
import os
import logging
import datetime
from pathlib import Path
from typing import Optional

from src.config.settings import settings, ROOT_DIR

# Create logs directory if it doesn't exist
LOGS_DIR = ROOT_DIR / "logs"
LOGS_DIR.mkdir(exist_ok=True)

# Log levels
LOG_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL
}

# Log format
LOG_FORMAT = "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Configure root logger
logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    datefmt=DATE_FORMAT
)

# Create console handler
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))


def get_logger(name: str, log_file: Optional[str] = None) -> logging.Logger:
    """
    Get a logger with the specified name and optional file output.
    
    Args:
        name: Name of the logger
        log_file: Optional file name for logging
        
    Returns:
        Logger instance
    """
    logger = logging.getLogger(name)
    
    # Set log level from settings
    log_level = settings.get("app.log_level", "INFO")
    logger.setLevel(LOG_LEVELS.get(log_level, logging.INFO))
    
    # Remove existing handlers to avoid duplicates
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Add console handler
    logger.addHandler(console_handler)
    
    # Add file handler if specified
    if log_file:
        file_path = LOGS_DIR / log_file
        file_handler = logging.FileHandler(file_path)
        file_handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
        logger.addHandler(file_handler)
    
    return logger


class LogManager:
    """
    Manager for application logs.
    """
    
    @staticmethod
    def get_logs(count: int = 100) -> list:
        """
        Get recent logs from the log directory.
        
        Args:
            count: Maximum number of log entries to return
            
        Returns:
            List of log entries
        """
        logs = []
        today = datetime.datetime.now().strftime("%Y-%m-%d")
        log_file = LOGS_DIR / f"app_{today}.log"
        
        if log_file.exists():
            with open(log_file, 'r') as f:
                lines = f.readlines()
                for line in lines[-count:]:
                    logs.append(line.strip())
        
        return logs
    
    @staticmethod
    def clear_logs() -> bool:
        """
        Clear all log files.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            for log_file in LOGS_DIR.glob("*.log"):
                os.remove(log_file)
            return True
        except Exception:
            return False
    
    @staticmethod
    def export_logs(export_path: Path) -> bool:
        """
        Export logs to a specified path.
        
        Args:
            export_path: Path to export logs to
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(export_path), exist_ok=True)
            
            with open(export_path, 'w') as out_file:
                for log_file in sorted(LOGS_DIR.glob("*.log")):
                    with open(log_file, 'r') as in_file:
                        out_file.write(f"\n--- {log_file.name} ---\n\n")
                        out_file.write(in_file.read())
            
            return True
        except Exception:
            return False


# Create a default application logger
app_logger = get_logger("app", f"app_{datetime.datetime.now().strftime('%Y-%m-%d')}.log") 