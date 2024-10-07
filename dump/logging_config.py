import logging
import os
from datetime import datetime


def setup_logging(
    log_dir: str = "logs", log_level: int = logging.DEBUG
) -> logging.Logger:
    """
    Initialize logging configuration.

    Args:
        log_dir (str): Directory to store log files.
        log_level (int): Logging level.

    Returns:
        logging.Logger: Configured logger.
    """
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    log_filename = datetime.now().strftime("app_%Y%m%d_%H%M%S.log")
    log_path = os.path.join(log_dir, log_filename)

    logger = logging.getLogger()
    logger.setLevel(log_level)

    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # File Handler
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(log_level)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Console Handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    logger.debug(f"Logging initialized. Log file at {log_path}")
    return logger
