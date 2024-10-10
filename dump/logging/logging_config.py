import logging
import os


def setup_logging(log_dir: str = "logs", log_level=logging.DEBUG):
    """Set up logging configuration."""
    os.makedirs(log_dir, exist_ok=True)
    logging.basicConfig(
        level=log_level,  # DEBUG level for detailed logs
        format="[%(asctime)s] [%(levelname)s] %(name)s:%(lineno)d: %(message)s",
        handlers=[
            logging.FileHandler(os.path.join(log_dir, "app.log"), encoding="utf-8"),
            logging.StreamHandler(),
        ],
    )
    logger = logging.getLogger()

    # Adjust logging levels for specific modules if needed
    logging.getLogger("dump.memory_dumper").setLevel(
        logging.WARNING
    )  # Ignore INFO and DEBUG logs for memory_dumper
    logging.getLogger("dump.memory_analyzer").setLevel(
        logging.ERROR
    )  # Ignore WARNING, INFO, DEBUG logs for memory_analyzer

    return logger
