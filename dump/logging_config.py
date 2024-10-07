import logging
import os


def setup_logging(log_dir: str = "logs", log_level=logging.DEBUG):
    os.makedirs(log_dir, exist_ok=True)
    logging.basicConfig(
        level=log_level,
        format='[%(asctime)s] [%(levelname)s] %(name)s: %(message)s',
        handlers=[
            logging.FileHandler(os.path.join(log_dir, "app.log"), encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger()