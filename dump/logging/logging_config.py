import logging
import os


def setup_logging(log_dir: str = "logs", log_level=logging.INFO):  # log_level을 INFO로 설정
    """Set up logging configuration."""
    
    # **기존 핸들러 모두 제거**
    root = logging.getLogger()
    for handler in root.handlers[:]:
        root.removeHandler(handler)
    
    os.makedirs(log_dir, exist_ok=True)
    logging.basicConfig(
        level=log_level,  # INFO 레벨 설정
        format="[%(asctime)s] [%(levelname)s] %(name)s:%(lineno)d: %(message)s",
        handlers=[
            logging.FileHandler(os.path.join(log_dir, "app.log"), encoding="utf-8"),
            logging.StreamHandler(),
        ],
    )
    logger = logging.getLogger()

    # **특정 모듈의 로깅 레벨 조정**
    logging.getLogger("dump.memory_dumper").setLevel(logging.WARNING)  # memory_dumper의 로그 레벨을 WARNING으로 설정
    logging.getLogger("dump.memory_analyzer").setLevel(logging.ERROR)  # memory_analyzer의 로그 레벨을 ERROR로 설정
    
    logging.getLogger("pymem").setLevel(logging.WARNING)  # pymem의 로그 레벨을 WARNING으로 설정  # 추가된 라인

    return logger