import logging

__all__ = ["logger"]

# 定义自定义日志格式和颜色
class CustomFormatter(logging.Formatter):
    """自定义一个日志格式器"""

    YELLOW = '\033[33m'
    WHITE = '\033[37m'
    RESET = '\033[0m'

    FORMAT = "%(levelcolor)s%(levelname)s%(reset)s: %(messagecolor)s%(message)s%(reset)s"

    FORMATS = {
        logging.WARNING: FORMAT.replace('%(levelcolor)s', YELLOW).replace('%(messagecolor)s', WHITE)
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, style='%')
        formatter.default_time_format = '%Y-%m-%d %H:%M:%S'
        formatter.default_msec_format = '%s.%03d'
        record.reset = self.RESET
        return formatter.format(record)

def setup_logger():
    """设置日志记录器"""
    logger = logging.getLogger("custom_logger")
    logger.setLevel(logging.WARNING)
    ch = logging.StreamHandler()
    ch.setLevel(logging.WARNING)
    ch.setFormatter(CustomFormatter())
    logger.addHandler(ch)
    return logger

# 使用自定义日志记录器
logger = setup_logger()