import logging
import logging.handlers
from coloredlogs import ColoredFormatter
from discord import Enum

from config import LOG_DATE_FORMAT, LOG_FORMAT, LOG_LEVEL, WVK_LOG_FILE_PATH, WZ_LOG_FILE_PATH


class APIAction(Enum):
    DISABLE_USER = "disable"
    DISABLE_USER_BULK = "disable_bulk"
    ENABLE_USER = "enable"
    KEY_COUNT = "keycount"
    USER_COUNT = "usercount"
    SEARCH = "search"


def construct_logger():
    logging.root.setLevel(LOG_LEVEL)

    WVK_LOG_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    WZ_LOG_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)

    # setup handlers
    # create a colored formatter for the console
    console_formatter = ColoredFormatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
    # create a regular non-colored formatter for the log file
    file_formatter = logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
    # create a handler for console logging
    stream = logging.StreamHandler()
    stream.setLevel(LOG_LEVEL)
    stream.setFormatter(console_formatter)
    # create a handler for file logging, 5 mb max size, with 5 backup files
    file_handler = logging.handlers.RotatingFileHandler(
        WVK_LOG_FILE_PATH, maxBytes=(1024*1024) * 5, backupCount=5)
    file_handler.setFormatter(file_formatter)

    # configure werkzeug and flask logger
    wzlogger = logging.getLogger('werkzeug')
    wzlogger.setLevel(logging.DEBUG)
    file_handler = logging.handlers.RotatingFileHandler(
        WZ_LOG_FILE_PATH, maxBytes=(1024*1024) * 5, backupCount=5)
    # create a regular non-colored formatter for the log file
    file_formatter = logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
    file_handler.setFormatter(file_formatter)
    wzlogger.addHandler(file_handler)
    wzlogger.addHandler(stream)

    # construct the logger
    logger = logging.getLogger("getwvkeys")
    logger.setLevel(LOG_LEVEL)
    logger.addHandler(stream)
    logger.addHandler(file_handler)
    return logger
