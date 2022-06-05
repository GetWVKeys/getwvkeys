import logging
import logging.handlers
from enum import Enum

from coloredlogs import ColoredFormatter

from getwvclone import config


class APIAction(Enum):
    DISABLE_USER = "disable"
    DISABLE_USER_BULK = "disable_bulk"
    ENABLE_USER = "enable"
    KEY_COUNT = "keycount"
    USER_COUNT = "usercount"
    SEARCH = "search"


def construct_logger():
    logging.root.setLevel(config.LOG_LEVEL)

    config.WVK_LOG_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    config.WZ_LOG_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)

    # setup handlers
    # create a colored formatter for the console
    console_formatter = ColoredFormatter(config.LOG_FORMAT, datefmt=config.LOG_DATE_FORMAT)
    # create a regular non-colored formatter for the log file
    file_formatter = logging.Formatter(config.LOG_FORMAT, datefmt=config.LOG_DATE_FORMAT)
    # create a handler for console logging
    stream = logging.StreamHandler()
    stream.setLevel(config.LOG_LEVEL)
    stream.setFormatter(console_formatter)
    # create a handler for file logging, 5 mb max size, with 5 backup files
    file_handler = logging.handlers.RotatingFileHandler(
        config.WVK_LOG_FILE_PATH, maxBytes=(1024*1024) * 5, backupCount=5)
    file_handler.setFormatter(file_formatter)

    # configure werkzeug and flask logger
    wzlogger = logging.getLogger('werkzeug')
    wzlogger.setLevel(logging.DEBUG)
    file_handler = logging.handlers.RotatingFileHandler(
        config.WZ_LOG_FILE_PATH, maxBytes=(1024*1024) * 5, backupCount=5)
    # create a regular non-colored formatter for the log file
    file_formatter = logging.Formatter(config.LOG_FORMAT, datefmt=config.LOG_DATE_FORMAT)
    file_handler.setFormatter(file_formatter)
    wzlogger.addHandler(file_handler)
    wzlogger.addHandler(stream)

    # construct the logger
    logger = logging.getLogger("getwvkeys")
    logger.setLevel(config.LOG_LEVEL)
    logger.addHandler(stream)
    logger.addHandler(file_handler)
    return logger
