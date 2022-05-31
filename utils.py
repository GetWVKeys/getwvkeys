import logging
import threading
from coloredlogs import ColoredFormatter

from config import LOG_DATE_FORMAT, LOG_FORMAT, LOG_LEVEL, WVK_LOG_FILE_PATH, WZ_LOG_FILE_PATH


def construct_logger():
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
    # create a handler for file logging
    file_handler = logging.FileHandler(WVK_LOG_FILE_PATH)
    file_handler.setFormatter(file_formatter)

    # configure werkzeug and flask logger
    wzlogger = logging.getLogger('werkzeug')
    wzlogger.setLevel(logging.DEBUG)
    file_handler = logging.FileHandler(WZ_LOG_FILE_PATH)
    # create a regular non-colored formatter for the log file
    file_formatter = logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
    file_handler.setFormatter(file_formatter)
    wzlogger.addHandler(file_handler)
    wzlogger.addHandler(stream)

    # setup getwvkeys logger
    logger = logging.getLogger(__name__)
    logging.root.setLevel(LOG_LEVEL)

    # construct the logger
    logger = logging.getLogger("getwvkeys")
    logger.setLevel(LOG_LEVEL)
    logger.addHandler(stream)
    logger.addHandler(file_handler)
    return logger


class StoppableThread(threading.Thread):
    """
    Thread class with a stop() method. The thread itself has to check
    regularly for the stopped() condition.
    """

    def __init__(self,  *args, **kwargs):
        super(StoppableThread, self).__init__(*args, **kwargs)
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def stopped(self):
        return self._stop_event.is_set()
