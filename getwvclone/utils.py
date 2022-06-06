import logging
import logging.handlers
from enum import Enum
import time
from typing import Union

import mariadb
from coloredlogs import ColoredFormatter

from getwvclone import config
from getwvclone.pssh_utils import parse_pssh


class APIAction(Enum):
    DISABLE_USER = "disable"
    DISABLE_USER_BULK = "disable_bulk"
    ENABLE_USER = "enable"
    KEY_COUNT = "keycount"
    USER_COUNT = "usercount"
    SEARCH = "search"


def log_date_time_string():
    """Return the current time formatted for logging."""
    monthname = [None, "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    now = time.time()
    year, month, day, hh, mm, ss, x, y, z = time.localtime(now)
    s = "%02d/%3s/%04d %02d:%02d:%02d" % (day, monthname[month], year, hh, mm, ss)
    return s


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
    file_handler = logging.handlers.RotatingFileHandler(config.WVK_LOG_FILE_PATH, maxBytes=(1024 * 1024) * 5, backupCount=5)
    file_handler.setFormatter(file_formatter)

    # configure werkzeug logger
    wzlogger = logging.getLogger("werkzeug")
    wzlogger.setLevel(logging.ERROR)
    file_handler = logging.handlers.RotatingFileHandler(config.WZ_LOG_FILE_PATH, maxBytes=(1024 * 1024) * 5, backupCount=5)

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


class DatabaseManager:
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.connection = None
        self.cursor = None

    def connect(self):
        if self.connection != None:
            self.logger.warning("[Database] Tried to connect to database, but a connection is already open!")
            return True
        try:
            self.logger.info("[Database] Attempting to connect to database...")
            self.connection = mariadb.connect(
                user=config.DATABASE_USER,
                password=config.DATABASE_PASSWORD,
                host=config.DATABASE_HOST,
                port=config.DATABASE_PORT,
                database=config.DATABASE_NAME,
            )
            self.connection.autocommit = True
            self.cursor = self.connection.cursor()
            self.logger.info("[Database] Successfully connected to database.")
            return True
        except mariadb.Error as e:
            self.logger.fatal("Error connecting to database: {}".format(e))
            return False

    def disconnect(self):
        if self.connection == None:
            self.logger.warning("[Database] Tried to disconnect from database, but no connection is open!")
            return True
        try:
            self.cursor.close()
            self.connection.close()
            self.connection = None
            self.cursor = None
            return True
        except mariadb.Error as e:
            self.logger.fatal("[Database] Error disconnecting from database: {}".format(e))
            return False

    def execute(self, query: str, args=Union[None, tuple]):
        if self.connection == None:
            self.logger.warning("[Database] Tried to execute query, but no connection is open!")
            return False
        try:
            self.cursor.execute(query, args)
            return True
        except mariadb.Error as e:
            self.logger.fatal("[Database] Error executing query: {}".format(e))
            return False

    def fetchall(self):
        return self.cursor.fetchall()

    def fetchone(self):
        return self.cursor.fetchone()

    def get_cursor(self):
        return self.cursor

    def get_connection(self):
        return self.connection


class CacheBase(object):
    def __init__(self, added_at: int, added_by: Union[str, None], license_url: Union[str, None]):
        self.added_at = added_at
        self.added_by = added_by
        self.license_url = license_url

    @staticmethod
    def from_dict(d: dict):
        (added_at, added_by, license_url) = (d["added_at"], d.get("added_by"), d.get("license_url"))
        return CacheBase(added_at, added_by, license_url)


class CachedKey(CacheBase):
    """
    Represents cached key information that contains a single key
    """

    def __init__(self, kid: str, added_at: int, added_by: Union[str, None], license_url: Union[str, None], key: str):
        super().__init__(added_at, added_by, license_url)
        self.kid = kid
        self.key = key

    @staticmethod
    def from_dict(d: dict):
        (kid, added_at, license_url, key) = (d["kid"], d["added_at"], d.get("license_url", None), d["key"])
        return CachedKey(kid, added_at, license_url, key)

    def to_json(self):
        return {"kid": self.kid, "added_at": self.added_at, "license_url": self.license_url, "key": self.key}


def extract_kid_from_pssh(pssh: str):
    logger = logging.getLogger("getwvkeys")
    try:
        parsed_pssh = parse_pssh(pssh)
        if len(parsed_pssh.key_ids) == 0:
            if len(parsed_pssh.data.key_ids) == 0:
                raise Exception("No key id found in pssh")
            elif len(parsed_pssh.data.key_ids) > 1:
                logger.warning("Multiple key ids found in pssh! {}".format(pssh))
                return parsed_pssh.data.key_ids
            else:
                return parsed_pssh.data.key_ids[0]
    except Exception as e:
        raise e
