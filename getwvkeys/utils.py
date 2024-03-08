"""
 This file is part of the GetWVKeys project (https://github.com/GetWVKeys/getwvkeys)
 Copyright (C) 2022-2024 Notaghost, Puyodead1 and GetWVKeys contributors 
 
 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published
 by the Free Software Foundation, version 3 of the License.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import base64
import logging
import logging.handlers
import re
from enum import Enum
from typing import Union

from cerberus import Validator
from coloredlogs import ColoredFormatter

from getwvkeys import config
from getwvkeys.pssh_utils import parse_pssh


class OPCode(Enum):
    DISABLE_USER = 0
    DISABLE_USER_BULK = 1
    ENABLE_USER = 2
    KEY_COUNT = 3
    USER_COUNT = 4
    SEARCH = 5
    UPDATE_PERMISSIONS = 6
    QUARANTINE = 7
    REPLY = 8
    RESET_API_KEY = 9


class UserFlags(Enum):
    ADMIN = 1 << 0
    BETA_TESTER = 1 << 1
    VINETRIMMER = 1 << 2
    KEY_ADDING = 1 << 3
    SUSPENDED = 1 << 4
    BLACKLIST_EXEMPT = 1 << 5


class FlagAction(Enum):
    ADD = "add"
    REMOVE = "remove"


def construct_logger():
    # ensure parent folders exist
    config.WVK_LOG_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)

    # setup handlers
    # create a colored formatter for the console
    console_formatter = ColoredFormatter(config.LOG_FORMAT, datefmt=config.LOG_DATE_FORMAT)

    # create a regular non-colored formatter for the log file
    file_formatter = logging.Formatter(config.LOG_FORMAT, datefmt=config.LOG_DATE_FORMAT)

    # create a handler for console logging
    stream = logging.StreamHandler()
    stream.setLevel(config.CONSOLE_LOG_LEVEL)
    stream.setFormatter(console_formatter)

    # create a handler for file logging, 5 mb max size, with 5 backup files
    file_handler = logging.handlers.RotatingFileHandler(
        config.WVK_LOG_FILE_PATH, maxBytes=(1024 * 1024) * 5, backupCount=5
    )
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(config.FILE_LOG_LEVEL)

    # construct the logger
    logger = logging.getLogger("getwvkeys")
    logger.setLevel(config.CONSOLE_LOG_LEVEL)
    logger.addHandler(stream)
    logger.addHandler(file_handler)
    return logger


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
        if len(parsed_pssh.key_ids) == 1:
            return parsed_pssh.key_ids[0].hex()
        elif len(parsed_pssh.key_ids) > 1:
            logger.warning("Multiple key ids found in pssh! {}".format(pssh))
            return parsed_pssh.key_ids[0].hex()
        elif len(parsed_pssh.key_ids) == 0:
            if len(parsed_pssh.data.key_ids) == 0 and parsed_pssh.data.content_id:
                return base64.b64encode(bytes.fromhex(parsed_pssh.data.content_id)).hex()
            elif len(parsed_pssh.data.key_ids) == 1:
                return parsed_pssh.data.key_ids[0]
            elif len(parsed_pssh.data.key_ids) > 1:
                logger.warning("Multiple key ids found in pssh! {}".format(pssh))
                return parsed_pssh.data.key_ids[0]
            else:
                raise Exception("No KID or Content ID was found in the PSSH.")
        else:
            raise Exception("No KID or Content ID was found in the PSSH.")
    except Exception as e:
        raise e


class Validators:
    def __init__(self) -> None:
        self.vinetrimmer_schema = {
            "method": {"required": True, "type": "string", "allowed": ["GetKeysX", "GetKeys", "GetChallenge"]},
            "params": {"required": False, "type": "dict"},
            "token": {"required": True, "type": "string"},
        }
        self.key_exchange_schema = {
            "cdmkeyresponse": {"required": True, "type": ["string", "binary"]},
            "encryptionkeyid": {"required": True, "type": ["string", "binary"]},
            "hmackeyid": {"required": True, "type": ["string", "binary"]},
            "session_id": {"required": True, "type": "string"},
        }
        self.keys_schema = {
            "cdmkeyresponse": {"required": True, "type": ["string", "binary"]},
            "session_id": {"required": True, "type": "string"},
        }
        self.challenge_schema = {
            "init": {"required": True, "type": "string"},
            "cert": {"required": True, "type": "string"},
            "raw": {"required": True, "type": "boolean"},
            "licensetype": {"required": True, "type": "string", "allowed": ["OFFLINE", "STREAMING"]},
            "device": {"required": True, "type": "string"},
        }
        self.vinetrimmer_validator = Validator(self.vinetrimmer_schema)
        self.key_exchange_validator = Validator(self.key_exchange_schema)
        self.keys_validator = Validator(self.keys_schema)
        self.challenge_validator = Validator(self.challenge_schema)


class Bitfield:
    def __init__(self, bits: Union[int, UserFlags] = 0):
        if isinstance(bits, UserFlags):
            bits = bits.value
        self.bits = bits

    def add(self, bit: Union[int, UserFlags]):
        if isinstance(bit, UserFlags):
            bit = bit.value
        self.bits |= bit
        return self.bits

    def remove(self, bit: Union[int, UserFlags]):
        if isinstance(bit, UserFlags):
            bit = bit.value
        self.bits &= ~bit
        return self.bits

    def has(self, bit: Union[int, UserFlags]):
        if isinstance(bit, UserFlags):
            bit = bit.value
        return (self.bits & bit) == bit


class BlacklistEntry:
    def __init__(self, obj) -> None:
        self.url = obj["url"]
        self.partial = obj["partial"]

        if self.partial:
            self.url = re.compile(self.url)

    def matches(self, url: str):
        if self.partial:
            m = self.url.match(url)
            return m is not None
        else:
            return self.url == url


class Blacklist:
    def __init__(self) -> None:
        self.blacklist: list[BlacklistEntry] = list()

        for x in config.DEFAULT_BLACKLISTED_URLS:
            self.blacklist.append(BlacklistEntry(x))

    def is_url_blacklisted(self, url: str):
        for entry in self.blacklist:
            if entry.matches(url):
                return True
        return False
