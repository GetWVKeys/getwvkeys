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
import os
import pathlib
import time

import toml

logger = logging.getLogger(__name__)

IS_DEVELOPMENT = bool(os.environ.get("DEVELOPMENT", False))
IS_STAGING = bool(os.environ.get("STAGING", False))
CONFIG_ENV = os.environ.get("CONFIG", None)  # used for docker, config is base64 encoded toml
CONFIG_FILE = "config.dev.toml" if IS_DEVELOPMENT else "config.staging.toml" if IS_STAGING else "config.toml"
CONFIG = toml.loads(base64.b64decode(CONFIG_ENV).decode()) if CONFIG_ENV else toml.load(CONFIG_FILE)

SECRET_KEY = CONFIG["general"]["secret_key"]  # Flask secret key

# auto generate secret key if not set
if not SECRET_KEY:
    logger.warning("No secret key found in config.toml, generating a new one.")
    SECRET_KEY = os.urandom(32).hex()
    CONFIG["general"]["secret_key"] = SECRET_KEY
    with open(CONFIG_FILE, "w") as f:
        toml.dump(CONFIG, f)

OAUTH2_CLIENT_ID = CONFIG["oauth"]["client_id"]  # Discord OAuth Client ID
OAUTH2_CLIENT_SECRET = CONFIG["oauth"]["client_secret"]  # Discord OAuth Client Secret
OAUTH2_REDIRECT_URL = CONFIG["oauth"]["redirect_url"]  # Discord OAuth Callback URL
SQLALCHEMY_DATABASE_URI = CONFIG["general"]["database_uri"]  # Database connection URI
REDIS_URI = CONFIG["general"].get("redis_uri", None)  # Redis connection URI

if SQLALCHEMY_DATABASE_URI.startswith("sqlite"):
    raise Exception("SQLite is not supported, please use a different database.")

API_HOST = CONFIG.get("api", {}).get("host", "0.0.0.0")
API_PORT = int(CONFIG.get("api", {}).get("port", 8080))
API_URL = CONFIG.get("api", {}).get("base_url", "https://getwvkeys.cc")

MAX_SESSIONS = CONFIG["general"].get("max_sessions", 60)
DEFAULT_DEVICES = CONFIG["general"].get("default_devices", [])  # list of build infos to use in key rotation
GUILD_ID = CONFIG["general"]["guild_id"]  # Discord Guild ID
VERIFIED_ROLE_ID = CONFIG["general"]["verified_role_id"]  # Discord Verified role ID
LOGIN_DISABLED = CONFIG["general"].get("login_disabled", False)
CONSOLE_LOG_LEVEL = logging.DEBUG
FILE_LOG_LEVEL = logging.DEBUG
LOG_FORMAT = CONFIG["general"].get(
    "log_format",
    "[%(asctime)s] [%(name)s] [%(funcName)s:%(lineno)d] %(levelname)s: %(message)s",
)
LOG_DATE_FORMAT = CONFIG["general"].get("log_date_format", "%I:%M:%S")
WVK_LOG_FILE_PATH = pathlib.Path(os.getcwd(), "logs", f"GWVK_{time.strftime('%Y-%m-%d')}.log")
URL_BLACKLIST = CONFIG.get("url_blacklist", [])
EXTERNAL_API_DEVICES = CONFIG.get("external_build_info", [])
# List of device keys that should use the blacklist, these are considered to be GetWVKeys System keys.
SYSTEM_DEVICES = CONFIG["general"].get("system_devices", [])
