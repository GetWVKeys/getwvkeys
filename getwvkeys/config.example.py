"""
 This file is part of the GetWVKeys project (https://github.com/GetWVKeys/getwvkeys)
 Copyright (C) 2022 Notaghost, Puyodead1 and GetWVKeys contributors 
 
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

import logging
import os
import pathlib
import time

from dotenv import load_dotenv

IS_DEVELOPMENT = bool(os.environ.get("DEVELOPMENT", False))
IS_STAGING = bool(os.environ.get("STAGING", False))
load_dotenv(".env.dev" if IS_DEVELOPMENT else ".env.staging" if IS_STAGING else ".env")

SECRET_KEY = os.environ["SECRET_KEY"]  # generate secret offline with os.urandom(16).hex()
OAUTH2_CLIENT_ID = os.environ["OAUTH2_CLIENT_ID"]  # Discord OAuth Client ID
OAUTH2_CLIENT_SECRET = os.environ["OAUTH2_CLIENT_SECRET"]  # Discord OAuth Client Secret
OAUTH2_REDIRECT_URL = os.environ["OAUTH2_REDIRECT_URL"]  # Discord OAuth Callback URL
SQLALCHEMY_DATABASE_URI = os.environ["SQLALCHEMY_DATABASE_URI"]  # Database connection URI
RABBIT_URI = os.environ.get("RABBIT_URI", None)  # RabbitMQ connection URI

API_HOST = os.environ.get("API_HOST", "0.0.0.0")
API_PORT = int(os.environ.get("API_PORT", 8080))
API_URL = os.environ.get("API_URL", "https://getwvkeys.cc")

MAX_SESSIONS = int(os.environ.get("MAX_SESSIONS", 60))
PROXY = {}
DEFAULT_CDMS = os.environ.get("DEFAULT_CDMS", "").split(",")  # list of build infos to use in key rotation
GUILD_ID = os.environ.get("GUILD_ID")  # Discord Guild ID
VERIFIED_ROLE = os.environ.get("VERIFIED_ROLE")  # Discord Verified role ID
LOGIN_DISABLED = bool(os.environ.get("LOGIN_DISABLED", False))
CONSOLE_LOG_LEVEL = logging.DEBUG
FILE_LOG_LEVEL = logging.DEBUG
LOG_FORMAT = "[%(asctime)s] [%(name)s] [%(funcName)s:%(lineno)d] %(levelname)s: %(message)s"
LOG_DATE_FORMAT = "%I:%M:%S"
WVK_LOG_FILE_PATH = pathlib.Path(os.getcwd(), "logs", f"GWVK_{time.strftime('%Y-%m-%d')}.log")
DEFAULT_BLACKLISTED_URLS = [
    # using regex to match a url
    {
        "url": ".*my\.awesome\.site.com.*",
        "partial": True,
    },
    # matching an exact url
    {
        "url": "https://example.com/some_awesome_page_to_block",
        "partial": False,
    },
]
EXTERNAL_API_BUILD_INFOS = [{"buildinfo": "my_awesome_custom_buildinfo", "url": "http://myamazingcdmapi.com", "token": "myS3cR$t"}]

# List of CDMs that should use the blacklist, these are considered to be GetWVKeys System CDMs.
SYSTEM_CDMS = os.environ.get("SYSTEM_CDMS", "").split(",")
