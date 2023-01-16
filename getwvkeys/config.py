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

import toml

IS_DEVELOPMENT = bool(os.environ.get("DEVELOPMENT", False))
IS_STAGING = bool(os.environ.get("STAGING", False))
config_filename = "config.dev.toml" if IS_DEVELOPMENT else "config.staging.toml" if IS_STAGING else "config.toml"
config = toml.load(config_filename)

general = config["general"]
api = config["api"]
database = config["database"]
rabbitmq = config["rabbitmq"]
oauth2 = config["oauth2"]
logging_config = config["logging"]

# generate a new secret key if one doesn't exist
if general["secret"] == "":
    print("Generating new secret key...")
    general["secret"] = os.urandom(16).hex()
    # save the new config
    toml.dump(config, open(config_filename, "w"))

# General Configuration Section
SECRET_KEY: str = general["secret"]
MAX_SESSIONS: int = general["max_sessions"]
GUILD_ID: str = general["guild_id"]
LOGIN_DISABLED: bool = general["login_disabled"]
REGISTRATION_DISABLED: bool = general["registration_disabled"]
VERIFIED_ROLE: str = general["verified_role"]
DEFAULT_CDMS: list[str] = general["default_cdms"]
SYSTEM_CDMS: list[str] = general["system_cdms"]
BLACKLIST = general.get("blacklist", [])
EXTERNAL_APIS = general.get("external_apis", [])

# API Configuration Section
API_HOST: str = api["host"]
API_PORT: int = api["port"]
API_URL: str = api["url"]

# Database Configuration Section
SQLALCHEMY_DATABASE_URI: str = database["uri"]

# RabbitMQ Configuration Section
RABBITMQ_URI: str = rabbitmq["uri"]

# OAuth2 Configuration Section
OAUTH2_CLIENT_ID: str = oauth2["client_id"]
OAUTH2_CLIENT_SECRET: str = oauth2["client_secret"]
OAUTH2_REDIRECT_URL: str = oauth2["redirect_url"]

# Logging Configuration Section
CONSOLE_LOG_LEVEL: str = logging_config["console_level"]
FILE_LOG_LEVEL: str = logging_config["file_level"]
LOG_FORMAT: str = logging_config["format"]
LOG_DATE_FORMAT: str = logging_config["date_format"]
LOG_FILE_PATH: pathlib.Path = pathlib.Path(os.getcwd(), logging_config["filename_format"].replace("%time%", time.strftime("%Y-%m-%d")))
