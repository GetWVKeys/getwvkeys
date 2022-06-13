import logging
import os
import pathlib
import time

from dotenv import load_dotenv

load_dotenv()
SECRET_KEY = os.environ["SECRET_KEY"]  # generate secret offline with os.urandom(16).hex()
OAUTH2_CLIENT_ID = os.environ["OAUTH2_CLIENT_ID"]  # Discord OAuth Client ID
OAUTH2_CLIENT_SECRET = os.environ["OAUTH2_CLIENT_SECRET"]  # Discord OAuth Client Secret
OAUTH2_REDIRECT_URL = os.environ["OAUTH2_REDIRECT_URL"]  # Discord OAuth Callback URL
OAUTH2_REDIRECT_URL_DEV = os.environ["OAUTH2_REDIRECT_URL_DEV"]  # Discord OAuth Callback URL for local development

IS_DEVELOPMENT = bool(os.environ.get("DEVELOPMENT", False))
API_HOST = "0.0.0.0"
API_PORT = int(os.environ.get("API_PORT", 8080))

PROXY = {}
DEFAULT_CDMS = [
    "xiaomi/whyred/whyred:9/PKQ1.180904.001/V10.3.1.0.PEIMIXM:user/release-keys",
    "Xiaomi/nitrogen/nitrogen:10/QKQ1.190910.002/V12.0.1.0.QEDMIXM:user/release-keys",
    "AZ1122/aosp_kenzo/kenzo:7.1.2/NZH541/doveki08121232:userdebug/test-keys",
    "AZ1122/aosp_kenzo/kenzo:7.1.2/NZH542/doveki08121232:userdebug/test-keys",
    "AZ1122/aosp_kenzo/kenzo:7.1.2/NZH543/doveki08121232:userdebug/test-keys",
    "AZ1122/aosp_kenzo/kenzo:7.1.2/NZH544/doveki08121232:userdebug/test-keys",
    "AZ1122/aosp_kenzo/kenzo:7.1.2/NZH545/doveki08121232:userdebug/test-keys",
]
APPENDERS = ["staff_getwvkeys", "seopsta0197123"]
GUILD_ID = "948675767754174465"
VERIFIED_ROLE_ID = "970332150891155607"
ELITE_ROLE_ID = "956263275887218808"
LOGIN_DISABLED = False
CONSOLE_LOG_LEVEL = logging.DEBUG if IS_DEVELOPMENT else logging.ERROR
FILE_LOG_LEVEL = logging.DEBUG
LOG_FORMAT = "[%(asctime)s] [%(name)s] [%(funcName)s:%(lineno)d] %(levelname)s: %(message)s"
LOG_DATE_FORMAT = "%I:%M:%S"
WVK_LOG_FILE_PATH = pathlib.Path(os.getcwd(), "logs", f"GWVK_{time.strftime('%Y-%m-%d')}.log")
WZ_LOG_FILE_PATH = pathlib.Path(os.getcwd(), "logs", f"ACCESS_{time.strftime('%Y-%m-%d')}.log")
SQLALCHEMY_DATABASE_URI = os.environ["SQLALCHEMY_DATABASE_URI"]
