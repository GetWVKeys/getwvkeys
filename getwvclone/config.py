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
SQLALCHEMY_DATABASE_URI = os.environ["SQLALCHEMY_DATABASE_URI"]
REDIS_URI = os.environ["REDIS_URI"]

API_HOST = "0.0.0.0"
API_PORT = int(os.environ.get("API_PORT", 8080))
API_URL = os.environ.get("API_URL", "https://getwvkeys.cc")

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
APPENDERS = ["seopsta0197f78c7034"]
GUILD_ID = "948675767754174465"
VERIFIED_ROLE_ID = "970332150891155607"
ELITE_ROLE_ID = "956263275887218808"
LOGIN_DISABLED = False
CONSOLE_LOG_LEVEL = logging.DEBUG
FILE_LOG_LEVEL = logging.DEBUG
LOG_FORMAT = "[%(asctime)s] [%(name)s] [%(funcName)s:%(lineno)d] %(levelname)s: %(message)s"
LOG_DATE_FORMAT = "%I:%M:%S"
WVK_LOG_FILE_PATH = pathlib.Path(os.getcwd(), "logs", f"GWVK_{time.strftime('%Y-%m-%d')}.log")
WZ_LOG_FILE_PATH = pathlib.Path(os.getcwd(), "logs", f"ACCESS_{time.strftime('%Y-%m-%d')}.log")
DEFAULT_BLACKLISTED_URLS = [
    {
        "url": "https://disney.playback.edge.bamgrid.com/widevine/v1/obtain-license",
        "partial": False,
    },
    {
        "url": ".*amazon.*",
        "partial": True,
    },
    {
        "url": ".*netflix.*",
        "partial": True,
    },
]
# List of CDMs that should use the blacklist, these are considered to be GetWVKeys CDMs.
SYSTEM_CDMS = [
    "xiaomi/whyred/whyred:9/PKQ1.180904.001/V10.3.1.0.PEIMIXM:user/release-keys",
    "Xiaomi/nitrogen/nitrogen:10/QKQ1.190910.002/V12.0.1.0.QEDMIXM:user/release-keys",
    "Xiaomi/nitrogen/nitrogen:9/PKQ1.181007.001/V11.0.2.2.PEDCNXM:user/release-keys",
    "Xiaomi/nitrogen/nitrogen:9/PKQ1.181007.001/V11.0.2.3.PEDCNXM:user/release-keys",
    "Xiaomi/nitrogen/nitrogen:9/PKQ1.181007.001/V11.0.2.4.PEDCNXM:user/release-keys",
    "Xiaomi/nitrogen/nitrogen:9/PKQ1.181007.001/V11.0.2.5.PEDCNXM:user/release-keys",
    "AZ1122/aosp_kenzo/kenzo:7.1.2/NZH541/doveki08121232:userdebug/test-keys",
    "AZ1122/aosp_kenzo/kenzo:7.1.2/NZH542/doveki08121232:userdebug/test-keys",
    "AZ1122/aosp_kenzo/kenzo:7.1.2/NZH543/doveki08121232:userdebug/test-keys",
    "AZ1122/aosp_kenzo/kenzo:7.1.2/NZH544/doveki08121232:userdebug/test-keys",
    "AZ1122/aosp_kenzo/kenzo:7.1.2/NZH545/doveki08121232:userdebug/test-keys",
    "Android/sdk_phone_x86_64/generic_x86_64:10/QSR1.210820.001/7663313:userdebug/test-keys",
]
