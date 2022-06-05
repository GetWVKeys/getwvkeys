import logging
import os
import pathlib
import time

DEBUG = True  # Flask debugging, is auto loaded by flask
PROXY = {}
DEFAULT_CDMS = [
    "xiaomi/whyred/whyred:9/PKQ1.180904.001/V10.3.1.0.PEIMIXM:user/release-keys",
    "Xiaomi/nitrogen/nitrogen:10/QKQ1.190910.002/V12.0.1.0.QEDMIXM:user/release-keys",
    "AZ1122/aosp_kenzo/kenzo:7.1.2/NZH541/doveki08121232:userdebug/test-keys",
    "AZ1122/aosp_kenzo/kenzo:7.1.2/NZH542/doveki08121232:userdebug/test-keys",
    "AZ1122/aosp_kenzo/kenzo:7.1.2/NZH543/doveki08121232:userdebug/test-keys",
    "AZ1122/aosp_kenzo/kenzo:7.1.2/NZH544/doveki08121232:userdebug/test-keys",
    "AZ1122/aosp_kenzo/kenzo:7.1.2/NZH545/doveki08121232:userdebug/test-keys"
]
APPENDERS = ["staff_getwvkeys", "seopsta0197123"]
GUILD_ID = "948675767754174465"
VERIFIED_ROLE_ID = "970332150891155607"
ELITE_ROLE_ID = "956263275887218808"
LOGIN_DISABLED = False
IS_DEVELOPMENT = os.environ.get("DEVELOPMENT", False)
OAUTH2_REDIRECT_URL = "http://localhost:8080/login/callback" if IS_DEVELOPMENT else "http://getwvkeys.cc/login/callback"
LOG_LEVEL = logging.DEBUG if IS_DEVELOPMENT else logging.INFO
LOG_FORMAT = '[%(asctime)s] [%(name)s] [%(funcName)s:%(lineno)d] %(levelname)s: %(message)s'
LOG_DATE_FORMAT = '%I:%M:%S'
WVK_LOG_FILE_PATH = pathlib.Path(
    os.getcwd(), "logs", f"GWVK_{time.strftime('%Y-%m-%d')}.log")
WZ_LOG_FILE_PATH = pathlib.Path(
    os.getcwd(), "logs", f"ACCESS_{time.strftime('%Y-%m-%d')}.log")
API_HOST = "0.0.0.0"
API_PORT = 8080
