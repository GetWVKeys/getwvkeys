import os

IS_DEVELOPMENT = os.environ.get("DEVELOPMENT")

# generate secret with https://generate-secret.vercel.app/32
SECRET_KEY = ""
OAUTH2_CLIENT_ID = ""  # Discord OAuth Client ID
# Discord OAuth Client Secret
OAUTH2_CLIENT_SECRET = ""
# use DEV token if we are in development
BOT_TOKEN = "DEV TOKEN" if IS_DEVELOPMENT else "PRODUCTION TOKEN"
