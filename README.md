## GetWVKeys

Widevine Utility Website and Remote Widevine Device API.

# Setup

- Install Python Poetry: https://python-poetry.org/docs/master/#installation
- Install depdencies: `poetry install`
- Copy `config.toml.example` to `config.toml`.
- Edit `config.toml` with your desired configuration. You will also need to generate and set the secret.
- Run database migrations. see [Database Migrations](#database-migrations)
- See [Deploy](#deploy)

# Local Development

For local development testing, you will need to disable the HTTPS requirement on the OAuth Callback URLs
with the environment variable `OAUTHLIB_INSECURE_TRANSPORT=1` or you will get the error `InsecureTransportError`.

- For Unix: `export OAUTHLIB_INSECURE_TRANSPORT=1`
- Windows (CMD): `set OAUTHLIB_INSECURE_TRANSPORT=1`
- Windows (Powershell): `$env:OAUTHLIB_INSECURE_TRANSPORT=1`

You should also enable development mode with the `DEVELOPMENT` environment variable.

- For Unix: `export DEVELOPMENT=1`
- Windows (CMD): `set DEVELOPMENT=1`
- Windows (Powershell): `$env:DEVELOPMENT=1`

For local development, you can use the built-in flask server with `poetry run serve`.

# Database Migrations

`poetry run setup`

# Environment Variables

- `OAUTHLIB_INSECURE_TRANSPORT`: Disable SSL for OAuth2 (This should only be used in development)
- `DEVELOPMENT`: Development mode, increased logging and loads config from `config.dev.toml`
- `STAGING`: Staging mode, loads config from `config.staging.toml`

# Deploy

Gunicorn is the recommended to run the server in production.

Example command to run on port 8081 listening on all interfaces:

- `poetry run gunicorn -w 1 -b 0.0.0.0:8081 getwvkeys.main:app`

_never use more than 1 worker, getwvkeys does not currently support that and you will encounter issues with sessions._

# Other Info

- Redis is used as a pub-sub system for communication with the Discord Bot. If you don't plan to use the bot, you don't need to setup redis and can comment it out in the `.env` file: `#REDIS_URI=redis://localhost:6379/0`
- GetWVKeys uses dynamic injection for scripts, this means that when a user downloads a script and is logged in, the server injects certain values by replacing strings such as their API key. Available placeholders are:
  - `__getwvkeys_api_key__`: Authenticated users api key
  - `__getwvkeys_api_url__`: The instances API URL, this is used for staging and production mainly but can also be used for self hosted instances
