## GetWVKeys

Widevine Utility Website and Remote Widevine Device API.

# Setup

-   Install Python Poetry: https://python-poetry.org/docs/master/#installation
-   Install Dependencies:
    -   For MySQL: `poetry install -E mysql`
    -   For MariaDB: `poetry install -E mariadb`
-   Copy `.env.example` to `.env`.(#environment-variables)
-   Copy `getwvkeys/config.toml.example` to `getwvkeys/config.toml`
-   Edit `config.toml`
    -   For a MySQL Database, use the prefix `mysql+mariadbconnector`
    -   For a MariaDB Database, use the prefix `mariadb+mariadbconnector`
-   Run database migrations. see [Database Migrations](#database-migrations)
-   See [Deploy](#deploy)

# Local Development

For local development testing, you will need to disable the HTTPS requirement on the OAuth Callback URLs
with the environment variable `OAUTHLIB_INSECURE_TRANSPORT=1` or you will get the error `InsecureTransportError`.

-   For Unix: `export OAUTHLIB_INSECURE_TRANSPORT=1`
-   Windows (CMD): `set OAUTHLIB_INSECURE_TRANSPORT=1`
-   Windows (Powershell): `$env:OAUTHLIB_INSECURE_TRANSPORT=1`

You should also enable development mode with the `DEVELOPMENT` environment variable.

-   For Unix: `export DEVELOPMENT=1`
-   Windows (CMD): `set DEVELOPMENT=1`
-   Windows (Powershell): `$env:DEVELOPMENT=1`

For local development, you can use the built-in flask server with `poetry run serve`.

# Database Migrations

`poetry run migrate`

# Environment Variables

-   `OAUTHLIB_INSECURE_TRANSPORT`: disable ssl for oauth
-   `DEVELOPMENT`: Development mode, increased logging and reads environment variables from `.env.dev`
-   `STAGING`: Staging mode, reads environment variables from `.env.staging`

# Deploy

Gunicorn is the recommended to run the server in production.

Example command to run on port 8081 listening on all interfaces:

-   `poetry run gunicorn -w 1 -b 0.0.0.0:8081 getwvkeys.main:app`

_never use more than 1 worker, getwvkeys does not currently support that and you will encounter issues with sessions._

# Other Info

-   GetWVKeys uses dynamic injection for scripts, this means that when a user downloads a script and is logged in, the server injects certain values by replacing strings such as their API key. Available placeholders are:
    -   `__getwvkeys_api_key__`: Authenticated users api key
    -   `__getwvkeys_api_url__`: The instances API URL, this is used for staging and production mainly but can also be used for self hosted instances


# Docker
- for development:
    - create `config.dev.toml`
    - `docker compose -f docker-compose-dev.yml up`
- for non-development:
    - create a regular `config.toml`
    - `docker compose -f docker-compose.yml up`

migrations are run automatically on boot