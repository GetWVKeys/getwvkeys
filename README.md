## GetWvClone

Widevine Utility Website and Remote Widevine Device API.

# Setup

- Install Python Poetry: https://python-poetry.org/docs/master/#installation
- `poetry install`
- Add Secret and OAuth Keys to `config.py`
- Run database migrations

You can now run the server with `poetry run serve`.

# Local Development

For local development testing, you will need to disable the HTTPS requirement on the OAuth Callback URLs
with the environment variable `OAUTHLIB_INSECURE_TRANSPORT=1` or you will get the error `InsecureTransportError`.

For Unix: `export OAUTHLIB_INSECURE_TRANSPORT=1`  
For Windows (CMD): `set OAUTHLIB_INSECURE_TRANSPORT=1`  
For Windows (Powershell): `$env:OAUTHLIB_INSECURE_TRANSPORT=1`

# Database Migrations

## Running migrations

- `python migrate.py up database.db`
- `python migrate.py up cdms.db`

## Creating migrations

- `python migrate.py create <database file.db> <migration name> <direction - up or down>`

This will create a new migration file with a filename in the form of:
`<unix timestamp>.<migration name>.<direction>.<database name>.sql`

# Deploy
Example deploy command for staging:
`poetry run gunicorn -w 4 -b 0.0.0.0:8081 getwvclone.main:app`