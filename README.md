## GET WV KEYS

e

# Setup

- Install requirements: `pip install -r requirements.txt`
- Run database migrations
- Setup `instance\config.py` by either copying the example or using an existing one.

# Local Development

## Run database migrations

- `python migrate.py up database.db`
- `python migrate.py up cdms.db`

## Create database migration

- `python migrate.py create <database file.db> <migration name> <direction - up or down>`

  This will create a new migration file with a filename in the form of: `<unix timestamp>.<migration name>.<direction>.<database name>.sql`

# oauthlib.oauth2.rfc6749.errors.InsecureTransportError

For local development testing, you will need to disable the https requirement with an evironment variable:

For Unix: `export OAUTHLIB_INSECURE_TRANSPORT=1`<br>
For Windows (CMD): `set OAUTHLIB_INSECURE_TRANSPORT=1`
For Windows (Powershell): `$env:OAUTHLIB_INSECURE_TRANSPORT=1`
