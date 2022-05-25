## GET WV KEYS

- create database.db and cdms.db

```sh
python create_databases.py
```

or manually:

```sql
CREATE TABLE "DATABASE" ( "KID" TEXT, "pssh" TEXT, "headers" TEXT, "proxy" TEXT, "time" TEXT, "license" TEXT, "keys" TEXT, PRIMARY KEY("KID") )
```

```sql
CREATE TABLE "CDMS" ( "session_id_type" TEXT DEFAULT 'android', "security_level" INTEGER DEFAULT 3, "client_id_blob_filename" TEXT, "device_private_key" TEXT, "CODE" TEXT )
```

# oauthlib.oauth2.rfc6749.errors.InsecureTransportError

For local development testing, you will need to disable the https requirement with an evironment variable:

For Unix: `export OAUTHLIB_INSECURE_TRANSPORT=1`<br>
For Windows: `set OAUTHLIB_INSECURE_TRANSPORT=1`
