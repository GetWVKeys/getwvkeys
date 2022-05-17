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
