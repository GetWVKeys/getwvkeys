import sqlite3

connection_obj = sqlite3.connect("database.db")
cursor_obj = connection_obj.cursor()
cursor_obj.execute('CREATE TABLE IF NOT EXISTS "DATABASE" ( "KID" TEXT, "pssh" TEXT, "headers" TEXT, "proxy" TEXT, "time" TEXT, "license" TEXT, "keys" TEXT, PRIMARY KEY("KID") )')
print("Created database.db")
connection_obj.close()

connection_obj = sqlite3.connect("cdms.db")
cursor_obj = connection_obj.cursor()
cursor_obj.execute('CREATE TABLE IF NOT EXISTS "CDMS" ( "session_id_type" TEXT DEFAULT "android", "security_level" INTEGER DEFAULT 3, "client_id_blob_filename" TEXT, "device_private_key" TEXT, "CODE" TEXT )')
print("Created cdms.db")
connection_obj.close()