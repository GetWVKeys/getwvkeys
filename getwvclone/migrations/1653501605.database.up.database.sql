-- Creates the database table for database.db

CREATE TABLE IF NOT EXISTS "DATABASE" (
    "KID" TEXT,
    "pssh" TEXT,
    "headers" TEXT,
    "proxy" TEXT,
    "time" TEXT,
    "license" TEXT,
    "keys" TEXT,
    PRIMARY KEY("KID")
);
