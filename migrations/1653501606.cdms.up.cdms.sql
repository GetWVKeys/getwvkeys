-- Creates the CDMS table for cdms.db

CREATE TABLE "CDMS" (
    "session_id_type" TEXT DEFAULT 'android',
    "security_level" INTEGER DEFAULT 3,
    "client_id_blob_filename" TEXT,
    "device_private_key" TEXT,
    "CODE" TEXT
);
