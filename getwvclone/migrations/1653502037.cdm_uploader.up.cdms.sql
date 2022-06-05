-- Adds uploaded_by column to cdms table, used to track user that uploaded a cdm

ALTER TABLE
    CDMS
ADD
    COLUMN uploaded_by TEXT DEFAULT "DEFAULT" NOT NULL;
