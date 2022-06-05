-- Adds a column to users table that describes a users status

ALTER TABLE
    users
ADD
    COLUMN status INTEGER DEFAULT 0 NOT NULL;
