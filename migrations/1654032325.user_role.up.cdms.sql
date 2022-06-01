-- Adds a column to users table that describes if a user is an admin or not. 0 is false, 1 is true

ALTER TABLE
    users
ADD
    COLUMN is_admin INTEGER DEFAULT 0 NOT NULL;
