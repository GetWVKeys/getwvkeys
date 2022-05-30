CREATE TABLE IF NOT EXISTS "users" (
    "id" INTEGER NOT NULL,
    "username" TEXT NOT NULL,
    "discriminator" INTEGER NOT NULL,
    "avatar" TEXT NOT NULL,
    "public_flags" INTEGER NOT NULL,
    "api_key" TEXT NOT NULL,
    PRIMARY KEY("id")
);
