CREATE TABLE "tmp_users" (
    "id" INTEGER NOT NULL,
    "username" TEXT NOT NULL,
    "discriminator" TEXT NOT NULL,
    "avatar" TEXT,
    "public_flags" INTEGER NOT NULL,
    "api_key" TEXT NOT NULL,
    "status" INTEGER DEFAULT 0 NOT NULL,
    "is_admin" INTEGER DEFAULT 0 NOT NULL,
    PRIMARY KEY("id")
);
