CREATE TABLE "tmp_users" (
    "id" INTEGER NOT NULL,
    "username" TEXT NOT NULL,
    "discriminator" INTEGER NOT NULL,
    "avatar" TEXT,
    "public_flags" INTEGER NOT NULL,
    "api_key" TEXT NOT NULL,
    PRIMARY KEY("id")
);
