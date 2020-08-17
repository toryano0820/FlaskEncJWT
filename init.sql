CREATE TABLE IF NOT EXISTS member (
    id INTEGER PRIMARY KEY,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    date_registered DATETIME NOT NULL,
);

CREATE TABLE IF NOT EXISTS auth_code (
    user_id INTEGER,
    code INTEGER NOT NULL,
    token TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scope (
    user_id INTEGER,
    scope TEXT NOT NULL
);

