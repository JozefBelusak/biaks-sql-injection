CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('administrátor', 'študent')),
    email TEXT NOT NULL DEFAULT '',
    study_group TEXT NOT NULL DEFAULT ''
);
