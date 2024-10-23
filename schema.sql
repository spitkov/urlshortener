-- Create User table
CREATE TABLE user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(80) NOT NULL UNIQUE,
    password_hash VARCHAR(200) NOT NULL
);

-- Create URL table
CREATE TABLE url (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_url VARCHAR(500) NOT NULL,
    short_url VARCHAR(10) NOT NULL UNIQUE,
    user_id INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES user (id)
);

-- Create index on short_url for faster lookups
CREATE INDEX idx_short_url ON url (short_url);

-- Create index on user_id for faster user-specific URL lookups
CREATE INDEX idx_user_id ON url (user_id);
