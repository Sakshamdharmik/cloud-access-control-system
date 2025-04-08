USE cap_db;

CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL
);

CREATE TABLE objects (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(50) UNIQUE NOT NULL
);

CREATE TABLE capabilities (
    id INT PRIMARY KEY AUTO_INCREMENT,
    subject_id INT,
    object_id INT,
    rights VARCHAR(50),
    expiry DATETIME,
    nonce VARCHAR(100),
    token TEXT,
    FOREIGN KEY(subject_id) REFERENCES users(id),
    FOREIGN KEY(object_id) REFERENCES objects(id)
);

CREATE TABLE revocation_list (
    id INT PRIMARY KEY AUTO_INCREMENT,
    token_hash VARCHAR(255),
    revoked_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
