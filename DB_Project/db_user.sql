CREATE DATABASE IF NOT EXISTS soc_project;
USE soc_project;

CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    encrypted_phone VARCHAR(255),
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    failed_login_attempts INT NOT NULL DEFAULT 0,
    locked_until DATETIME,
    last_login DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users (username, password_hash, encrypted_phone, role, failed_login_attempts, last_login)
VALUES
('ahmed_adel', 'fake_hash_1', 'fake_enc_1', 'admin', 0, NOW()),
('sara_m', 'fake_hash_2', 'fake_enc_2', 'user', 1, NOW()),
('mostafa_k', 'fake_hash_3', 'fake_enc_3', 'user', 0, NOW()),
('hacker_test', 'fake_hash_4', 'fake_enc_4', 'user', 7, NOW()),
('nour_h', 'fake_hash_5', 'fake_enc_5', 'user', 0, NOW()),
('admin_backup', 'fake_hash_6', 'fake_enc_6', 'admin', 2, NOW());