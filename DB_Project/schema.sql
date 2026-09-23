CREATE DATABASE IF NOT EXISTS soc_project;
USE soc_project;

-- Users Table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    failed_login_attempts INT DEFAULT 0,
    status VARCHAR(20) DEFAULT 'active',
    locked_until DATETIME DEFAULT NULL,
    role VARCHAR(20) DEFAULT 'user'
);

-- Audit Logs Table
CREATE TABLE IF NOT EXISTS audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50),
    user_role VARCHAR(20),
    ip_address VARCHAR(45),
    action VARCHAR(50),
    executed_query TEXT,
    rows_returned INT DEFAULT 0,
    execution_time DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- IP Deny List Table
CREATE TABLE IF NOT EXISTS ip_deny_list (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL UNIQUE,
    reason VARCHAR(255),
    blocked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    blocked_until DATETIME
);