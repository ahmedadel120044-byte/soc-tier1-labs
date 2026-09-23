USE soc_project;

CREATE TABLE audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50),
    user_role VARCHAR(20),
    ip_address VARCHAR(45),
    action VARCHAR(50),
    executed_query TEXT,
    rows_returned INT,
    execution_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO audit_logs (username, user_role, ip_address, action, executed_query, rows_returned, execution_time)
VALUES
-- 1) SQL Injection
('unknown', 'user', '41.32.10.5', 'SELECT',
 "SELECT * FROM users WHERE username='' OR 1=1 -- '", 6, NOW()),

-- 2) Privilege Escalation
('hacker_test', 'user', '41.32.10.5', 'UPDATE',
 "UPDATE users SET role='admin' WHERE username='hacker_test'", 1, NOW()),

-- 3) Data Exfiltration
('sara_m', 'user', '105.44.9.2', 'SELECT',
 "SELECT username, password_hash, encrypted_phone FROM users", 5000, NOW()),

-- 4) Insider Threat (وقت غريب، 3 الفجر)
('admin_backup', 'admin', '156.203.1.1', 'SELECT',
 "SELECT * FROM users", 6, '2026-09-22 03:15:00'),

-- 5) Impact & Integrity (DELETE من غير WHERE)
('mostafa_k', 'user', '41.32.10.5', 'DELETE',
 "DELETE FROM users", 6, NOW()),

-- 6) Defense Evasion (استهداف الـaudit_logs نفسه)
('hacker_test', 'user', '41.32.10.5', 'DELETE',
 "DELETE FROM audit_logs", 6, NOW());

-- 7) Credential Access: Brute Force (5 محاولات فاشلة على نفس اليوزر من نفس الـIP)
INSERT INTO audit_logs (username, user_role, ip_address, action, executed_query, rows_returned, execution_time)
VALUES
('sara_m', 'user', '88.12.44.9', 'LOGIN_FAILED', NULL, 0, NOW()),
('sara_m', 'user', '88.12.44.9', 'LOGIN_FAILED', NULL, 0, NOW()),
('sara_m', 'user', '88.12.44.9', 'LOGIN_FAILED', NULL, 0, NOW()),
('sara_m', 'user', '88.12.44.9', 'LOGIN_FAILED', NULL, 0, NOW()),
('sara_m', 'user', '88.12.44.9', 'LOGIN_FAILED', NULL, 0, NOW());

-- 8) Credential Access: Credential Stuffing (نفس الـIP بيجرب 5 يوزرات مختلفة)
INSERT INTO audit_logs (username, user_role, ip_address, action, executed_query, rows_returned, execution_time)
VALUES
('ahmed_adel', NULL, '77.20.5.14', 'LOGIN_FAILED', NULL, 0, NOW()),
('nour_h', NULL, '77.20.5.14', 'LOGIN_FAILED', NULL, 0, NOW()),
('mostafa_k', NULL, '77.20.5.14', 'LOGIN_FAILED', NULL, 0, NOW()),
('admin_backup', NULL, '77.20.5.14', 'LOGIN_FAILED', NULL, 0, NOW()),
('unknown_user', NULL, '77.20.5.14', 'LOGIN_FAILED', NULL, 0, NOW());