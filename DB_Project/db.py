import mysql.connector
import re
import os

# بيانات الاتصال بقاعدة البيانات (مستخرجة بأمان من الـ Environment Variables)
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "user": os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", ""),
    "database": os.getenv("DB_NAME", "soc_project")
}

def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)

def setup_deny_table_if_not_exists():
    """تأكيد وجود جدول الحظر لمنع أخطاء التشغيل"""
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        create_table_query = """
        CREATE TABLE IF NOT EXISTS ip_deny_list (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip_address VARCHAR(45) NOT NULL UNIQUE,
            reason VARCHAR(255),
            blocked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            blocked_until DATETIME
        );
        """
        cursor.execute(create_table_query)
        conn.commit()
    except mysql.connector.Error as err:
        print(f"[ERROR] Failed to verify/create ip_deny_list table: {err}")
    finally:
        if cursor: cursor.close()
        if conn and conn.is_connected(): conn.close()

# ==========================================
# 1. DAY 3: BRUTE FORCE DETECTION
# ==========================================
def run_brute_force_detection():
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        query = """
        SELECT username, failed_login_attempts, status 
        FROM users 
        WHERE failed_login_attempts >= 5;
        """

        cursor.execute(query)
        results = cursor.fetchall()

        print("\n=== [SOC ENGINE] Running Brute Force Detection (Users Table) ===")
        if not results:
            print("[INFO] No suspicious brute force activities detected in Users table.")
        else:
            for row in results:
                username = row['username']
                attempts = row['failed_login_attempts']
                print(f"\033[91m[CRITICAL ALERT] Brute Force Threshold Exceeded! User: '{username}' | Failed Attempts: {attempts}\033[0m")

    except mysql.connector.Error as err:
        print(f"[ERROR] Brute Force Detection Failed: {err}")
    finally:
        if cursor: cursor.close()
        if conn and conn.is_connected(): conn.close()

# ==========================================
# 2. DAY 4: CREDENTIAL STUFFING DETECTION
# ==========================================
def run_credential_stuffing_detection():
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        query = """
        SELECT ip_address, COUNT(DISTINCT username) AS tried_users_count
        FROM audit_logs
        WHERE action = 'LOGIN_FAILED'
        GROUP BY ip_address
        HAVING COUNT(DISTINCT username) >= 5;
        """

        cursor.execute(query)
        results = cursor.fetchall()

        print("\n=== [SOC ENGINE] Running Credential Stuffing Detection (Audit Logs) ===")
        if not results:
            print("[INFO] No credential stuffing activities detected.")
        else:
            for row in results:
                ip_address = row['ip_address']
                tried_users_count = row['tried_users_count']
                print(f"\033[91m[CRITICAL ALERT] Credential Stuffing Attack Detected! Source IP: '{ip_address}' | Targeted Unique Users: {tried_users_count}\033[0m")

    except mysql.connector.Error as err:
        print(f"[ERROR] Credential Stuffing Detection Failed: {err}")
    finally:
        if cursor: cursor.close()
        if conn and conn.is_connected(): conn.close()

# ==========================================
# 3. DAY 5: SQL INJECTION DETECTION
# ==========================================
def run_sqli_detection():
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        query = """
        SELECT id, username, ip_address, executed_query, execution_time 
        FROM audit_logs 
        WHERE executed_query IS NOT NULL 
        ORDER BY id DESC LIMIT 1000;
        """
        cursor.execute(query)
        logs = cursor.fetchall()

        sqli_patterns = [
            r"OR\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
            r"UNION\s+(ALL\s+)?SELECT",
            r"SLEEP\s*\(",
            r"BENCHMARK\s*\(",
            r"DROP\s+TABLE",
            r"--",
            r"#",
            r"/\*.*\*/"
        ]
        combined_regex = "|".join(sqli_patterns)

        print("\n=== [SOC ENGINE] Running SQL Injection Detection (Python Regex) ===")
        found_sqli = False

        for log in logs:
            executed_query = log['executed_query']
            match = re.search(combined_regex, executed_query, re.IGNORECASE)
            
            if match:
                found_sqli = True
                print(f"\033[91m[CRITICAL ALERT] SQL Injection Payload Detected!\033[0m")
                print(f" -> Log ID: {log['id']} | User: '{log['username']}' | IP: {log['ip_address']}")
                print(f" -> Matched Pattern: '{match.group(0)}'")
                print(f" -> Full Query: \"{executed_query}\"")
                print("-" * 65)

        if not found_sqli:
            print("[INFO] No SQL Injection patterns detected.")

    except mysql.connector.Error as err:
        print(f"[ERROR] SQLi Detection Failed: {err}")
    finally:
        if cursor: cursor.close()
        if conn and conn.is_connected(): conn.close()

# ==========================================
# 4. DAY 6: PRIVILEGE ESCALATION DETECTION
# ==========================================
def run_privilege_escalation_detection():
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        query = """
        SELECT id, username, user_role, ip_address, executed_query, execution_time
        FROM audit_logs
        WHERE LOWER(user_role) = 'user' 
          AND (
               LOWER(executed_query) LIKE '%role%' 
            OR LOWER(executed_query) LIKE '%admin%' 
            OR LOWER(executed_query) LIKE '%grant%'
          );
        """

        cursor.execute(query)
        results = cursor.fetchall()

        print("\n=== [SOC ENGINE] Running Privilege Escalation Detection (Audit Logs) ===")
        if not results:
            print("[INFO] No privilege escalation attempts detected.")
        else:
            for log in results:
                print(f"\033[91m[CRITICAL ALERT] Privilege Escalation Attempt Detected!\033[0m")
                print(f" -> Log ID: {log['id']} | User: '{log['username']}' ({log['user_role']}) | IP: {log['ip_address']}")
                print(f" -> Query: \"{log['executed_query']}\"")
                print("-" * 65)

    except mysql.connector.Error as err:
        print(f"[ERROR] Privilege Escalation Detection Failed: {err}")
    finally:
        if cursor: cursor.close()
        if conn and conn.is_connected(): conn.close()

# ==========================================
# 5. DAY 7: DATA EXFILTRATION DETECTION
# ==========================================
def run_data_exfiltration_detection():
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        query = """
        SELECT id, username, user_role, ip_address, executed_query, rows_returned, execution_time
        FROM audit_logs
        WHERE rows_returned > 1000 
           OR LOWER(executed_query) LIKE '%password_hash%'
           OR LOWER(executed_query) LIKE '%encrypted_phone%';
        """

        cursor.execute(query)
        results = cursor.fetchall()

        print("\n=== [SOC ENGINE] Running Data Exfiltration Detection (Audit Logs) ===")
        if not results:
            print("[INFO] No data exfiltration activities detected.")
        else:
            for log in results:
                print(f"\033[91m[CRITICAL ALERT] Data Exfiltration / Sensitive Access Detected!\033[0m")
                print(f" -> Log ID: {log['id']} | User: '{log['username']}' | IP: {log['ip_address']}")
                print(f" -> Rows Returned: {log['rows_returned']}")
                print(f" -> Query: \"{log['executed_query']}\"")
                print("-" * 65)

    except mysql.connector.Error as err:
        print(f"[ERROR] Data Exfiltration Detection Failed: {err}")
    finally:
        if cursor: cursor.close()
        if conn and conn.is_connected(): conn.close()

# ==========================================
# 6. DAY 8: INSIDER THREAT DETECTION
# ==========================================
def run_insider_threat_detection():
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        query = """
        SELECT id, username, user_role, ip_address, executed_query, execution_time
        FROM audit_logs
        WHERE LOWER(user_role) = 'admin' 
          AND HOUR(execution_time) BETWEEN 1 AND 5;
        """

        cursor.execute(query)
        results = cursor.fetchall()

        print("\n=== [SOC ENGINE] Running Insider Threat Detection (Off-Hours Admin Activity) ===")
        if not results:
            print("[INFO] No suspicious off-hours admin activities detected.")
        else:
            for log in results:
                print(f"\033[91m[CRITICAL ALERT] Suspicious Off-Hours Admin Activity Detected!\033[0m")
                print(f" -> Log ID: {log['id']} | Admin User: '{log['username']}' | IP: {log['ip_address']}")
                print(f" -> Time: {log['execution_time']}")
                print(f" -> Query: \"{log['executed_query']}\"")
                print("-" * 65)

    except mysql.connector.Error as err:
        print(f"[ERROR] Insider Threat Detection Failed: {err}")
    finally:
        if cursor: cursor.close()
        if conn and conn.is_connected(): conn.close()

# ==========================================
# 7. DAY 9: IMPACT & INTEGRITY DETECTION
# ==========================================
def run_impact_integrity_detection():
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        query = """
        SELECT id, username, user_role, ip_address, executed_query, execution_time
        FROM audit_logs
        WHERE (UPPER(executed_query) LIKE '%DELETE%' OR UPPER(executed_query) LIKE '%UPDATE%')
          AND UPPER(executed_query) NOT LIKE '%WHERE%';
        """

        cursor.execute(query)
        results = cursor.fetchall()

        print("\n=== [SOC ENGINE] Running Impact & Integrity Detection (Unbounded Operations) ===")
        if not results:
            print("[INFO] No unbounded DELETE/UPDATE queries detected.")
        else:
            for log in results:
                print(f"\033[91m[CRITICAL ALERT] Unbounded Destructive Query Detected (Missing WHERE Clause)!\033[0m")
                print(f" -> Log ID: {log['id']} | User: '{log['username']}' ({log['user_role']}) | IP: {log['ip_address']}")
                print(f" -> Query: \"{log['executed_query']}\"")
                print("-" * 65)

    except mysql.connector.Error as err:
        print(f"[ERROR] Impact & Integrity Detection Failed: {err}")
    finally:
        if cursor: cursor.close()
        if conn and conn.is_connected(): conn.close()

# ==========================================
# 8. DAY 10: DEFENSE EVASION DETECTION
# ==========================================
def run_defense_evasion_detection():
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        query = """
        SELECT id, username, user_role, ip_address, executed_query, execution_time
        FROM audit_logs
        WHERE LOWER(executed_query) LIKE '%audit_logs%' 
          AND (
               UPPER(executed_query) LIKE '%DROP%' 
            OR UPPER(executed_query) LIKE '%TRUNCATE%' 
            OR UPPER(executed_query) LIKE '%DELETE%'
          );
        """

        cursor.execute(query)
        results = cursor.fetchall()

        print("\n=== [SOC ENGINE] Running Defense Evasion Detection (Anti-Forensics) ===")
        if not results:
            print("[INFO] No log tampering attempts detected.")
        else:
            for log in results:
                print(f"\033[91m[CRITICAL ALERT] Defense Evasion / Log Tampering Detected!\033[0m")
                print(f" -> Log ID: {log['id']} | User: '{log['username']}' ({log['user_role']}) | IP: {log['ip_address']}")
                print(f" -> Query: \"{log['executed_query']}\"")
                print("-" * 65)

    except mysql.connector.Error as err:
        print(f"[ERROR] Defense Evasion Detection Failed: {err}")
    finally:
        if cursor: cursor.close()
        if conn and conn.is_connected(): conn.close()

# ==========================================
# 9. DAY 11: ACTIVE MITIGATION & DENY RULES
# ==========================================
def run_account_lockout_and_deny():
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        print("\n=== [SOC ENGINE] Running Day 11: Active Mitigation & Deny Rules ===")

        # 1. إغلاق وحظر الحسابات المتجاوزة لعدد المحاولات الفاشلة
        lock_accounts_query = """
        UPDATE users 
        SET status = %s, locked_until = DATE_ADD(NOW(), INTERVAL 15 MINUTE) 
        WHERE failed_login_attempts >= %s 
          AND (status IS NULL OR status != 'locked');
        """
        cursor.execute(lock_accounts_query, ('locked', 5))
        locked_rows = cursor.rowcount
        conn.commit()

        if locked_rows > 0:
            print(f"\033[91m[ACTION TAKEN - DENY] Locked {locked_rows} user account(s) for 15 minutes due to Brute Force.\033[0m")
        else:
            print("[INFO] No new user accounts required lockout.")

        # 2. حظر الـ IPs المتورطة في Credential Stuffing
        find_bad_ips_query = """
        SELECT ip_address, COUNT(DISTINCT username) AS tried_users
        FROM audit_logs
        WHERE action = 'LOGIN_FAILED'
        GROUP BY ip_address
        HAVING COUNT(DISTINCT username) >= 5;
        """
        cursor.execute(find_bad_ips_query)
        bad_ips = cursor.fetchall()

        for record in bad_ips:
            ip = record['ip_address']
            deny_ip_query = """
            INSERT INTO ip_deny_list (ip_address, reason, blocked_until)
            VALUES (%s, %s, DATE_ADD(NOW(), INTERVAL 15 MINUTE))
            ON DUPLICATE KEY UPDATE blocked_until = DATE_ADD(NOW(), INTERVAL 15 MINUTE);
            """
            cursor.execute(deny_ip_query, (ip, 'Credential Stuffing Detected'))
            conn.commit()
            print(f"\033[91m[ACTION TAKEN - DENY] IP '{ip}' added to Active Deny List for 15 minutes.\033[0m")

    except mysql.connector.Error as err:
        print(f"[ERROR] Active Mitigation Failed: {err}")
    finally:
        if cursor: cursor.close()
        if conn and conn.is_connected(): conn.close()

# ==========================================
# 10. DAY 12: HARDENING (PRIVILEGES & TRIGGERS)
# ==========================================
def setup_day12_hardening():
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        print("\n=== [SOC ENGINE] Running Day 12: Hardening & Preventive Controls ===")

        # 1. التأكد من وجود كلمة سر مستخدم التطبيق من البيئة، وإلا يتم توقف التشغيل فوراً (Fail Fast)
        app_user_password = os.getenv("APP_USER_PASSWORD")
        if not app_user_password:
            raise ValueError("APP_USER_PASSWORD environment variable is not set. Cannot configure application user safely.")

        # إنشاء المستخدم وسحب صلاحية تعديل الـ role
        cursor.execute(f"CREATE USER IF NOT EXISTS 'app_user'@'localhost' IDENTIFIED BY '{app_user_password}';")
        cursor.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON soc_project.* TO 'app_user'@'localhost';")
        cursor.execute("REVOKE UPDATE (role) ON soc_project.users FROM 'app_user'@'localhost';")
        print("[SUCCESS] Applied Column-Level Privilege: Revoked UPDATE(role) on 'users' for 'app_user'.")

        # 2. تفعيل مفتاح الأمان SQL_SAFE_UPDATES لمنع حذف/تعديل البيانات بدون شرط WHERE
        cursor.execute("SET GLOBAL sql_safe_updates = 1;")
        print("[SUCCESS] Global SQL_SAFE_UPDATES enabled (Prevents unbounded UPDATE/DELETE queries).")

        # 3. إنشاء Trigger يمنع مسح أي بيانات من جدول users نهائياً
        cursor.execute("DROP TRIGGER IF EXISTS prevent_users_deletion;")
        trigger_sql = """
        CREATE TRIGGER prevent_users_deletion
        BEFORE DELETE ON users
        FOR EACH ROW
        BEGIN
            SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'SECURITY DENY: Direct deletion of user records is strictly forbidden!';
        END;
        """
        cursor.execute(trigger_sql)
        print("[SUCCESS] BEFORE DELETE Trigger created on 'users' table.")

        conn.commit()

    except mysql.connector.Error as err:
        print(f"[ERROR] Day 12 Hardening Failed: {err}")
    except ValueError as val_err:
        print(f"[SECURITY ERROR] {val_err}")
    finally:
        if cursor: cursor.close()
        if conn and conn.is_connected(): conn.close()

# ==========================================
# 11. DAY 13: IMMUTABLE LOGS & LOG SHIPPING
# ==========================================
def setup_day13_hardening():
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        print("\n=== [SOC ENGINE] Running Day 13: Append-Only Audit Logs & Architecture Documentation ===")

        # 1. تحويل جدول الـ audit_logs لـ Append-Only لمنع تعديل أو مسح اللوجات
        cursor.execute("REVOKE DELETE, UPDATE, DROP ON soc_project.audit_logs FROM 'app_user'@'localhost';")
        cursor.execute("FLUSH PRIVILEGES;")
        print("[SUCCESS] Audit Logs Hardened: Revoked DELETE, UPDATE, DROP on 'audit_logs' for 'app_user'.")

        # 2. طباعة التوثيق المعماري الخاص بالـ Remote Log Shipping لـ SIEM
        doc = """
        ----------------------------------------------------------------------
        [ARCHITECTURAL DOCUMENTATION] SIEM Remote Log Shipping Strategy
        ----------------------------------------------------------------------
        * Strategy: Streaming audit logs in real-time to a remote SIEM (Splunk/QRadar).
        * Pipeline: [MySQL Database] -> [Syslog/Logstash Agent] -> [Encrypted Pipeline] -> [Remote SIEM]
        * Benefit: Even if the DB server is compromised or erased locally, 
                   forensic artifacts remain intact and untampered in the central SIEM.
        ----------------------------------------------------------------------
        """
        print(doc)

        conn.commit()

    except mysql.connector.Error as err:
        print(f"[ERROR] Day 13 Hardening Failed: {err}")
    finally:
        if cursor: cursor.close()
        if conn and conn.is_connected(): conn.close()

# ==========================================
# MAIN EXECUTION
# ==========================================
if __name__ == "__main__":
    print("==================================================")
    print("       STARTING SOC SECURITY DETECTION ENGINE     ")
    print("==================================================")
    
    # 1. تجهيز جدول الحظر
    setup_deny_table_if_not_exists()
    
    # 2. تشغيل وحدات الاكتشاف (Days 3 to 10)
    run_brute_force_detection()
    run_credential_stuffing_detection()
    run_sqli_detection()
    run_privilege_escalation_detection()
    run_data_exfiltration_detection()
    run_insider_threat_detection()
    run_impact_integrity_detection()
    run_defense_evasion_detection()
    
    # 3. تطبيق إجراءات الحظر والمنع التلقائي (Day 11)
    run_account_lockout_and_deny()
    
    # 4. تطبيق قواعد الحماية والتقسية المباشرة في قاعدة البيانات (Days 12 & 13)
    setup_day12_hardening()
    setup_day13_hardening()
    
    print("\n==================================================")
    print("        ALL DETECTION & HARDENING RUNS COMPLETED  ")
    print("==================================================")