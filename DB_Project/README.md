# SOC Detection Engine

A lightweight Python-based **Security Operations Center (SOC) engine** that detects and actively mitigates common attack patterns directly against a MySQL database — brute force, credential stuffing, SQL injection, privilege escalation, data exfiltration, insider threats, and log tampering — with built-in hardening controls to prevent evasion and destructive queries.

Built as a progressive day-by-day project (Day 3 → Day 13), starting from basic detection queries and ending with active mitigation, database hardening, and immutable audit logging.

---

## Features

| Module | Detects |
|---|---|
| **Brute Force Detection** | Users with excessive failed login attempts |
| **Credential Stuffing Detection** | Single IPs attempting logins against many distinct usernames |
| **SQL Injection Detection** | Regex-based scan of executed queries for common SQLi payloads (`UNION SELECT`, `SLEEP()`, `OR 1=1`, comment injection, etc.) |
| **Privilege Escalation Detection** | Regular users attempting role/admin/grant-related queries |
| **Data Exfiltration Detection** | Abnormally large result sets or queries touching sensitive columns (password hashes, encrypted PII) |
| **Insider Threat Detection** | Admin activity during off-hours (1 AM–5 AM) |
| **Impact & Integrity Detection** | Unbounded `DELETE`/`UPDATE` queries missing a `WHERE` clause |
| **Defense Evasion Detection** | Attempts to `DROP`/`TRUNCATE`/`DELETE` the audit log table itself |

### Active Mitigation
- Automatically **locks user accounts** (15-minute lockout) after repeated failed logins
- Automatically **adds offending IPs** to a deny list after credential-stuffing patterns are detected

### Hardening
- Creates a **least-privilege application user** with `role` column updates revoked
- Enables **`SQL_SAFE_UPDATES`** globally to block unbounded destructive queries
- Adds a **`BEFORE DELETE` trigger** that blocks direct deletion from the `users` table
- Revokes `DELETE`, `UPDATE`, and `DROP` on `audit_logs`, making the audit trail **append-only**
- Documents a recommended **remote log-shipping architecture** to a SIEM (Splunk/QRadar) for tamper-proof forensics

---

## Requirements

- Python 3.8+
- MySQL 5.7+ / 8.0+
- [`mysql-connector-python`](https://pypi.org/project/mysql-connector-python/)

Install dependencies:

```bash
pip install mysql-connector-python
```

---

## Setup

### 1. Environment variables

This project reads all credentials from environment variables — **no credentials are hardcoded**. Create a `.env` file (and make sure it's excluded via `.gitignore`) or export these directly:

```bash
export DB_HOST=localhost
export DB_USER=root
export DB_PASSWORD=your_db_password
export DB_NAME=soc_project
export APP_USER_PASSWORD=your_app_user_password
```

> `APP_USER_PASSWORD` is required for the Day 12 hardening step — the script will refuse to run that step and raise an error if it isn't set, rather than falling back to an insecure default.

### 2. Database schema

The engine expects (at minimum) the following tables in your `soc_project` database:

- **`users`** — `username`, `failed_login_attempts`, `status`, `locked_until`, `role`
- **`audit_logs`** — `id`, `username`, `user_role`, `ip_address`, `action`, `executed_query`, `rows_returned`, `execution_time`

The `ip_deny_list` table is created automatically on first run if it doesn't exist.

### 3. Run

```bash
python soc_engine.py
```

---

## How It Works

On each run, the engine:

1. Ensures the `ip_deny_list` table exists
2. Runs all eight detection modules against `users` and `audit_logs`, printing color-coded alerts for anything suspicious
3. Applies active mitigation — locking flagged accounts and denying flagged IPs
4. Applies (idempotent) hardening controls to the database itself — least-privilege grants, safe-update mode, protective triggers, and append-only audit logs

Detection is read-only; mitigation and hardening are the only steps that write to the schema or grants, and they're designed to be safely re-run without side effects (`CREATE USER IF NOT EXISTS`, `DROP TRIGGER IF EXISTS` before recreate, etc.).

---

## Security Notes

- All credentials are pulled from environment variables at runtime — none are committed to source control.
- The application database user (`app_user`) is deliberately restricted: it cannot alter the `role` column on `users`, and after Day 13 hardening it can no longer delete, update, or drop `audit_logs`.
- `SQL_SAFE_UPDATES` and the `prevent_users_deletion` trigger are defense-in-depth measures against accidental or malicious unbounded writes.
- For production use, audit logs should be shipped to an external SIEM in real time (see the architecture note printed by the Day 13 module) so that log integrity survives even a full compromise of the database host.

---

## Disclaimer

This project was built as a learning exercise in SOC detection logic and defensive database design. Review and adapt the detection thresholds, regex patterns, and hardening steps before using any part of this in a production environment.

---

## License

Add your preferred license here (e.g. MIT).