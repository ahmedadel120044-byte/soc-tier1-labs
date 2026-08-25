raw_logs = [
    "2026-08-25 08:00:12 - IP: 192.168.1.50 - Status: FAILED - User: admin",
    "2026-08-25 08:00:15 - IP: 192.168.1.50 - Status: FAILED - User: admin",
    "2026-08-25 08:00:20 - IP: 192.168.1.50 - Status: FAILED - User: root",
    "2026-08-25 08:00:25 - IP: 192.168.1.50 - Status: FAILED - User: admin",
    "2026-08-25 08:00:30 - IP: 192.168.1.50 - Status: FAILED - User: test",
    "2026-08-25 08:00:35 - IP: 192.168.1.50 - Status: FAILED - User: admin",
    "2026-08-25 08:01:00 - IP: 10.0.0.12 - Status: SUCCESS - User: ahmed",
    "2026-08-25 08:02:11 - IP: 172.16.0.5 - Status: FAILED - User: user1",
    "2026-08-25 08:02:15 - IP: 172.16.0.5 - Status: FAILED - User: user1",
    "2026-08-25 08:03:00 - CORRUPTED_LOG_LINE_MISSING_DATA",
    "2026-08-25 08:04:10 - IP: 192.168.1.100 - Status: SUCCESS - User: sara",
]

def analyze_single_log(log):
    try:
        parts = log.split(" - ")
        return {
            "TimeStamp": parts[0],
            "IP": parts[1].split(": ")[1],
            "Status": parts[2].split(": ")[1],
            "User": parts[3].split(": ")[1],
        }
    except (IndexError, ValueError):
        # سطر معطوب أو ناقص بيانات - نتجاهله بدل ما نوقع السكريبت كله
        return None

def cleaning_logs(logs_list):
    cleaned = []
    for log in logs_list:
        line = analyze_single_log(log)
        if line is not None and line["Status"] == "FAILED":
            cleaned.append(line)
    return cleaned

def counting_tries(logs_list):
    logs = cleaning_logs(logs_list)
    failed_attempts = {}
    for log in logs:
        ip = log["IP"]
        failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
    return failed_attempts

def flagging_ips(failed_attempts, threshold=5):
    return {ip: count for ip, count in failed_attempts.items() if count > threshold}

if __name__ == "__main__":
    counts = counting_tries(raw_logs)
    flagged = flagging_ips(counts)
    print("Failed attempts per IP:", counts)
    print("Flagged IPs (exceeded threshold):", flagged)