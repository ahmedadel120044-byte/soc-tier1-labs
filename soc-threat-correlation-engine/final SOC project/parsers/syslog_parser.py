import logging
import re

logger = logging.getLogger(__name__)


def parse_syslog(log_path: str) -> list:
  logs_data = []

  failed_regex = re.compile(
      r"(?P<timestamp>\b\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\b)\s+(?P<hostname>\S+)\s+sshd\[\d+\]:\s+Failed"
      r" password for (?:invalid user )?(?P<user>\S+) from"
      r" (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
  )

  accepted_regex = re.compile(
      r"(?P<timestamp>\b\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\b)\s+(?P<hostname>\S+)\s+sshd\[\d+\]:\s+Accepted"
      r" password for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
  )

  try:
    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
      for line in f:
        line = line.strip()
        if not line:
          continue

        event_id = None
        username = "N/A"
        ip_address = "N/A"
        hostname = "N/A"
        timestamp_val = None

        failed_match = failed_regex.search(line)
        accepted_match = accepted_regex.search(line)

        if failed_match:
          event_id = "SSH_FAILED_LOGIN"
          timestamp_val = failed_match.group("timestamp")
          hostname = failed_match.group("hostname")
          username = failed_match.group("user")
          ip_address = failed_match.group("ip")
        elif accepted_match:
          event_id = "SSH_SUCCESS"
          timestamp_val = accepted_match.group("timestamp")
          hostname = accepted_match.group("hostname")
          username = accepted_match.group("user")
          ip_address = accepted_match.group("ip")

        if event_id:
          logs_data.append({
              "EventID": event_id,
              "Timestamp": timestamp_val,
              "User Name": username,
              "Workstation": hostname,
              "IP": ip_address,
          })

  except (FileNotFoundError, PermissionError) as e:
    logger.error(f"Error reading Syslog file {log_path}: {e}")

  return logs_data