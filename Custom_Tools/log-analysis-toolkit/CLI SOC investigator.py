import argparse
import re

# Regex pattern لتفكيك السطر: Timestamp, IP, Status Code, Status Message, Endpoint
log_pattern = r"^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\d+)\s+([a-zA-Z]+)\s+/(.+)$"


def analyze_single_log(log_line: str) -> dict:
  match = re.search(log_pattern, log_line)
  if match:
    return {
        "action": "Successful",
        "timestamp": match.group(1),
        "ip": match.group(2),
        "status_code": match.group(3),
        "status": match.group(4),
        "endpoint": match.group(5),
    }
  return {"action": "Failed", "log": log_line}


def analyze_logs(file_path: str, threshold: int, output_file: str = None):
  failed_attempts = {}

  print(f"[+] Analyzing log file: {file_path}")
  print(f"[+] Alert threshold set to: {threshold}")

  try:
    with open(file_path, "r") as file:
      for log in file:
        clean_line = analyze_single_log(log.strip())

        # تجميع الـ IPs التي قامت بمحاولات غير مصرح بها (Unauthorized / 401)
        if (
            clean_line["action"] == "Successful"
            and clean_line["status"] == "Unauthorized"
        ):
          ip = clean_line["ip"]
          failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

    # فلترة الـ IPs التي تجاوزت الـ Threshold
    suspicious_ips = {
        ip: count
        for ip, count in failed_attempts.items()
        if count >= threshold
    }

    # حفظ النتائج في ملف الـ Output
    if output_file:
      with open(output_file, "w") as output:
        output.write("=== SOC Suspicious IP Report ===\n")
        if suspicious_ips:
          for ip, count in suspicious_ips.items():
            line = (
                f"[ALERT] IP: {ip} | Failed Attempts: {count} (Exceeded"
                f" Threshold {threshold})\n"
            )
            output.write(line)
            print(f"[Alert] {line.strip()}")
        else:
          output.write("No suspicious IPs found exceeding the threshold.\n")

      print(f"[+] Report saved successfully to: {output_file}")

  except FileNotFoundError:
    print(f"[-] Error: Log file '{file_path}' was not found.")
  except PermissionError:
    print("[-] Error: Permission denied when accessing the file.")
  except Exception as e:
    print(f"[-] Unexpected error: {e}")


def main():
  parser = argparse.ArgumentParser(description="SOC Log Investigator Tool")

  parser.add_argument(
      "-f", "--file", required=True, type=str, help="Path to the log file"
  )
  parser.add_argument(
      "-t",
      "--threshold",
      default=3,
      type=int,
      help="Alert threshold for failed attempts",
  )
  parser.add_argument(
      "-o",
      "--output",
      default="report.txt",
      type=str,
      help="Path to the output report file",
  )

  args = parser.parse_args()
  analyze_logs(args.file, args.threshold, args.output)


if __name__ == "__main__":
  main()