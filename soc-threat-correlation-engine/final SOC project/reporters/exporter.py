import json
import os
import pandas as pd


def export_results(
    df: pd.DataFrame, threat_summary: list, output_dir: str = "output"
) -> None:
  """Generates details.csv, summary.json, and prints terminal summary."""
  os.makedirs(output_dir, exist_ok=True)

  csv_path = os.path.join(output_dir, "details.csv")
  df.to_csv(csv_path, index=False)

  json_path = os.path.join(output_dir, "summary.json")
  with open(json_path, "w", encoding="utf-8") as f:
    json.dump(threat_summary, f, indent=4, ensure_ascii=False)

  print("\n" + "=" * 55)
  print(" 🛡️   SOC THREAT ANALYSIS SUMMARY   🛡️")
  print("=" * 55)

  if not threat_summary:
    print("[+] No suspicious activities detected above threshold.")
  else:
    print(f"[*] Total Suspicious IPs Flagged: {len(threat_summary)}")
    print("-" * 55)

    for item in threat_summary:
      print(f" 🚨 IP Address   : {item.get('IP')}")
      print(f" 📊 Severity     : {item.get('Severity')}")
      print(f" 🔢 Total Events : {item.get('Total_Events')}")
      print(
          " 🎯 MITRE ATT&CK:"
          f" {', '.join(item.get('MITRE_Techniques', []))}"
      )

      ioc = item.get("IOC_Data", {})
      if ioc:
        score = ioc.get("abuseConfidenceScore", 0)
        country = ioc.get("countryCode", "N/A")
        isp = ioc.get("isp", "N/A")
        print(f" 🌐 Threat Intel : Score {score}% | Country: {country} | {isp}")

      print(
          f" ⏱️ Timeline     : {item.get('First_Seen')} ->"
          f" {item.get('Last_Seen')}"
      )
      print("-" * 55)

  print(f"[+] Full clean details saved to: {csv_path}")
  print(f"[+] Threat summary saved to  : {json_path}")
  print("=" * 55 + "\n")