import argparse
import logging
import os
import yaml

from core.cleaner import clean_logs
from core.correlator import analyze_threats
from enrichment.ioc_lookup import check_ioc
from parsers.evtx_parser import parse_evtx
from parsers.pcap_parser import parse_pcap
from parsers.syslog_parser import parse_syslog
from reporters.exporter import export_results

from dotenv import load_dotenv

load_dotenv()  

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("SOC_Analyzer")


def load_config(config_path: str, extra_config_path: str = None) -> dict:
  """Loads base config.yaml and merges optional additional mapping YAML files."""
  base_config = {}
  if os.path.exists(config_path):
    with open(config_path, "r", encoding="utf-8") as f:
      base_config = yaml.safe_load(f) or {}

  if extra_config_path and os.path.exists(extra_config_path):
    with open(extra_config_path, "r", encoding="utf-8") as f:
      extra_config = yaml.safe_load(f) or {}

    extra_mitre = extra_config.get("mitre_mapping", {})
    base_mitre = base_config.setdefault("mitre_mapping", {})

    base_mitre.setdefault("event_ids", {}).update(
        extra_mitre.get("event_ids", {})
    )
    base_mitre.setdefault("network_events", {}).update(
        extra_mitre.get("network_events", {})
    )

  return base_config


def main():
  parser = argparse.ArgumentParser(
      description="SOC Log Analysis & Threat Intelligence Engine"
  )
  parser.add_argument("--evtx", type=str, help="Path to Windows EVTX log file")
  parser.add_argument(
      "--pcap", type=str, help="Path to PCAP network traffic file"
  )
  parser.add_argument("--syslog", type=str, help="Path to Linux Syslog file")
  parser.add_argument(
      "--config",
      type=str,
      default="config.yaml",
      help="Path to base config.yaml file",
  )
  parser.add_argument(
      "--extra-config",
      type=str,
      help="Path to additional MITRE mapping YAML file",
  )
  parser.add_argument(
      "--threshold", type=int, help="Override threshold for alert triggering"
  )
  parser.add_argument(
      "--output",
      type=str,
      default="output",
      help="Directory to save generated reports",
  )

  args = parser.parse_args()

  config = load_config(args.config, args.extra_config)
  default_threshold = config.get("thresholds", {}).get("failed_logins", 5)
  threshold = args.threshold or default_threshold

  # Secure API key retrieval: Environment Variable > config.yaml fallback
  api_key = os.environ.get("ABUSEIPDB_API_KEY") or config.get(
      "ioc_enrichment", {}
  ).get("abuseipdb_api_key", "")
  ioc_enabled = config.get("ioc_enrichment", {}).get("enabled", True)

  raw_logs = []

  if args.evtx and os.path.exists(args.evtx):
    logger.info(f"Parsing EVTX file: {args.evtx}")
    raw_logs.extend(parse_evtx(args.evtx))

  if args.pcap and os.path.exists(args.pcap):
    logger.info(f"Parsing PCAP file: {args.pcap}")
    raw_logs.extend(parse_pcap(args.pcap, config))

  if args.syslog and os.path.exists(args.syslog):
    logger.info(f"Parsing Syslog file: {args.syslog}")
    raw_logs.extend(parse_syslog(args.syslog))

  if not raw_logs:
    logger.warning("No valid log files provided or all specified files are missing.")
    print("\nUsage example: python main.py --evtx samples/Security.evtx\n")
    return

  logger.info("Cleaning logs and applying Unified Schema...")
  clean_df = clean_logs(raw_logs)

  logger.info("Running Threat Engine & MITRE ATT&CK Mapping...")
  analysis_res = analyze_threats(clean_df, config, threshold)
  threat_summary = analysis_res.get("summary", [])

  if threat_summary and ioc_enabled:
    if api_key:
      logger.info("Fetching Threat Intel from AbuseIPDB...")
      for item in threat_summary:
        ip = item["IP"]
        item["IOC_Data"] = check_ioc(ip, api_key)
    else:
      logger.warning("No AbuseIPDB API Key found in environment variables. Skipping IOC lookup.")

  logger.info("Generating output files...")
  export_results(clean_df, threat_summary, output_dir=args.output)


if __name__ == "__main__":
  main()