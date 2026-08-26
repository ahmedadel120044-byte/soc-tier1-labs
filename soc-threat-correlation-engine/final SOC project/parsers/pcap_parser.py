from collections import defaultdict
from datetime import datetime
import logging
from scapy.all import DNSQR, IP, IPv6, TCP, UDP, Scapy_Exception, rdpcap

logger = logging.getLogger(__name__)


def parse_pcap(pcap_path: str, config: dict = None) -> list:
  logs_data = []
  config = config or {}

  try:
    packets = rdpcap(pcap_path)
  except (FileNotFoundError, PermissionError, Scapy_Exception) as e:
    logger.error(f"Error reading PCAP file {pcap_path}: {e}")
    return logs_data

  port_map = defaultdict(set)
  last_seen_ts = {}

  for idx, pkt in enumerate(packets):
    try:
      timestamp_val = (
          datetime.fromtimestamp(float(pkt.time)).isoformat()
          if hasattr(pkt, "time")
          else None
      )

      src_ip = None
      dst_ip = None

      if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
      elif pkt.haslayer(IPv6):
        src_ip = pkt[IPv6].src
        dst_ip = pkt[IPv6].dst
      else:
        continue

      event_id = "NETWORK_TRAFFIC"

      if pkt.haslayer(DNSQR):
        event_id = "DNS_QUERY"
      elif pkt.haslayer(TCP):
        event_id = "TCP_TRAFFIC"
      elif pkt.haslayer(UDP):
        event_id = "UDP_TRAFFIC"

      if pkt.haslayer(TCP) and src_ip:
        port_map[src_ip].add(pkt[TCP].dport)
        last_seen_ts[src_ip] = timestamp_val

      logs_data.append({
          "EventID": event_id,
          "Timestamp": timestamp_val,
          "User Name": "N/A",
          "Workstation": dst_ip if dst_ip else "N/A",
          "IP": src_ip if src_ip else "N/A",
      })

    except Exception as e:
      logger.warning(
          f"Failed to parse packet #{idx} in {pcap_path}: {e}", exc_info=True
      )
      continue

  scan_threshold = config.get("thresholds", {}).get("port_scan_packets", 100)
  for ip, ports in port_map.items():
    if len(ports) >= scan_threshold:
      logs_data.append({
          "EventID": "PORT_SCAN",
          "Timestamp": last_seen_ts.get(ip),
          "User Name": "N/A",
          "Workstation": "N/A",
          "IP": ip,
      })

  return logs_data