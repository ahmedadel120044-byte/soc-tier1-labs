import pandas as pd


def analyze_threats(
    df: pd.DataFrame, config: dict, threshold: int = 5
) -> dict:
  """SOC Threat Engine: Correlates events, calculates metrics, maps MITRE ATT&CK techniques, and scores severity."""
  if df.empty:
    return {"flagged_ips": {}, "summary": []}

  mitre_config = config.get("mitre_mapping", {})
  event_ids_map = mitre_config.get("event_ids", {})
  network_map = mitre_config.get("network_events", {})
  full_map = {**event_ids_map, **network_map}

  ip_counts = df["IP"].value_counts()
  suspicious_ips = ip_counts[
      (ip_counts >= threshold) & (ip_counts.index != "0.0.0.0")
  ].to_dict()

  threat_summary = []

  for ip, count in suspicious_ips.items():
    ip_df = df[df["IP"] == ip]

    first_seen = ip_df["Timestamp"].min()
    last_seen = ip_df["Timestamp"].max()
    duration_sec = (last_seen - first_seen).total_seconds()

    events_detected = ip_df["EventID"].unique().tolist()

    mitre_techniques = []
    for e in events_detected:
      mapping_info = full_map.get(str(e))
      if mapping_info:
        tech_id = mapping_info.get("technique_id", "T1000")
        tech_name = mapping_info.get("technique_name", "General Anomaly")
        mitre_techniques.append(f"{tech_id} - {tech_name}")
      else:
        mitre_techniques.append(f"T1000 - General Anomaly ({e})")

    mitre_techniques = sorted(list(set(mitre_techniques)))

    has_host_log = any(
        str(e) in ["4625", "SSH_FAILED_LOGIN"] for e in events_detected
    )
    has_network_log = any(
        str(e) in ["PORT_SCAN", "DNS_QUERY", "TCP_TRAFFIC", "UDP_TRAFFIC"]
        for e in events_detected
    )
    cross_source = has_host_log and has_network_log

    if count >= 20 or cross_source:
      severity = "CRITICAL"
    elif count >= 10:
      severity = "HIGH"
    elif count >= threshold:
      severity = "MEDIUM"
    else:
      severity = "LOW"

    threat_summary.append({
        "IP": ip,
        "Total_Events": count,
        "Severity": severity,
        "Cross_Source_Detected": cross_source,
        "Events": events_detected,
        "MITRE_Techniques": mitre_techniques,
        "First_Seen": first_seen.isoformat(),
        "Last_Seen": last_seen.isoformat(),
        "Duration_Seconds": duration_sec,
    })

  return {"flagged_ips": suspicious_ips, "summary": threat_summary}