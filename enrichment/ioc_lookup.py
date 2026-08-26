import logging
import requests

logger = logging.getLogger(__name__)


def check_ioc(ip: str, api_key: str = None) -> dict:
  """Queries AbuseIPDB API for threat intelligence on suspicious IPs."""
  default_res = {
      "abuseConfidenceScore": 0,
      "countryCode": "N/A",
      "isp": "N/A (No API Key Provided)",
  }

  if not api_key:
    return default_res

  url = "https://api.abuseipdb.com/api/v2/check"
  headers = {"Accept": "application/json", "Key": api_key}
  params = {"ipAddress": ip, "maxAgeInDays": "90"}

  try:
    response = requests.get(url, headers=headers, params=params, timeout=5)
    if response.status_code == 200:
      data = response.json().get("data", {})
      return {
          "abuseConfidenceScore": data.get("abuseConfidenceScore", 0),
          "countryCode": data.get("countryCode", "N/A"),
          "isp": data.get("isp", "N/A"),
      }
    else:
      logger.warning(
          f"AbuseIPDB returned status code {response.status_code} for IP"
          f" {ip}"
      )
  except Exception as e:
    logger.error(f"Threat Intel lookup failed for {ip}: {e}")

  return default_res