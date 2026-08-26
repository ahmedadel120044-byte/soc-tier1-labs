import unittest
import pandas as pd
from core.correlator import analyze_threats


class TestSOCAnalyzerCorrelator(unittest.TestCase):

  def setUp(self):
    self.config = {
        "mitre_mapping": {
            "event_ids": {
                "4625": {
                    "technique_id": "T1110",
                    "technique_name": "Brute Force",
                },
                "SSH_FAILED_LOGIN": {
                    "technique_id": "T1110",
                    "technique_name": "Brute Force",
                },
            },
            "network_events": {
                "PORT_SCAN": {
                    "technique_id": "T1046",
                    "technique_name": "Network Service Discovery",
                }
            },
        }
    }

  def test_empty_dataframe(self):
    df = pd.DataFrame(
        columns=["EventID", "Timestamp", "User Name", "Workstation", "IP"]
    )
    result = analyze_threats(df, self.config, threshold=5)
    self.assertEqual(result["summary"], [])

  def test_medium_severity_threshold(self):
    data = [{
        "EventID": "4625",
        "Timestamp": pd.to_datetime("2026-08-01 10:00:00"),
        "User Name": "admin",
        "Workstation": "WS01",
        "IP": "192.168.1.50",
    }] * 5

    df = pd.DataFrame(data)
    result = analyze_threats(df, self.config, threshold=5)

    self.assertEqual(len(result["summary"]), 1)
    self.assertEqual(result["summary"][0]["Severity"], "MEDIUM")
    self.assertFalse(result["summary"][0]["Cross_Source_Detected"])

  def test_critical_severity_cross_source(self):
    host_events = [{
        "EventID": "SSH_FAILED_LOGIN",
        "Timestamp": pd.to_datetime("2026-08-01 10:00:00"),
        "User Name": "root",
        "Workstation": "SRV",
        "IP": "10.0.0.99",
    }] * 3

    net_events = [{
        "EventID": "PORT_SCAN",
        "Timestamp": pd.to_datetime("2026-08-01 10:05:00"),
        "User Name": "N/A",
        "Workstation": "N/A",
        "IP": "10.0.0.99",
    }] * 3

    df = pd.DataFrame(host_events + net_events)
    result = analyze_threats(df, self.config, threshold=5)

    self.assertEqual(len(result["summary"]), 1)
    self.assertEqual(result["summary"][0]["Severity"], "CRITICAL")
    self.assertTrue(result["summary"][0]["Cross_Source_Detected"])


if __name__ == "__main__":
  unittest.main()