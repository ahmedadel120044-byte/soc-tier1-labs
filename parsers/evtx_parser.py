import logging
import xml.etree.ElementTree as ET
from Evtx.Evtx import Evtx

logger = logging.getLogger(__name__)


def parse_evtx(evtx_file: str) -> list:
  logs_data = []
  ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}

  try:
    with Evtx(evtx_file) as logs:
      for record in logs.records():
        try:
          xml_str = record.xml()
          root = ET.fromstring(xml_str)

          event_id = root.find(".//ns:EventID", ns)
          time_created = root.find(".//ns:TimeCreated", ns)

          event_id_val = event_id.text if event_id is not None else None
          timestamp_val = (
              time_created.attrib.get("SystemTime")
              if time_created is not None
              else None
          )

          username = None
          workstation = None
          ip_address = None

          for data in root.findall(".//ns:EventData/ns:Data", ns):
            name_attr = data.attrib.get("Name")
            if name_attr == "TargetUserName":
              username = data.text
            elif name_attr == "WorkstationName":
              workstation = data.text
            elif name_attr == "IpAddress":
              ip_address = data.text

          logs_data.append({
              "EventID": event_id_val,
              "Timestamp": timestamp_val,
              "User Name": username,
              "Workstation": workstation,
              "IP": ip_address,
          })
        except Exception as err:
          logger.warning(
              f"Error parsing single EVTX record in {evtx_file}: {err}"
          )
          continue
  except Exception as e:
    logger.error(f"Failed to open EVTX file {evtx_file}: {e}")

  return logs_data