from scapy.all import DNSQR, IP, IPv6, Scapy_Exception, rdpcap


def analyze_dns_pcap(pcap_path: str):
  try:
    packets = rdpcap(pcap_path)
    print(f"Total number of packets: {len(packets)}")

    for pkt in packets:
      try:
        if pkt.haslayer(IP) and pkt.haslayer(DNSQR):
          src_ip = pkt[IP].src
          domain = pkt[DNSQR].qname.decode("utf-8").rstrip(".")
          print(f"Source IP: {src_ip}, Domain: {domain}")
        elif pkt.haslayer(IPv6) and pkt.haslayer(DNSQR):
          src_ip = pkt[IPv6].src
          domain = pkt[DNSQR].qname.decode("utf-8").rstrip(".")
          print(f"Source IP: {src_ip}, Domain: {domain}")
      except (AttributeError, IndexError, UnicodeDecodeError):
        continue 

  except FileNotFoundError:
    print("File not found")
  except PermissionError:
    print("Permission denied")
  except Scapy_Exception:
    print("Scapy error")
  except Exception as e:
    print(f"An error occurred: {e}")


if __name__ == "__main__":
    analyze_dns_pcap("dns.pcapng")