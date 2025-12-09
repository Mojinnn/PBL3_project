from scapy.all import sniff
from datetime import datetime
import time
import csv
import os

# ========================
# CONFIGURATION
# ========================
IFACE = "bridge0"
CAPTURE_TIME = 10          # capture duration each cycle (s)
INTERVAL = 60              # time between 2 measurements (s)
CSV_FILE = "data/traffic_probe.csv"

# ========================
# UTILITY FUNCTIONS
# ========================
def analyze_packets(packets):
    stats = {
#        "total_packets": len(packets),
        "tcp": 0,
        "udp": 0,
        "icmp": 0,
        "other": 0,
        "total_bytes": 0
    }

    for pkt in packets:

        # This code line to check the integrity of packet like wireshark
        # print(f"{pkt.time}: {pkt.summary()}")

        stats["total_bytes"] += len(pkt)
        if pkt.haslayer("TCP"):
            stats["tcp"] += 1
        elif pkt.haslayer("UDP"):
            stats["udp"] += 1
        elif pkt.haslayer("ICMP"):
            stats["icmp"] += 1
        else:
            stats["other"] += 1

# Tổng gói = tổng TCP+UDP+ICMP+Other
    stats["total_packets"] = stats["tcp"] + stats["udp"] + stats["icmp"] + stats["other"]
    return stats

def ensure_csv_header(file):
    if not os.path.exists(file):
        os.makedirs(os.path.dirname(file), exist_ok=True)
        with open(file, mode="w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "total_packets", "tcp", "udp", "icmp", "other", "total_bytes"])

# ========================
# MAIN FUNCTION
# ========================
def main():
    ensure_csv_header(CSV_FILE)
    print(f"Starting Scapy capture on interface '{IFACE}'. Data will be saved to {CSV_FILE}")
    while True:
        print(f"Capturing {CAPTURE_TIME}s of traffic on {IFACE}...")
        packets = sniff(iface=IFACE, timeout=CAPTURE_TIME)
        stats = analyze_packets(packets)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with open(CSV_FILE, mode="a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                timestamp, IFACE,
                stats["total_packets"],
                stats["tcp"],
                stats["udp"],
                stats["icmp"],
                stats["other"],
                stats["total_bytes"]
            ])


        print(f"[{timestamp}] total={stats['total_packets']} | tcp={stats['tcp']} | udp={stats['udp']} | icmp={stats['icmp']} | bytes={stats['total_bytes']}")
        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()

# implement with cmd: sudo /home/pi/venv/bin/python traffic_probe.py
