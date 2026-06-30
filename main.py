import os
import socket
import struct
import logging
from collections import defaultdict
import time
from logging import CRITICAL

HOST = "10.244.1.22" # put in your own network address

logging.basicConfig(
    filename="net_traffic.log",
    level=logging.INFO,
    format="%(asctime)s | %(message)s"
)

network_scanner = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

network_scanner.bind((HOST, 0))

if os.name == "nt":
    network_scanner.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

CRITICAL_PORTS = {21, 23, 445, 3389}
MAX_ICMP_PAYLOAD = 100

icmp_tracker = defaultdict(list)
ICMP_THRESHOLD = 10
TIME_WINDOW = 5

print(f"[*] Sniffer was started on {HOST}")

try:
    while True:
        raw_data, addr = network_scanner.recvfrom(65535)
        packet_size = len(raw_data)

        ip_header_raw = raw_data[0:20]
        ip_header = struct.unpack("!BBHHHBBH4s4s", ip_header_raw)

        version_ihl = ip_header[0]
        ihl = version_ihl & 0x0F
        ip_header_length = ihl * 4

        source_ip = socket.inet_ntoa(ip_header[8])
        destination_ip = socket.inet_ntoa(ip_header[9])

        protocol = ip_header[6]

        packet_info = f"IP: {source_ip} -> {destination_ip} | Protocol: {protocol} | Size: {packet_size}B"
        print(f"[*] {packet_info}")

        transport_data = raw_data[ip_header_length:]

        is_anomaly = False
        alert_reason = ""

        match protocol:
            case 6:
                tcp_header = struct.unpack("!HH", transport_data[0:4])
                source_port = tcp_header[0]
                destination_port = tcp_header[1]
                print(f"    TCP connection: {source_port} -> {destination_port}")

                if destination_port in CRITICAL_PORTS:
                    is_anomaly = True
                    alert_reason = f"TCP | Connection to critical port attempt"
            case 17:
                udp_header = struct.unpack("!HH", transport_data[0:4])
                source_port = udp_header[0]
                destination_port = udp_header[1]
                print(f"    UDP connection: {udp_header[0]} -> {udp_header[1]}")

                if destination_port in CRITICAL_PORTS:
                    is_anomaly = True
                    alert_reason = f"UDP | Connection to critical port attempt"
            case 1:
                curr_time = time.time()

                icmp_header = struct.unpack("!BB", transport_data[0:2])
                icmp_type = icmp_header[0]
                icmp_code = icmp_header[1]

                match icmp_type:
                    case 8:
                        print("    ICMP connection: Echo Request")
                    case 0:
                        print("    ICMP connection: Echo Reply")
                    case 3:
                        print(f"    ICMP connection: Destination Unreachable (Code: {icmp_code})")

                if packet_size > MAX_ICMP_PAYLOAD:
                    is_anomaly = True
                    alert_reason = f"ICMP | Anomaly ICMP packet size - ({packet_size}B). Data tunneling is possible"

                else:
                    icmp_tracker[source_ip].append(curr_time)
                    icmp_tracker[source_ip] = [t for t in icmp_tracker[source_ip] if curr_time - t <= TIME_WINDOW]
                    if len(icmp_tracker[source_ip]) > ICMP_THRESHOLD:
                        is_anomaly = True
                        alert_reason = (f"ICMP | Flooding/Scanning detected! ({len(icmp_tracker[source_ip])}) packets per {TIME_WINDOW}s.")

        if is_anomaly:
            alert_message = f"[ALERT] ANOMALY: {alert_reason} | {packet_info}"
            print(f"\033[91m{alert_message}\033[0m")
            logging.warning(alert_message)
        else:
            logging.info(packet_info)
except KeyboardInterrupt:
    print("\n[*] Sniffer stopped")
    if os.name == "nt":
        network_scanner.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)