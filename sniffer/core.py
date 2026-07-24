import os
import socket

from sniffer.parser import PacketParser
from sniffer.detector import AnomalyDetector
from sniffer.logger import NetworkLogger


class RawSniffer:
    def __init__(
        self,
        host: str,
        detector: AnomalyDetector,
        logger: NetworkLogger,
    ) -> None:
        self._host = host
        self._detector = detector
        self._logger = logger
        self._socket: socket.socket | None = None

    def start(self) -> None:
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        self._socket.bind((self._host, 0))

        if os.name == "nt":
            self._socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        self._logger.log_info(f"Sniffer was started on {self._host}")
        print(f"[*] Sniffer was started on {self._host}")

        try:
            while True:
                raw_data, addr = self._socket.recvfrom(65535)
                packet = PacketParser.parse(raw_data)

                packet_info = (
                    f"IP: {packet.source_ip} -> {packet.destination_ip} "
                    f"| Protocol: {packet.protocol} | Size: {packet.packet_size}B"
                )
                print(f"[*] {packet_info}")

                self._print_transport(packet)

                is_anomaly, alert_reason = self._detector.check(packet)

                if is_anomaly:
                    alert_message = f"[ALERT] ANOMALY: {alert_reason} | {packet_info}"
                    print(f"\033[91m{alert_message}\033[0m")
                    self._logger.log_alert(alert_message)
                else:
                    self._logger.log_info(packet_info)

        except KeyboardInterrupt:
            print("\n[*] Sniffer stopped")
            self._logger.log_info("Sniffer stopped")
        finally:
            if self._socket is not None:
                if os.name == "nt":
                    self._socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                self._socket.close()

    @staticmethod
    def _print_transport(packet: object) -> None:
        from sniffer.parser import IPPacket

        if not isinstance(packet, IPPacket):
            return

        th = packet.transport_header
        match packet.protocol:
            case 6:
                print(f"    TCP connection: {th.source_port} -> {th.destination_port}")
            case 17:
                print(f"    UDP connection: {th.source_port} -> {th.destination_port}")
            case 1:
                match th.icmp_type:
                    case 8:
                        print("    ICMP connection: Echo Request")
                    case 0:
                        print("    ICMP connection: Echo Reply")
                    case 3:
                        print(f"    ICMP connection: Destination Unreachable (Code: {th.icmp_code})")
