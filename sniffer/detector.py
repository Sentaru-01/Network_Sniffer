import time
from collections import defaultdict

from sniffer.parser import IPPacket


class AnomalyDetector:
    def __init__(
        self,
        critical_ports: set[int],
        max_icmp_payload: int,
        icmp_threshold: int,
        time_window: int,
    ) -> None:
        self._critical_ports = critical_ports
        self._max_icmp_payload = max_icmp_payload
        self._icmp_threshold = icmp_threshold
        self._time_window = time_window
        self._icmp_tracker: dict[str, list[float]] = defaultdict(list)

    def check(self, packet: IPPacket) -> tuple[bool, str]:
        is_anomaly = False
        alert_reason = ""

        match packet.protocol:
            case 6:
                if packet.transport_header.destination_port in self._critical_ports:
                    is_anomaly = True
                    alert_reason = "TCP | Connection to critical port attempt"
            case 17:
                if packet.transport_header.destination_port in self._critical_ports:
                    is_anomaly = True
                    alert_reason = "UDP | Connection to critical port attempt"
            case 1:
                curr_time = time.time()

                if packet.packet_size > self._max_icmp_payload:
                    is_anomaly = True
                    alert_reason = (
                        f"ICMP | Anomaly ICMP packet size - ({packet.packet_size}B). "
                        "Data tunneling is possible"
                    )
                else:
                    self._icmp_tracker[packet.source_ip].append(curr_time)
                    self._icmp_tracker[packet.source_ip] = [
                        t
                        for t in self._icmp_tracker[packet.source_ip]
                        if curr_time - t <= self._time_window
                    ]
                    if len(self._icmp_tracker[packet.source_ip]) > self._icmp_threshold:
                        is_anomaly = True
                        alert_reason = (
                            f"ICMP | Flooding/Scanning detected! "
                            f"({len(self._icmp_tracker[packet.source_ip])}) "
                            f"packets per {self._time_window}s."
                        )

        return is_anomaly, alert_reason
