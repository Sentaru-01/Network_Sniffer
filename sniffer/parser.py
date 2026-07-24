import socket
import struct
from dataclasses import dataclass


@dataclass
class TransportHeader:
    source_port: int | None = None
    destination_port: int | None = None
    icmp_type: int | None = None
    icmp_code: int | None = None


@dataclass
class IPPacket:
    source_ip: str
    destination_ip: str
    protocol: int
    packet_size: int
    transport_header: TransportHeader


class PacketParser:
    @staticmethod
    def parse(raw_data: bytes) -> IPPacket:
        if len(raw_data) < 20:
            raise ValueError("Packet too short for IP header")

        ip_header = struct.unpack("!BBHHHBBH4s4s", raw_data[:20])

        version_ihl = ip_header[0]
        ihl = version_ihl & 0x0F
        ip_header_length = ihl * 4

        source_ip = socket.inet_ntoa(ip_header[8])
        destination_ip = socket.inet_ntoa(ip_header[9])
        protocol = ip_header[6]

        transport_data = raw_data[ip_header_length:]
        transport_header = PacketParser._parse_transport(protocol, transport_data)

        return IPPacket(
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            packet_size=len(raw_data),
            transport_header=transport_header,
        )

    @staticmethod
    def _parse_transport(protocol: int, data: bytes) -> TransportHeader:
        match protocol:
            case 6:
                if len(data) < 4:
                    raise ValueError("Packet too short for TCP header")
                tcp_header = struct.unpack("!HH", data[:4])
                return TransportHeader(
                    source_port=tcp_header[0],
                    destination_port=tcp_header[1],
                )
            case 17:
                if len(data) < 4:
                    raise ValueError("Packet too short for UDP header")
                udp_header = struct.unpack("!HH", data[:4])
                return TransportHeader(
                    source_port=udp_header[0],
                    destination_port=udp_header[1],
                )
            case 1:
                if len(data) < 2:
                    raise ValueError("Packet too short for ICMP header")
                icmp_header = struct.unpack("!BB", data[:2])
                return TransportHeader(
                    icmp_type=icmp_header[0],
                    icmp_code=icmp_header[1],
                )
        return TransportHeader()
