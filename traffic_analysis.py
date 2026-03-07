from scapy.all import IP, TCP # type: ignore
from collections import defaultdict



class TrafficAnalyzer:
    def __init__(self):
        self.connections = defaultdict(list)
        self.flow_stats = defaultdict(
            lambda: {
                "packet_count": 0,
                "byte_count": 0,
                "start_time": None,
                "last_time": None,
            }
        )

    def analyze_packet(self, packet):
        if IP in packet and TCP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport

            flow_key = (ip_src, ip_dst, port_src, port_dst)

            # Update flow statistics
            stats = self.flow_stats[flow_key]
            stats["packet_count"] += 1 # type: ignore
            stats["byte_count"] += len(packet) # type: ignore
            current_time = packet.time

            if not stats["start_time"]:
                stats["start_time"] = current_time
            stats["last_time"] = current_time

            return self.extract_features(packet, stats)

    def extract_features(self, packet, stats):
        time = stats["last_time"] - stats["start_time"]

        if time == 0:
            return {
                "packet_size": len(packet),
                "flow_duration": stats["last_time"] - stats["start_time"],
                "packet_rate": 0,
                "byte_rate": 0,
                "tcp_flags": packet[TCP].flags,
                "window_size": packet[TCP].window,
            }

        else:
            return {
                "packet_size": len(packet),
                "flow_duration": stats["last_time"] - stats["start_time"],
                "packet_rate": stats["packet_count"] / time,
                "byte_rate": stats["byte_count"] / time,
                "tcp_flags": packet[TCP].flags,
                "window_size": packet[TCP].window,
            }

