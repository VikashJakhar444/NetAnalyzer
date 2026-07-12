"""
Protocol Analyzer Module.
Decodes packet layers (IP, ARP, ICMP, TCP, UDP, DNS, HTTP) and formats packet info strings.
"""
import sys
from typing import Dict, Any

# Setup import compatibility for testing and main execution
try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from core.logger import logger


class ProtocolAnalyzer:
    """
    Decodes Scapy network frames to identify protocols and construct human-readable summaries.
    """

    @staticmethod
    def analyze(packet) -> Dict[str, Any]:
        """
        Parses a Scapy packet and returns a dictionary with src, dst, protocol, and info summary.
        """
        result = {
            "src": "Unknown",
            "dst": "Unknown",
            "protocol": "Raw",
            "info": f"Length: {len(packet)} bytes"
        }

        if not SCAPY_AVAILABLE:
            return result

        try:
            # 1. ARP Protocol
            if packet.haslayer(scapy.ARP):
                result["protocol"] = "ARP"
                result["src"] = packet[scapy.ARP].psrc if packet[scapy.ARP].psrc else packet.src
                result["dst"] = packet[scapy.ARP].pdst if packet[scapy.ARP].pdst else packet.dst
                
                op_code = packet[scapy.ARP].op
                if op_code == 1:
                    result["info"] = f"Who has {packet[scapy.ARP].pdst}? Tell {packet[scapy.ARP].psrc}"
                elif op_code == 2:
                    result["info"] = f"{packet[scapy.ARP].psrc} is at {packet[scapy.ARP].hwsrc}"
                else:
                    result["info"] = "ARP packet query/reply"
                return result

            # 2. IP Protocol Layers
            if packet.haslayer(scapy.IP):
                ip_layer = packet[scapy.IP]
                result["src"] = ip_layer.src
                result["dst"] = ip_layer.dst
                result["protocol"] = "IP"
                result["info"] = f"IP Packet from {ip_layer.src} to {ip_layer.dst}"

                # 2.1 ICMP Layer
                if packet.haslayer(scapy.ICMP):
                    result["protocol"] = "ICMP"
                    icmp_type = packet[scapy.ICMP].type
                    if icmp_type == 8:
                        result["info"] = "ICMP Echo Request (Ping)"
                    elif icmp_type == 0:
                        result["info"] = "ICMP Echo Reply (Pong)"
                    else:
                        result["info"] = f"ICMP Packet (Type: {icmp_type})"
                    return result

                # 2.2 TCP Layer
                elif packet.haslayer(scapy.TCP):
                    tcp_layer = packet[scapy.TCP]
                    result["protocol"] = "TCP"
                    
                    # Resolve TCP Flags
                    flags = []
                    tcp_flags = tcp_layer.underlayer.fields.get("flags") or tcp_layer.flags
                    if isinstance(tcp_flags, str):
                        # Scapy flags are string flags (e.g. 'S' for SYN, 'A' for ACK)
                        if 'S' in tcp_flags: flags.append("SYN")
                        if 'A' in tcp_flags: flags.append("ACK")
                        if 'F' in tcp_flags: flags.append("FIN")
                        if 'R' in tcp_flags: flags.append("RST")
                        if 'P' in tcp_flags: flags.append("PSH")
                    else:
                        # Integer flags mask checks
                        if tcp_flags & 0x02: flags.append("SYN")
                        if tcp_flags & 0x10: flags.append("ACK")
                        if tcp_flags & 0x01: flags.append("FIN")
                        if tcp_flags & 0x04: flags.append("RST")
                        if tcp_flags & 0x08: flags.append("PSH")

                    flag_str = "+".join(flags) if flags else "NONE"
                    result["info"] = f"TCP Port: {tcp_layer.sport} -> {tcp_layer.dport} | Flags: {flag_str}"

                    # Detect HTTP Protocol inside TCP payload
                    if tcp_layer.dport == 80 or tcp_layer.sport == 80:
                        result["protocol"] = "HTTP"
                        # Try parsing raw payload to find HTTP request line
                        payload = bytes(tcp_layer.payload)
                        if payload:
                            try:
                                payload_str = payload.decode("utf-8", errors="ignore")
                                first_line = payload_str.split("\r\n")[0]
                                if any(x in first_line for x in ["GET", "POST", "HTTP/1.", "PUT", "DELETE"]):
                                    result["info"] = f"HTTP: {first_line[:60]}"
                            except Exception:
                                pass
                        if result["info"].startswith("TCP"):
                            result["info"] = f"HTTP Web Traffic on port {tcp_layer.sport or tcp_layer.dport}"

                    # Detect HTTPS Protocol inside TCP
                    elif tcp_layer.dport == 443 or tcp_layer.sport == 443:
                        result["protocol"] = "HTTPS"
                        result["info"] = "Encrypted TLS Traffic on port 443"

                # 2.3 UDP Layer
                elif packet.haslayer(scapy.UDP):
                    udp_layer = packet[scapy.UDP]
                    result["protocol"] = "UDP"
                    result["info"] = f"UDP Port: {udp_layer.sport} -> {udp_layer.dport}"

                    # Detect DNS Protocol inside UDP
                    if packet.haslayer(scapy.DNS):
                        result["protocol"] = "DNS"
                        dns_layer = packet[scapy.DNS]
                        qd_list = dns_layer.qd
                        if dns_layer.qr == 0:  # Query
                            qname = "Unknown"
                            if qd_list:
                                try:
                                    first_qd = qd_list[0]
                                    if first_qd and hasattr(first_qd, "qname") and first_qd.qname:
                                        qname = first_qd.qname.decode("utf-8", errors="ignore")
                                except Exception:
                                    pass
                            result["info"] = f"DNS Query: {qname.rstrip('.')}"
                        else:  # Response
                            rname = "Unknown"
                            if qd_list:
                                try:
                                    first_qd = qd_list[0]
                                    if first_qd and hasattr(first_qd, "qname") and first_qd.qname:
                                        rname = first_qd.qname.decode("utf-8", errors="ignore")
                                except Exception:
                                    pass
                            result["info"] = f"DNS Response for {rname.rstrip('.')}"

            # 3. Ethernet Layer Fallback (e.g. Non-IP raw Layer 2 packets)
            elif packet.haslayer(scapy.Ether):
                result["src"] = packet.src
                result["dst"] = packet.dst
                result["protocol"] = "Ethernet"
                result["info"] = f"Layer 2 frame: {packet.src} -> {packet.dst}"

        except Exception as e:
            logger.debug(f"ProtocolAnalyzer parsing error: {e}")

        return result
