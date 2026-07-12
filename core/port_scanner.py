"""
Port Scanner Module.
Scans TCP ports, identifies services, executes banner grabs, maps risks, and writes to database.
"""
import concurrent.futures
import ipaddress
import re
import socket
import ssl
import sys
import threading
import time
from typing import List, Dict, Any, Tuple, Optional

# Setup import compatibility for testing and main execution
try:
    from core.constants import TOP_COMMON_PORTS, TOP_COMMON_UDP_PORTS, VULNERABLE_PORTS
    from core.logger import logger
    from core.database import DatabaseManager
    from core.event_bus import EventBus
except ImportError:
    TOP_COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3306, 3389, 8080]
    TOP_COMMON_UDP_PORTS = [53, 67, 68, 123, 137, 138, 161, 162, 389, 514, 1900, 5353]
    VULNERABLE_PORTS = {
        21: {"service": "FTP", "risk": "Medium"},
        23: {"service": "Telnet", "risk": "High"},
        80: {"service": "HTTP", "risk": "Low"},
        445: {"service": "SMB", "risk": "High"},
        3389: {"service": "RDP", "risk": "Medium"},
    }
    from core.compat import DummyLogger
    logger = DummyLogger()


def _extract_banner_text(data: bytes, max_len: int = 100) -> str:
    """Extract readable ASCII text from binary banner data.
    Joins DNS label-encoded parts with dots when separators are 1–63.
    """
    parts = []
    cur = []
    seps = []
    for b in data:
        if 0x20 <= b <= 0x7E:
            cur.append(chr(b))
        else:
            if len(cur) >= 3:
                parts.append(''.join(cur))
                seps.append(b)
            cur = []
    if len(cur) >= 3:
        parts.append(''.join(cur))
        seps.append(0)

    if not parts:
        return ""

    # If all inter-part separators are 1–63, treat as DNS label encoding
    is_dns = all(1 <= seps[i] <= 63 for i in range(len(parts) - 1))
    text = ("." if is_dns else " ").join(parts)
    text = text.replace("\r", "").replace("\n", " | ")[:max_len]
    return text


class PortScanner:
    """
    TCP/UDP port scanner. Uses thread-pool concurrent execution.
    Supports TCP connect scan and UDP probe scan.
    """

    def __init__(self):
        self.db = DatabaseManager()
        self.event_bus = EventBus()
        self.is_scanning = False
        self.lock = threading.Lock()

    def run_scan(self, target_ip: str, scan_mode: str = "Quick", custom_ports: Optional[List[int]] = None, stop_event: Optional[threading.Event] = None, protocol: str = "TCP") -> List[Dict[str, Any]]:
        """
        Main entry point to perform port scans.
        Modes: Quick (common ports), Full (1-1024), Extreme (1-65535), Custom (user defined list/range).
        Protocol: TCP (connect scan), UDP (probe scan).
        """
        with self.lock:
            if self.is_scanning:
                logger.warning("Port scan already running. Request rejected.")
                return []
            self.is_scanning = True

        self.event_bus.publish("PORT_SCAN_STARTED", {"target_ip": target_ip, "mode": scan_mode, "protocol": protocol})
        logger.info(f"Port scan started on target: {target_ip} (Mode: {scan_mode}, Protocol: {protocol})")

        # Resolve ports list based on mode
        ports_to_scan = []
        if scan_mode == "Quick":
            if protocol == "UDP":
                ports_to_scan = list(TOP_COMMON_UDP_PORTS)
            else:
                ports_to_scan = list(TOP_COMMON_PORTS)
        elif scan_mode == "Full":
            ports_to_scan = list(range(1, 1025))
        elif scan_mode == "Extreme":
            ports_to_scan = list(range(1, 65536))
        elif scan_mode == "Custom":
            ports_to_scan = custom_ports if custom_ports else []
        
        if not ports_to_scan:
            logger.warning("No target ports specified for scan.")
            self.is_scanning = False
            self.event_bus.publish("PORT_SCAN_FINISHED", {"target_ip": target_ip, "ports": []})
            return []

        open_ports = []
        try:
            max_workers = min(300, len(ports_to_scan))
            scan_func = self._scan_tcp_port if protocol == "TCP" else self._scan_udp_port

            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(scan_func, target_ip, port): port 
                    for port in ports_to_scan
                }

                total_ports = len(ports_to_scan)
                scanned_count = 0
                progress_interval = max(1, total_ports // 100)
                last_progress = -1
                scan_start = time.time()
                max_duration = 3600

                for future in concurrent.futures.as_completed(futures):
                    if stop_event and stop_event.is_set():
                        logger.info("Port scanning cancelled by user. Terminating executor.")
                        executor.shutdown(wait=False, cancel_futures=True)
                        break

                    if time.time() - scan_start > max_duration:
                        logger.warning("Port scan reached maximum duration, stopping.")
                        executor.shutdown(wait=False, cancel_futures=True)
                        break

                    port_result = future.result()
                    scanned_count += 1

                    if scanned_count % progress_interval == 0 or scanned_count == total_ports:
                        progress = int((scanned_count / total_ports) * 100)
                        if progress != last_progress:
                            last_progress = progress
                            self.event_bus.publish("PORT_SCAN_PROGRESS", {"target_ip": target_ip, "progress": progress})

                    if port_result["state"] in ("Open", "Open|Filtered"):
                        open_ports.append(port_result)
                        self.event_bus.publish("PORT_DISCOVERED", {"target_ip": target_ip, "port_info": port_result})

            if not (stop_event and stop_event.is_set()):
                self._save_results_to_database(target_ip, open_ports)

        except Exception as e:
            logger.error(f"Error during port scanning task: {e}")
        finally:
            self.is_scanning = False
            self.event_bus.publish("PORT_SCAN_FINISHED", {"target_ip": target_ip, "ports": open_ports})

        return open_ports

    @staticmethod
    def _family(ip: str) -> int:
        try:
            return socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET
        except (ValueError, ipaddress.AddressValueError):
            return socket.AF_INET

    def _scan_tcp_port(self, ip: str, port: int) -> Dict[str, Any]:
        """Scans a single TCP port. Uses OS TCP timeout (no per-port timeout)."""
        result = {
            "port": port, "protocol": "TCP",
            "service": "Unknown", "state": "Closed", "banner": "", "risk": "None",
        }
        sock = None
        try:
            sock = socket.socket(self._family(ip), socket.SOCK_STREAM)

            if sock.connect_ex((ip, port)) == 0:
                result["state"] = "Open"
                result["service"] = self._resolve_service(port, "tcp")
                result["risk"] = self._resolve_risk(port)
                raw_banner = self._grab_banner(sock, port)
                if raw_banner:
                    result["banner"] = raw_banner
                    version = self._parse_service_version(raw_banner, port)
                    if version:
                        result["service"] = f"{result['service']} ({version})"
        except Exception:
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

        return result

    _UDP_SERVICES = {
        53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP",
        123: "NTP", 137: "NetBIOS", 138: "NetBIOS", 161: "SNMP",
        162: "SNMP-Trap", 389: "LDAP", 514: "Syslog",
        520: "RIP", 546: "DHCPv6", 547: "DHCPv6",
        1900: "SSDP", 3702: "WS-Discovery", 4500: "IPsec-NAT-T",
        5353: "mDNS", 5355: "LLMNR", 5683: "CoAP",
    }

    _TCP_SERVICES = {
        7: "ECHO", 9: "DISCARD", 13: "DAYTIME", 17: "QOTD",
        19: "CHARGEN", 20: "FTP-DATA", 21: "FTP", 22: "SSH",
        23: "TELNET", 25: "SMTP", 37: "TIME", 43: "WHOIS",
        53: "DNS", 70: "GOPHER", 79: "FINGER", 80: "HTTP",
        88: "KERBEROS", 109: "POP2", 110: "POP3", 111: "RPC",
        113: "IDENT", 119: "NNTP", 123: "NTP", 135: "MSRPC",
        137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN",
        143: "IMAP", 161: "SNMP", 162: "SNMP-Trap", 179: "BGP",
        194: "IRC", 389: "LDAP", 427: "SLP", 443: "HTTPS",
        444: "SNPP", 445: "SMB", 465: "SMTPS", 500: "ISAKMP",
        512: "EXEC", 513: "LOGIN", 514: "SHELL", 515: "PRINTER",
        520: "RIP", 521: "RIPng", 524: "NCP", 540: "UUCP",
        543: "KLOGIN", 544: "KSHELL", 546: "DHCPv6-C",
        547: "DHCPv6-S", 548: "AFP", 554: "RTSP", 563: "NNTP-SSL",
        587: "SMTP-SUB", 591: "FileMaker", 593: "MSRPC-SSL",
        631: "IPP", 636: "LDAPS", 646: "LDP", 666: "DOOM",
        691: "MS-EXCH", 694: "Linux-HA", 700: "EPP",
        808: "HTTP-ALT", 843: "ADOBE-Flash", 853: "DNS-TLS",
        860: "ISCSI", 873: "RSYNC", 902: "VMware-Server",
        903: "VMware-Console", 989: "FTP-DATA-SSL", 990: "FTP-SSL",
        991: "NAS-Admin", 992: "TELNET-SSL", 993: "IMAPS",
        994: "IRC-SSL", 995: "POP3S", 1024: "DCOM",
        1080: "SOCKS-Proxy", 1099: "RMI-Registry",
        1433: "MSSQL", 1521: "Oracle-DB", 2049: "NFS",
        2082: "cPanel", 2083: "cPanel-SSL", 2086: "WHM",
        2087: "WHM-SSL", 2095: "Webmail", 2096: "Webmail-SSL",
        2222: "DirectAdmin", 2375: "Docker", 2376: "Docker-SSL",
        3000: "Node.js-Dev", 3128: "Squid-Proxy",
        3306: "MySQL", 3389: "RDP", 3690: "SVN",
        4000: "Node.js-Dev", 4443: "HTTPS-ALT",
        4848: "GlassFish",
        5000: "UPnP", 5001: "iperf", 5060: "SIP",
        5061: "SIP-TLS", 5222: "XMPP", 5223: "XMPP-SSL",
        5269: "XMPP-Server",
        5432: "PostgreSQL", 5500: "VNC", 5555: "Android-Debug",
        5601: "Kibana", 5631: "pcANYWHERE", 5671: "AMQP-SSL",
        5672: "AMQP", 5800: "VNC-HTTP", 5900: "VNC",
        5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
        6000: "X11", 6379: "Redis", 6443: "HTTPS-ALT",
        6667: "IRC", 6697: "IRC-SSL", 7001: "WebLogic",
        7002: "WebLogic-SSL", 7070: "RTSP-ALT", 8000: "HTTP-ALT",
        8008: "HTTP-ALT", 8009: "AJP13", 8080: "HTTP-Alt",
        8181: "HTTP-ALT", 8291: "RouterOS-Winbox",
        8332: "Bitcoin", 8333: "Bitcoin", 8443: "HTTPS-ALT",
        8649: "Ganglia", 8834: "Nessus", 8888: "HTTP-ALT",
        8983: "Solr", 9000: "HTTP-ALT", 9042: "Cassandra",
        9090: "HTTP-ALT", 9092: "Kafka", 9100: "JetDirect",
        9150: "Tor", 9200: "Elasticsearch", 9300: "Elasticsearch",
        9418: "Git", 9443: "HTTPS-ALT", 9876: "HTTP-ALT",
        10000: "HTTP-ALT", 11211: "Memcached", 12345: "NetBus",
        13720: "NetBackup", 20000: "DNP3", 30718: "Lantronix",
    }

    _UDP_PROBES = {
        53: bytes([0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x03, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
                   0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01]),
        161: bytes([0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69,
                    0x63, 0xa0, 0x19, 0x02, 0x04, 0x7f, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00,
                    0x02, 0x01, 0x00, 0x30, 0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01,
                    0x02, 0x01, 0x05, 0x00]),
        123: bytes([0x23, 0x00, 0x0e, 0xfa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x56, 0x67, 0x89]),
        1900: b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n",
    }

    def _scan_udp_port(self, ip: str, port: int, timeout: float = 2.0) -> Dict[str, Any]:
        """Scans a single UDP port. Sends protocol-specific probes, detects via response or ICMP error."""
        result = {
            "port": port, "protocol": "UDP",
            "service": self._UDP_SERVICES.get(port, "Unknown"),
            "state": "Closed", "banner": "", "risk": "None",
        }
        sock = None
        try:
            sock = socket.socket(self._family(ip), socket.SOCK_DGRAM)
            sock.settimeout(timeout)

            probe = self._UDP_PROBES.get(port, b"")
            send_count = 0

            while send_count < 2:
                try:
                    sock.sendto(probe if probe else b"", (ip, port))
                    send_count += 1
                    data, addr = sock.recvfrom(1024)
                    result["state"] = "Open"
                    result["risk"] = self._resolve_risk(port)
                    if data:
                        text = _extract_banner_text(data, 100)
                        result["banner"] = text if text else f"[{len(data)} bytes of binary data]"
                    break
                except socket.timeout:
                    if send_count >= 2:
                        result["state"] = "Open|Filtered"
                except ConnectionRefusedError:
                    result["state"] = "Closed"
                    break
                except OSError as e:
                    if getattr(e, "winerror", None) in (10054,):
                        result["state"] = "Closed"
                        break
                    raise
        except (ConnectionRefusedError, OSError) as e:
            if getattr(e, "winerror", None) in (10054,):
                result["state"] = "Closed"
        except Exception:
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

        return result

    def _resolve_service(self, port: int, proto: str = "tcp") -> str:
        """Resolves port to common service name using local mapping or socket API."""
        if port in VULNERABLE_PORTS:
            return VULNERABLE_PORTS[port]["service"]
        if proto == "tcp" and port in self._TCP_SERVICES:
            return self._TCP_SERVICES[port]
        if proto == "udp" and port in self._UDP_SERVICES:
            return self._UDP_SERVICES[port]
        try:
            return socket.getservbyport(port, proto).upper()
        except OSError:
            return "Unknown"

    def _resolve_risk(self, port: int) -> str:
        """Determines the risk classification of open ports."""
        if port in VULNERABLE_PORTS:
            return VULNERABLE_PORTS[port]["risk"]
        return "Low"  # Default fallback classification for unspecified open TCP ports

    _SSL_PORTS = {443, 465, 563, 636, 989, 990, 993, 994, 995, 8443}

    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        """Attempts to read banner from open socket. Uses 3s read timeout."""
        probes = {
            21: b"USER anonymous\r\n",
            22: b"",
            23: b"",
            25: b"EHLO scanner\r\n",
            80: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
            110: b"",
            143: b"",
            443: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
            445: b"",
            993: b"",
            995: b"",
            3306: b"",
            3389: b"",
            5432: b"",
            5900: b"",
            6379: b"",
            8080: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
            8443: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
            27017: b"",
        }

        try:
            sock.settimeout(3.0)

            # Wrap with TLS for SSL ports before any I/O
            conn = sock
            if port in self._SSL_PORTS:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = ctx.wrap_socket(sock, server_hostname="localhost")

            probe = probes.get(port)
            if probe:
                conn.sendall(probe)

            banner = conn.recv(1024)
            if banner:
                text = _extract_banner_text(banner, 200)
                if text:
                    return text
        except socket.timeout:
            pass
        except Exception:
            pass
        return ""

    _VERSION_RE = {
        22: (r"SSH-2\.0-([^\s]+)", 0),
        21: (r"(?:220\s+)?(?:\(?[\w.-]+\)?\s)?([\w./]+(?:\s+[\d.]+)?)", 0),
        25: (r"220\s+(?:\S+\s+)?(.+?)(?:\s+ESMTP|SMTP)?\s*(?:\r|$)", 0),
        80: (r"Server:\s*(.+?)(?:\r|$)", 0),
        443: (r"Server:\s*(.+?)(?:\r|$)", 0),
        8080: (r"Server:\s*(.+?)(?:\r|$)", 0),
    }

    _VERSION_BY_BANNER = {
        "ProFTPD": r"ProFTPD\s+([\d.]+)",
        "vsFTPd": r"vsFTPd\s+([\d.]+)",
        "OpenSSH": r"OpenSSH[_-]([\w.]+)",
        "Apache": r"Apache/([\d.]+)",
        "nginx": r"nginx/([\d.]+)",
        "Postfix": r"Postfix\s+([\w.]+)",
        "Microsoft-IIS": r"Microsoft-IIS/([\d.]+)",
        "pure-ftpd": r"pure-ftpd.*",
        "FileZilla": r"FileZilla.*",
    }

    def _parse_service_version(self, banner: str, port: int) -> str:
        """Extracts version string from banner text."""
        # Try port-specific regex first
        if port in self._VERSION_RE:
            pattern, group = self._VERSION_RE[port]
            m = re.search(pattern, banner)
            if m:
                ver = m.group(group + 1)
                if ver and not ver.isspace():
                    return ver.strip()

        # Try known service patterns across the banner
        for name, pattern in self._VERSION_BY_BANNER.items():
            m = re.search(pattern, banner, re.IGNORECASE)
            if m:
                return m.group(0)

        return ""

    def _save_results_to_database(self, target_ip: str, open_ports: List[Dict[str, Any]]):
        """
        Locates target device ID in SQLite database and commits port scan records.
        """
        # Search for device ID
        dev_records = self.db.execute_read("SELECT device_id FROM devices WHERE ip_address = ?", (target_ip,))
        if dev_records:
            device_id = dev_records[0]["device_id"]
        else:
            # Fallback: create device record if scanned IP was not previously discovered
            device_id = self.db.upsert_device(
                ip_address=target_ip,
                mac_address="",
                hostname="Unknown",
                vendor="Unknown",
                status="Online",
                response_time=0.0
            )

        if device_id:
            # Map parameters for DatabaseManager.save_port_scans compatibility
            scans = []
            for p in open_ports:
                scans.append({
                    "port": p["port"],
                    "protocol": p["protocol"],
                    "service": p["service"],
                    "state": p["state"],
                    "risk": p["risk"],
                    "banner": p.get("banner", ""),
                })
            self.db.save_port_scans(device_id, scans)
            logger.info(f"Saved {len(open_ports)} open port records to database for device ID {device_id}.")
