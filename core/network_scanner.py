"""
Network Scanner Module.
Discovers active devices on a local subnet using Scapy ARP sweeps and socket-based TCP ping fallbacks.
"""
import concurrent.futures
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import List, Dict, Any, Optional

# Setup import compatibility for testing and main execution
try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    from core.logger import logger
    from core.database import DatabaseManager
    from core.event_bus import EventBus
    from core.vendor_lookup import VendorLookup
except ImportError:
    from core.compat import DummyLogger
    logger = DummyLogger()
    SCAPY_AVAILABLE = False


# OUI cache file for online vendor resolution
OUI_CACHE_PATH = Path(__file__).resolve().parent.parent / "data" / "oui_cache.json"

# Port-based device type signatures
DEVICE_TYPE_SIGNATURES = [
    (("Apple",), {62078}, "Apple Device"),
    (("Google", "Pixel"), {5555}, "Android Device"),
    (("Samsung",), {5555}, "Samsung Mobile"),
    (("OnePlus",), {5555}, "OnePlus Device"),
    (("Xiaomi",), {5555}, "Xiaomi Device"),
    (("Huawei",), {5555, 3724}, "Huawei Device"),
    (tuple(), {139, 445}, "Windows Device"),
    (tuple(), {22, 23}, "Network Device"),
    (tuple(), {80, 443, 8080}, "Web Server"),
    (tuple(), {53}, "DNS Server"),
    (tuple(), {21}, "FTP Server"),
    (tuple(), {25, 587}, "Mail Server"),
    (tuple(), {515, 631, 9100}, "Printer"),
    (tuple(), {5060, 5061}, "VoIP Phone"),
    (tuple(), {1883, 8883}, "IoT Device"),
    (tuple(), {1900, 5353}, "Media Device"),
    (tuple(), {502, 44818, 47808}, "Industrial Device"),
    (tuple(), {554, 1935, 32400}, "Media Streamer"),
    (tuple(), {548, 2049}, "NAS Storage"),
]


def _load_oui_cache() -> Dict[str, str]:
    try:
        with open(OUI_CACHE_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_oui_cache(cache: Dict[str, str]):
    try:
        os.makedirs(os.path.dirname(OUI_CACHE_PATH), exist_ok=True)
        with open(OUI_CACHE_PATH, 'w') as f:
            json.dump(cache, f)
    except Exception:
        pass


def _classify_device(vendor: str, mac: str, open_ports: list) -> str:
    """Determine device type from vendor, MAC, and open ports."""
    port_set = set(open_ports)
    v = vendor.upper() if vendor else ""

    for sig_vendors, sig_ports, label in DEVICE_TYPE_SIGNATURES:
        if sig_ports and sig_ports.issubset(port_set):
            if not sig_vendors:
                return label
            for sv in sig_vendors:
                if sv.upper() in v:
                    return label

    # Privacy MAC → mobile
    if mac and len(mac) >= 8:
        try:
            if int(mac[1], 16) & 0x02:
                return "Mobile"
        except ValueError:
            pass

    # Router: common router ports
    if 80 in port_set or 443 in port_set or 8080 in port_set:
        return "Router" if len(port_set) <= 5 else "Server"

    return ""


class NetworkScanner:
    """
    Scans the local IPv4 subnet to identify online hosts.
    Resolves Hostnames, MAC addresses, and vendor details.
    """

    def __init__(self):
        self.db = DatabaseManager()
        self.event_bus = EventBus()
        self.is_scanning = False
        self.lock = threading.Lock()

    def scan_subnet(self, subnet_cidr: str, scan_type: str = "Quick", target_ips: Optional[List[str]] = None, stop_event: Optional[threading.Event] = None) -> List[Dict[str, Any]]:
        """
        Public scanning entry point. Runs host discovery based on subnet_cidr.
        If target_ips is provided, scans only those specific IPs instead of the full subnet.
        Devices appear in the UI in real-time as they are discovered.
        """
        with self.lock:
            if self.is_scanning:
                logger.warning("Scan already in progress. Ignoring scan request.")
                return []
            self.is_scanning = True

        self.event_bus.publish("SCAN_STARTED", subnet_cidr)
        # Publish 0% progress immediately so the progress bar activates
        self.event_bus.publish("SCAN_PROGRESS", 0, 1)
        logger.info(f"Subnet discovery started on: {subnet_cidr} (Mode: {scan_type})")

        discovered_devices = []
        try:
            is_v6 = self._is_ipv6(subnet_cidr.split('/')[0]) if '/' in subnet_cidr else False
            if target_ips:
                hosts = [ipaddress.ip_address(ip.strip()) for ip in target_ips if ip.strip()]
            else:
                net = ipaddress.ip_network(subnet_cidr.strip(), strict=False)
                hosts = list(net.hosts())

            if not hosts:
                logger.warning(f"No valid hosts found in subnet range: {subnet_cidr}")
                self.is_scanning = False
                self.event_bus.publish("SCAN_FINISHED", [])
                return []

            def _publish_device(device: dict):
                """Save to DB + publish event so UI shows device immediately."""
                if stop_event and stop_event.is_set():
                    return
                hostname = device.get("hostname", "")
                vendor = device.get("vendor", "")
                mac = device.get("mac_address", "")
                ip = device.get("ip_address", "")
                open_ports = device.get("open_ports", [])

                # Local OUI cache lookup (no blocking HTTP call in hot path)
                if not vendor or vendor == "Unknown":
                    oui = mac[:8].upper() if mac and len(mac) >= 8 else ""
                    if oui:
                        try:
                            cache = _load_oui_cache()
                            if oui in cache and cache[oui]:
                                vendor = cache[oui]
                                device["vendor"] = vendor
                        except Exception:
                            pass

                # Determine gateway IP from system routing table
                gateway_ip = ""
                try:
                    if is_v6:
                        route_out = subprocess.run(
                            ["netsh", "interface", "ipv6", "show", "route"],
                            capture_output=True, text=True, timeout=2,
                            startupinfo=subprocess.STARTUPINFO(dwFlags=subprocess.STARTF_USESHOWWINDOW)
                        ).stdout
                        for line in route_out.splitlines():
                            if "::/0" in line:
                                parts = line.split()
                                for p in parts:
                                    try:
                                        ipaddress.IPv6Address(p)
                                        if p.startswith("fe80") or p.startswith("fd"):
                                            gateway_ip = p
                                            break
                                    except Exception:
                                        pass
                                if gateway_ip:
                                    break
                    else:
                        route_out = subprocess.run(
                            ["route", "print", "0.0.0.0"],
                            capture_output=True, text=True, timeout=2,
                            startupinfo=subprocess.STARTUPINFO(dwFlags=subprocess.STARTF_USESHOWWINDOW)
                        ).stdout
                        for line in route_out.splitlines():
                            if "0.0.0.0" in line and "0.0.0.0" in line.split()[:2]:
                                parts = line.split()
                                if len(parts) >= 3:
                                    gw = parts[2]
                                    try:
                                        ipaddress.IPv4Address(gw)
                                        gateway_ip = gw
                                    except Exception:
                                        pass
                                    break
                except Exception:
                    pass

                is_gateway = ip == gateway_ip
                is_privacy = False
                if mac and len(mac) >= 8:
                    try:
                        is_privacy = bool(int(mac[1], 16) & 0x02)
                    except ValueError:
                        pass

                # OS fingerprint (TTL from ping) — skip if already set
                os_type = device.get("os_type", "")
                if not os_type:
                    os_type = self._fingerprint_os(ip)

                # Banner grab on first open HTTP port — skip if already set
                banner = device.get("banner", "")
                if not banner:
                    for bp in (80, 8080, 8443, 443):
                        if bp in open_ports:
                            b = self._grab_banner(ip, bp)
                            if b:
                                banner = b.split()[0] if b else b
                                break

                # Classify device type from ports + vendor + OS
                device_type = _classify_device(vendor, mac, open_ports)

                # Build ultimate display hostname
                if not hostname or hostname == "Unknown" or hostname == ip:
                    if device_type:
                        hostname = device_type
                    elif os_type and not is_gateway:
                        hostname = os_type
                    elif is_gateway:
                        hostname = "Router"
                    elif is_privacy:
                        hostname = "Mobile"
                    elif vendor and vendor not in ("Unknown", "Private/Randomized") and vendor != ip:
                        hostname = vendor
                    elif banner:
                        hostname = banner
                    else:
                        hostname = ip

                dev_id = self.db.upsert_device(
                    ip_address=ip,
                    mac_address=mac,
                    hostname=hostname,
                    vendor=vendor,
                    status="Online",
                    response_time=device["response_time"]
                )
                device["device_id"] = dev_id
                device["hostname"] = hostname
                device["vendor"] = vendor
                self.event_bus.publish("DEVICE_DISCOVERED", device)

            # Perform scan
            total_hosts = len(hosts)

            use_arp = SCAPY_AVAILABLE and not is_v6
            if use_arp and scan_type == "Quick":
                discovered_devices = self._arp_scan_scapy(subnet_cidr, stop_event)
                total_found = len(discovered_devices)
                _arp_lock = threading.Lock()
                _arp_done = [0]
                def _process_arp(d):
                    if stop_event and stop_event.is_set():
                        return
                    d["hostname"] = self._resolve_device_name(d["ip_address"])
                    d["vendor"] = VendorLookup.lookup(d["mac_address"])
                    d["open_ports"] = self._quick_port_probe(d["ip_address"])
                    _publish_device(d)
                    if total_found:
                        with _arp_lock:
                            _arp_done[0] += 1
                            pct = int(_arp_done[0] / total_found * 100)
                        self.event_bus.publish("SCAN_PROGRESS", pct, total_hosts)
                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as _arp_pool:
                    list(_arp_pool.map(_process_arp, discovered_devices))
            elif use_arp and scan_type == "Full":
                arp_devices = self._arp_scan_scapy(subnet_cidr, stop_event)
                arp_ips = {d["ip_address"] for d in arp_devices}
                remaining = [h for h in hosts if str(h) not in arp_ips]
                total_remaining = len(remaining)
                _full_arp_lock = threading.Lock()
                _full_done = [0]
                def _process_full_arp(d):
                    if stop_event and stop_event.is_set():
                        return d
                    d["hostname"] = self._resolve_device_name(d["ip_address"])
                    d["vendor"] = VendorLookup.lookup(d["mac_address"])
                    d["open_ports"] = self._quick_port_probe(d["ip_address"])
                    _publish_device(d)
                    with _full_arp_lock:
                        _full_done[0] += 1
                        arp_pct = int(_full_done[0] / total_hosts * 100)
                    self.event_bus.publish("SCAN_PROGRESS", arp_pct, total_hosts)
                    return d
                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as _full_arp_pool:
                    arp_processed = list(_full_arp_pool.map(_process_full_arp, arp_devices))
                    discovered_devices.extend(arp_processed)

                # Socket sweep remaining IPs — publishes per-device as found
                if remaining:
                    socket_devices = self._socket_ping_sweep(remaining, stop_event, on_device_found=_publish_device)
                    discovered_devices.extend(socket_devices)
            else:
                # Fallback: ARP (if available and IPv4) → socket sweep
                if use_arp:
                    arp_fallback = self._arp_scan_scapy(subnet_cidr, stop_event)
                    if arp_fallback:
                        total_found = len(arp_fallback)
                        _fb_lock = threading.Lock()
                        _fb_done = [0]
                        def _process_fallback(d):
                            if stop_event and stop_event.is_set():
                                return d
                            d["hostname"] = self._resolve_device_name(d["ip_address"])
                            d["vendor"] = VendorLookup.lookup(d["mac_address"])
                            d["open_ports"] = self._quick_port_probe(d["ip_address"])
                            _publish_device(d)
                            if total_found:
                                with _fb_lock:
                                    _fb_done[0] += 1
                                    pct = int(_fb_done[0] / total_found * 100)
                                self.event_bus.publish("SCAN_PROGRESS", pct, total_hosts)
                            return d
                        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as _fb_pool:
                            discovered_devices = list(_fb_pool.map(_process_fallback, arp_fallback))
                if not discovered_devices:
                    discovered_devices = self._socket_ping_sweep(hosts, stop_event, on_device_found=_publish_device)

            logger.info(f"Subnet scan completed. Discovered {len(discovered_devices)} active devices.")

        except Exception as e:
            logger.error(f"Error executing subnet scan: {e}")
            self.event_bus.publish("SCAN_ERROR", str(e))
        finally:
            self.is_scanning = False
            self.event_bus.publish("SCAN_FINISHED", discovered_devices)

        return discovered_devices

    def _arp_scan_scapy(self, subnet_cidr: str, stop_event: Optional[threading.Event]) -> List[Dict[str, Any]]:
        """
        Performs high-speed ARP scanning using Scapy library (IPv4 only).
        For IPv6 subnets, falls through to socket-based discovery.
        Requires Admin rights and active Npcap loopback/network driver.
        """
        if self._is_ipv6(subnet_cidr.split('/')[0]):
            logger.info("IPv6 subnet detected — skipping ARP, using socket ping sweep.")
            net = ipaddress.ip_network(subnet_cidr.strip(), strict=False)
            return self._socket_ping_sweep(list(net.hosts()), stop_event)

        logger.info("Initiating Scapy ARP discovery sweep.")
        devices = []
        try:
            # Construct ARP frame
            arp_request = scapy.ARP(pdst=subnet_cidr)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_packet = broadcast / arp_request
            
            # Send ARP request and receive answers
            answered_list, _ = scapy.srp(arp_packet, timeout=2, verbose=False, retry=1)
            
            for sent, received in answered_list:
                if stop_event and stop_event.is_set():
                    break
                
                # Measure round-trip time approximation
                rtt = received.time - sent.sent_time
                if rtt < 0:
                    rtt = 0.001
                
                devices.append({
                    "ip_address": received.psrc,
                    "mac_address": received.hwsrc.lower(),
                    "response_time": round(rtt, 4),
                    "hostname": "",
                    "vendor": "",
                    "status": "Online",
                    "open_ports": [],
                    "os_type": "",
                    "banner": "",
                })
        except Exception as e:
            logger.warning(f"Scapy ARP scan failed: {e}. Falling back to socket ping sweep.")
            # If Scapy fails, fall back to socket sweep automatically
            net = ipaddress.ip_network(subnet_cidr.strip(), strict=False)
            return self._socket_ping_sweep(list(net.hosts()), stop_event)

        return devices

    def _socket_ping_sweep(self, hosts: List, stop_event: Optional[threading.Event],
                          on_device_found: Optional[callable] = None) -> List[Dict[str, Any]]:
        """
        Optimized host discovery with tiered probing:
        1. ICMP ping (fast, 500ms per host)
        2. Top 10 TCP ports (fast, 100ms per port)
        3. UDP probe (top 5 ports, 300ms per port)
        4. Extended TCP (remaining ports, 150ms) — only if ICMP succeeded
        Calls on_device_found(device) per-device for real-time UI updates.
        Supports both IPv4 and IPv6 addresses.
        """
        total = len(hosts)
        logger.info(f"Initiating optimized host discovery across {total} hosts.")
        devices = []
        results_lock = threading.Lock()
        completed = [0]
        last_progress_pct = [0]
        self.event_bus.publish("SCAN_PROGRESS", 0, total)

        system_arp_table = self._read_system_arp_table()

        FAST_TCP_PORTS = [80, 443, 22, 445, 3389, 8080, 135, 139, 53, 21]
        EXTRA_TCP_PORTS = [
            23, 25, 110, 143, 389, 993, 995, 1433, 1521, 1723, 2049, 3306,
            5432, 5900, 6379, 8443, 27017, 1883, 502, 5060, 5061, 515, 631,
            9100, 548, 554, 636, 111, 587, 465,
        ]
        UDP_PORTS = [53, 137, 5353, 1900, 161]

        TCP_TIMEOUT = 0.1
        FULL_TCP_TIMEOUT = 0.15

        def _tcp_probe(ip: str, ports: list, timeout: float) -> tuple:
            open_found = []
            family = socket.AF_INET6 if self._is_ipv6(ip) else socket.AF_INET
            for port in ports:
                if stop_event and stop_event.is_set():
                    return False, []
                try:
                    sock = socket.socket(family, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    result = sock.connect_ex((ip, port))
                    sock.close()
                    if result == 0:
                        open_found.append(port)
                except Exception:
                    pass
            return bool(open_found), open_found

        def _udp_probe(ip: str) -> bool:
            family = socket.AF_INET6 if self._is_ipv6(ip) else socket.AF_INET
            for port in UDP_PORTS:
                if stop_event and stop_event.is_set():
                    return False
                try:
                    sock = socket.socket(family, socket.SOCK_DGRAM)
                    sock.settimeout(0.3)
                    sock.sendto(b"\x00" * 1, (ip, port))
                    try:
                        sock.recvfrom(256)
                        sock.close()
                        return True
                    except socket.timeout:
                        pass
                    sock.close()
                except Exception:
                    pass
            return False

        def probe_host(ip: str):
            if stop_event and stop_event.is_set():
                return

            start_time = time.time()
            online = False
            open_ports = []

            online = self._ping_host_os(ip)

            if not online:
                online, open_ports = _tcp_probe(ip, FAST_TCP_PORTS, TCP_TIMEOUT)

            if not online:
                online = _udp_probe(ip)

            if online:
                extra_ports = []
            else:
                online, extra_ports = _tcp_probe(ip, EXTRA_TCP_PORTS, FULL_TCP_TIMEOUT)
            if extra_ports:
                open_ports.extend(extra_ports)

            if online:
                rtt = time.time() - start_time
                mac = system_arp_table.get(ip, "")

                if not mac and not ipaddress.ip_address(ip).is_loopback:
                    mac = self._get_arp_mac(ip)

                if not mac and not ipaddress.ip_address(ip).is_loopback:
                    if open_ports:
                        mac = ""
                    else:
                        return

                device = {
                    "ip_address": ip,
                    "mac_address": mac.lower(),
                    "response_time": round(rtt, 4),
                    "hostname": "",
                    "vendor": "",
                    "status": "Online",
                    "open_ports": open_ports,
                }

                device["hostname"] = self._resolve_device_name(ip)
                device["vendor"] = VendorLookup.lookup(device["mac_address"])

                # OS fingerprint + banner grab for socket-discovered devices
                if not device.get("os_type"):
                    device["os_type"] = self._fingerprint_os(ip)
                if not device.get("banner") and open_ports:
                    for bp in (80, 8080, 8443, 443, 22, 21):
                        if bp in open_ports:
                            b = self._grab_banner(ip, bp)
                            if b:
                                device["banner"] = b
                                break

                # Retry MAC lookup after all probes have populated ARP/ND cache
                if not device["mac_address"] and not ipaddress.ip_address(ip).is_loopback:
                    mac = self._get_arp_mac(ip)
                    if mac:
                        device["mac_address"] = mac
                        device["vendor"] = VendorLookup.lookup(mac)

                with results_lock:
                    devices.append(device)

                if on_device_found:
                    on_device_found(device)

        with concurrent.futures.ThreadPoolExecutor(max_workers=80) as executor:
            futures = {
                executor.submit(probe_host, str(host)): host
                for host in hosts
            }
            for future in concurrent.futures.as_completed(futures):
                if stop_event and stop_event.is_set():
                    for f in futures:
                        f.cancel()
                    break
                future.result()
                completed[0] += 1
                pct = int(completed[0] * 100 / total)
                if pct - last_progress_pct[0] >= 1:
                    last_progress_pct[0] = pct
                    self.event_bus.publish("SCAN_PROGRESS", completed[0], total)

        return devices

    @staticmethod
    def _validate_ip(ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except (ValueError, ipaddress.AddressValueError):
            return False

    @staticmethod
    def _is_ipv6(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).version == 6
        except (ValueError, ipaddress.AddressValueError):
            return False

    def _ping_host_os(self, ip: str) -> bool:
        """Sends a single system ping packet to check if the host is reachable."""
        if not self._validate_ip(ip):
            return False
        try:
            # -n 1 sends 1 packet, -w 500 sets timeout to 500ms
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW  # Prevent console window popping up
            
            output = subprocess.run(
                ["ping", "-n", "1", "-w", "500", ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                startupinfo=startupinfo,
                timeout=1.0
            )
            return output.returncode == 0
        except Exception:
            return False

    def _quick_port_probe(self, ip: str) -> list:
        """Quickly probe a few key ports to detect device type. Returns list of open ports."""
        if not self._validate_ip(ip):
            return []
        detection_ports = [80, 443, 22, 23, 21, 139, 445, 3389, 8080, 8443,
                           62078, 5555, 5060, 515, 631, 1883, 1900, 53, 548, 2049]
        open_ports = []
        family = socket.AF_INET6 if self._is_ipv6(ip) else socket.AF_INET
        for port in detection_ports:
            try:
                sock = socket.socket(family, socket.SOCK_STREAM)
                sock.settimeout(0.15)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
                sock.close()
            except Exception:
                pass
        return open_ports

    def _fingerprint_os(self, ip: str) -> str:
        """Detect OS family from ping TTL + TCP probes."""
        if not self._validate_ip(ip):
            return ""
        os_guess = ""
        try:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            output = subprocess.run(
                ["ping", "-n", "1", ip],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                startupinfo=startupinfo, timeout=2, text=True
            )
            m = re.search(r"TTL=(\d+)", output.stdout)
            if m:
                ttl = int(m.group(1))
                if ttl >= 120 and ttl <= 130:
                    os_guess = "Windows"
                elif ttl >= 50 and ttl <= 70:
                    os_guess = "Linux/Unix"
                elif ttl >= 240 and ttl <= 260:
                    os_guess = "Router/Network"
        except Exception:
            pass
        return os_guess

    def _grab_banner(self, ip: str, port: int, timeout: float = 1.0) -> str:
        """Grab service banner from an open port. Supports both IPv4 and IPv6."""
        if not self._validate_ip(ip):
            return ""
        sock = None
        try:
            family = socket.AF_INET6 if self._is_ipv6(ip) else socket.AF_INET
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            banner = b""
            if port in (80, 443, 8080, 8443):
                host_header = f"[{ip}]" if self._is_ipv6(ip) else ip
                sock.send(f"GET / HTTP/1.0\r\nHost: {host_header}\r\n\r\n".encode())
            try:
                banner = sock.recv(1024)
            except socket.timeout:
                pass
            if banner:
                parts = []
                cur = []
                for b in banner:
                    if 0x20 <= b <= 0x7E:
                        cur.append(chr(b))
                    else:
                        if len(cur) >= 3:
                            parts.append(''.join(cur))
                        cur = []
                if len(cur) >= 3:
                    parts.append(''.join(cur))
                text = ' '.join(parts)
                if port in (80, 443, 8080, 8443):
                    sm = re.search(r'Server:\s*(.+?)\r?\n', text, re.IGNORECASE)
                    if sm:
                        return sm.group(1).strip()
                elif port == 21:
                    return text.split('\r\n')[0].strip()
                elif port == 22:
                    return text.split('\n')[0].strip()
                elif port == 25:
                    return text.split('\n')[0].strip()
                elif port in (110, 143, 993, 995):
                    return text.split('\n')[0].strip()
                return text.split('\n')[0].strip()[:80]
        except Exception:
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
        return ""

    def _resolve_oui_online(self, mac: str) -> str:
        """Resolve vendor from MAC OUI via online API, with local caching."""
        if not mac or len(mac) < 8:
            return ""
        oui = mac[:8].upper()
        if not re.match(r'^[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}$', oui):
            return ""
        cache = _load_oui_cache()
        if oui in cache:
            return cache[oui]
        try:
            url = f"https://api.macvendors.com/{oui}"
            req = urllib.request.Request(url, headers={'User-Agent': 'NetworkAnalyzer/1.0'})
            with urllib.request.urlopen(req, timeout=3, context=ssl.create_default_context()) as resp:
                if resp.status == 200:
                    vendor = resp.read().decode().strip()
                    if vendor:
                        vendor = re.sub(r'[^\x20-\x7E]', '', vendor)[:128]
                        cache[oui] = vendor
                        _save_oui_cache(cache)
                        logger.info(f"Online OUI: {oui} → {vendor}")
                        return vendor
        except Exception as e:
            logger.debug(f"Online OUI lookup failed for {oui}: {e}")
        cache[oui] = ""
        _save_oui_cache(cache)
        return ""

    def _resolve_device_name(self, ip: str) -> str:
        """Resolves device name using multiple methods: NetBIOS (IPv4) → Reverse DNS → mDNS."""
        if not self._validate_ip(ip):
            return ""
        if not self._is_ipv6(ip):
            name = self._resolve_netbios_name(ip)
            if name:
                return name
        name = self._resolve_hostname(ip)
        if name and name != "Unknown":
            return name
        name = self._resolve_mdns(ip)
        if name:
            return name
        return "Unknown"

    def _resolve_mdns(self, ip: str) -> str:
        """Resolves hostname via mDNS (Bonjour) — for Apple, Android, IoT devices. Supports IPv6."""
        if not self._validate_ip(ip):
            return ""
        import struct
        import random
        is_v6 = self._is_ipv6(ip)
        for attempt_class in (0x8001, 0x0001):
            try:
                if is_v6:
                    addr = ipaddress.IPv6Address(ip)
                    nibbles = addr.exploded.replace(':', '')
                    rev_name = '.'.join(reversed(nibbles)) + '.ip6.arpa'
                    mcast_addr = 'ff02::fb'
                    family = socket.AF_INET6
                else:
                    parts = ip.split('.')
                    rev_name = '.'.join(reversed(parts)) + '.in-addr.arpa'
                    mcast_addr = '224.0.0.251'
                    family = socket.AF_INET
                tid = random.randint(0, 0xFFFF)
                qname = b''
                for label in rev_name.split('.'):
                    qname += bytes([len(label)]) + label.encode()
                qname += b'\x00'
                header = struct.pack('!HHHHHH', tid, 0x0100, 1, 0, 0, 0)
                question = qname + struct.pack('!HH', 12, attempt_class)
                packet = header + question
                sock = socket.socket(family, socket.SOCK_DGRAM)
                sock.settimeout(1.0)
                try:
                    if is_v6:
                        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 2)
                    else:
                        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
                except Exception:
                    pass
                sock.sendto(packet, (mcast_addr, 5353))
                try:
                    data, addr = sock.recvfrom(4096)
                except socket.timeout:
                    sock.close()
                    continue
                idx = 12
                max_iters = 100
                iters = 0
                while idx < len(data) and iters < max_iters:
                    iters += 1
                    if data[idx] & 0xC0:
                        idx += 2; break
                    elif data[idx] == 0:
                        idx += 1; break
                    else:
                        lbl_len = data[idx]
                        if idx + 1 + lbl_len > len(data):
                            break
                        idx += lbl_len + 1
                idx += 4
                while idx < len(data) and iters < max_iters:
                    iters += 1
                    while idx < len(data) and iters < max_iters:
                        iters += 1
                        if data[idx] & 0xC0:
                            idx += 2; break
                        elif data[idx] == 0:
                            idx += 1; break
                        else:
                            lbl_len = data[idx]
                            if idx + 1 + lbl_len > len(data):
                                break
                            idx += lbl_len + 1
                    if idx + 10 > len(data): break
                    atype, aclass, ttl, rdlen = struct.unpack('!HHIH', data[idx:idx+10])
                    idx += 10
                    if idx + rdlen > len(data): break
                    if atype == 12:
                        ptr_idx = idx
                        target_parts = []
                        ptr_iters = 0
                        while ptr_idx < idx + rdlen and ptr_iters < max_iters:
                            ptr_iters += 1
                            if data[ptr_idx] & 0xC0:
                                ptr_idx += 2; break
                            elif data[ptr_idx] == 0:
                                ptr_idx += 1; break
                            else:
                                lbl_len = data[ptr_idx]
                                if ptr_idx + 1 + lbl_len > len(data):
                                    break
                                target_parts.append(data[ptr_idx+1:ptr_idx+1+lbl_len].decode('utf-8', errors='ignore'))
                                ptr_idx += lbl_len + 1
                        if target_parts:
                            sock.close()
                            hn = '.'.join(target_parts).rstrip('.')
                            if hn.endswith('.local'):
                                hn = hn[:-6]
                            return hn
                    idx += rdlen
                sock.close()
            except Exception:
                pass
        return ""

    def _resolve_netbios_name(self, ip: str) -> str:
        """Resolves NetBIOS name table via nbtstat (Windows, IPv4 only)."""
        if not self._validate_ip(ip) or self._is_ipv6(ip):
            return ""
        try:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            output = subprocess.run(
                ["nbtstat", "-A", ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                startupinfo=startupinfo,
                timeout=2.0,
                text=True,
            )
            if output.returncode != 0:
                return ""
            for line in output.stdout.splitlines():
                if "<00>" in line and "UNIQUE" in line:
                    parts = line.strip().split()
                    if parts:
                        return parts[0]
        except Exception:
            pass
        return ""

    def _resolve_hostname(self, ip: str) -> str:
        """Resolves hostname via reverse DNS lookup with 2s timeout."""
        if not self._validate_ip(ip):
            return ""
        def _dns_lookup(ip):
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                fut = pool.submit(_dns_lookup, ip)
                hostname = fut.result(timeout=2.0)
            return hostname
        except concurrent.futures.TimeoutError:
            return "Unknown"
        except Exception:
            return "Unknown"

    def _read_system_arp_table(self) -> Dict[str, str]:
        """
        Parses the OS local ARP table (`arp -a`) to retrieve MAC addresses.
        Also reads IPv6 neighbor cache for MAC-to-IPv6 mappings.
        """
        arp_cache = {}
        try:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            
            output = subprocess.check_output(["arp", "-a"], startupinfo=startupinfo, text=True, errors="ignore")
            # Parse arp -a entries (IPv4 + IPv6 on Windows 10/11)
            # IPv4 pattern
            ipv4_pattern = r"\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s+([0-9a-fA-F-]{17})"
            for ip, mac in re.findall(ipv4_pattern, output):
                arp_cache[ip] = mac.replace("-", ":").lower()
            # IPv6 pattern (arp -a on Windows also shows IPv6 neighbors)
            ipv6_pattern = r"\s*([0-9a-fA-F:]+%?\d*)\s+([0-9a-fA-F-]{17})"
            for ip, mac in re.findall(ipv6_pattern, output):
                try:
                    ipaddress.IPv6Address(ip.split('%')[0])
                    arp_cache[ip] = mac.replace("-", ":").lower()
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"Failed to read system ARP/ND cache table: {e}")
        return arp_cache

    def _get_arp_mac(self, ip: str) -> str:
        """Reads MAC for a single IP from system ARP (IPv4) or ND cache (IPv6) after probe, with retry."""
        if not self._validate_ip(ip):
            return ""
        is_v6 = self._is_ipv6(ip)
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        for attempt in range(3):
            try:
                output = subprocess.check_output(
                    ["arp", "-a"], startupinfo=startupinfo, text=True, errors="ignore"
                )
                pattern = rf"\s*({re.escape(ip)})\s+([0-9a-fA-F-]{{17}})"
                m = re.search(pattern, output)
                if m:
                    return m.group(2).replace("-", ":").lower()
            except Exception:
                pass
            time.sleep(0.1)

        # Fallback: nbtstat for IPv4 only
        if not is_v6:
            try:
                output = subprocess.run(
                    ["nbtstat", "-A", ip],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    startupinfo=startupinfo, timeout=2, text=True,
                )
                m = re.search(r"MAC\s*Address\s*=\s*([0-9a-fA-F-]{17})", output.stdout)
                if m:
                    return m.group(1).replace("-", ":").lower()
            except Exception:
                pass
        return ""
