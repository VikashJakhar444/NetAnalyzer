"""
Packet Sniffer Module.
Captures live network packets on selected interfaces using Scapy, with pause, resume, and stop controls.
"""
import sys
import threading
import time
import re
import winreg
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
    from core.protocol_analyzer import ProtocolAnalyzer
except ImportError:
    from core.compat import DummyLogger
    logger = DummyLogger()
    SCAPY_AVAILABLE = False
    class ProtocolAnalyzer:
        @staticmethod
        def analyze(packet) -> Dict[str, Any]:
            return {"protocol": "IP", "info": "Raw IP packet", "src": "0.0.0.0", "dst": "0.0.0.0"}


class PacketSniffer:
    """
    Scapy-based live packet sniffer.
    Supports pause, resume, limits, and database writes.
    """

    def __init__(self):
        self.db = DatabaseManager()
        self.event_bus = EventBus()
        self.is_capturing = False
        self.is_paused = False
        self.captured_count = 0
        self.lock = threading.Lock()
        self._interface_map: Dict[str, str] = {}
        self._stop_event: Optional[threading.Event] = None
        self._packet_buffer: List[tuple] = []
        self._buffer_lock = threading.Lock()
        self._BATCH_SIZE = 50

    def _resolve_friendly_name(self, raw_iface: str) -> str:
        """Resolves a Windows interface GUID (from Scapy) to a friendly name via registry."""
        guid_match = re.search(r'\{([^}]+)\}', raw_iface)
        if not guid_match:
            return raw_iface
        guid = guid_match.group(1)
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                rf"SYSTEM\CurrentControlSet\Control\Network\{{4d36e972-e325-11ce-bfc1-08002be10318}}\{{{guid}}}\Connection"
            )
            name, _ = winreg.QueryValueEx(key, "Name")
            winreg.CloseKey(key)
            tag = self._detect_iface_type(name, guid)
            if tag == "[Loopback]":
                return "[Loopback]"
            return f"{name} {tag}"
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.debug(f"Failed to resolve interface name for {guid}: {e}")
        # fallback: strip raw iface down to just the GUID-based name
        return raw_iface.replace("\\Device\\NPF_", "")[:40]

    @staticmethod
    def _detect_iface_type(name: str, guid: str) -> str:
        """Detects interface type by name heuristics and registry PnpInstanceID."""
        name_lower = name.lower()
        if any(x in name_lower for x in ("loopback", "lo")):
            return "[Loopback]"
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                rf"SYSTEM\CurrentControlSet\Control\Network\{{4d36e972-e325-11ce-bfc1-08002be10318}}\{{{guid}}}\Connection"
            )
            try:
                pnp, _ = winreg.QueryValueEx(key, "PnpInstanceID")
            except FileNotFoundError:
                pnp = ""
            winreg.CloseKey(key)
            pnp_lower = (pnp or "").lower()
            if "ROOT" in (pnp or "").upper():
                return "[Virtual]"
            if "SWD" in (pnp or "").upper():
                return "[Software]"
            if any(x in pnp_lower for x in ("vwifi", "vms", "hyper", "vmware")):
                return "[Virtual]"
            if any(x in pnp_lower for x in ("tap", "tun", "vpn", "openvpn",
                    "wireguard", "tailscale", "zerotier", "nordvpn", "protonvpn")):
                return "[VPN/Tunnel]"
            if any(x in pnp_lower for x in ("docker", "wsl")):
                return "[Virtual]"
        except Exception:
            pass
        if any(x in name_lower for x in ("wi-fi", "wireless", "wlan", "802.11")):
            return "[Wi-Fi]"
        if any(x in name_lower for x in ("ethernet", "lan", "gigabit")):
            return "[Ethernet]"
        if "bluetooth" in name_lower:
            return "[Bluetooth]"
        if any(x in name_lower for x in ("tap", "tun", "vpn", "openvpn",
                "wireguard", "tailscale", "zerotier", "nordvpn", "protonvpn")):
            return "[VPN/Tunnel]"
        if any(x in name_lower for x in ("docker", "wsl", "hyper-v", "hyperv")):
            return "[Virtual]"
        if any(x in name_lower for x in ("ndis", "wanc", "ras")):
            return "[Software]"
        if "*" in name:
            return "[Virtual]"
        return "[Unknown]"

    def get_interfaces(self) -> List[str]:
        """
        Retrieves list of network interfaces with friendly display names.
        Stores raw Scapy GUIDs mapped to friendly names for capture use.
        """
        if not SCAPY_AVAILABLE:
            return ["Loopback (Scapy Not Available)"]

        self._interface_map.clear()
        interfaces = []
        try:
            iface_list = scapy.get_if_list()
            for raw_iface in iface_list:
                raw = str(raw_iface)
                friendly = self._resolve_friendly_name(raw)
                self._interface_map[friendly] = raw
                interfaces.append(friendly)

            if not interfaces:
                fallback = str(scapy.conf.iface) if scapy.conf.iface else "Ethernet"
                interfaces.append(fallback)
                self._interface_map[fallback] = fallback
        except Exception as e:
            logger.error(f"Error listing network interfaces: {e}")
            interfaces = ["Ethernet"]
            self._interface_map["Ethernet"] = "Ethernet"

        # Deduplicate loopback — keep only one
        lb_count = 0
        filtered = []
        for iface in interfaces:
            if iface == "[Loopback]":
                lb_count += 1
                if lb_count == 1:
                    filtered.append(iface)
            else:
                filtered.append(iface)
        interfaces = filtered

        # Sort: real network first, then virtual, loopback last
        def _priority(iface: str) -> int:
            if "[Wi-Fi]" in iface or "[Ethernet]" in iface:
                return 0
            if "[Bluetooth]" in iface:
                return 1
            if "[VPN/Tunnel]" in iface:
                return 2
            if "[Virtual]" in iface or "[Software]" in iface:
                return 3
            if "[Unknown]" in iface:
                return 4
            if "[Loopback]" in iface:
                return 5
            return 6
        interfaces.sort(key=_priority)
        return interfaces

    def start_capture(self, interface_name: str, packet_limit: int = 1000, stop_event: Optional[threading.Event] = None):
        """
        Captures raw packets on a background thread.
        Utilizes a stop_filter callback checking stop_event to terminate Scapy sniff loop gracefully.
        """
        with self.lock:
            if self.is_capturing:
                logger.warning("Packet sniffing already active. Request ignored.")
                return
            self.is_capturing = True
            self.is_paused = False
            self.captured_count = 0
            self._stop_event = stop_event

        self.event_bus.publish("SNIFFER_STARTED", interface_name)
        logger.info(f"Packet sniffer started on interface: {interface_name} (Limit: {packet_limit})")

        # Resolve raw Scapy GUID from friendly display name
        iface = self._interface_map.get(interface_name, interface_name)

        def scapy_packet_callback(packet):
            """Processes each packet captured by the Scapy sniff loop."""
            if self.is_paused:
                return

            try:
                self.captured_count += 1
                
                # Analyze protocol signatures
                analysis = ProtocolAnalyzer.analyze(packet)
                
                # Extract details
                length = len(packet)
                source_ip = analysis.get("src", "Unknown")
                destination_ip = analysis.get("dst", "Unknown")
                protocol = analysis.get("protocol", "Unknown")
                info = analysis.get("info", "")

                # Buffer packet for batch DB write
                record = (source_ip, destination_ip, protocol, length, info)
                with self._buffer_lock:
                    self._packet_buffer.append(record)

                # Flush buffer when batch size reached
                if len(self._packet_buffer) >= self._BATCH_SIZE:
                    self._flush_buffer()

                # Dispatch captured event payload to EventBus UI listeners
                packet_data = {
                    "timestamp": time.strftime("%H:%M:%S"),
                    "source": source_ip,
                    "destination": destination_ip,
                    "protocol": protocol,
                    "length": length,
                    "info": info
                }
                self.event_bus.publish("PACKET_CAPTURED", packet_data)

            except Exception as ex:
                logger.debug(f"Error handling captured packet callback: {ex}")

        def stop_check_filter(packet) -> bool:
            """
            Scapy sniff stop callback. Returning True signals Scapy to close the socket immediately.
            """
            if stop_event and stop_event.is_set():
                logger.info("Signal received to stop sniffer loop.")
                return True
            if self.captured_count >= packet_limit:
                logger.info(f"Packet sniffer limit ({packet_limit}) reached. Stopping capture.")
                return True
            return False

        try:
            if not SCAPY_AVAILABLE:
                raise ImportError("Scapy packet capture is unavailable (Npcap not installed or not running as Administrator).")

            # Loop with 3s idle timeout so stop_filter is checked regularly
            # even on silent networks. Active traffic keeps sniff alive.
            while not (stop_event and stop_event.is_set()) and self.captured_count < packet_limit:
                scapy.sniff(
                    iface=iface,
                    prn=scapy_packet_callback,
                    stop_filter=stop_check_filter,
                    store=False,
                    promisc=True,
                    timeout=3
                )
                # Flush buffered packets between sniff iterations
                self._flush_buffer()
                # Enforce storage limits periodically
                if self.captured_count % 100 == 0:
                    self.db.clean_old_packets(max_limit=packet_limit)

        except Exception as e:
            logger.error(f"Error executing packet capture loop: {e}")
            self.event_bus.publish("SNIFFER_ERROR", str(e))
        finally:
            self._flush_buffer()  # final flush before stop
            self.is_capturing = False
            self.event_bus.publish("SNIFFER_FINISHED", self.captured_count)
            logger.info(f"Packet capture completed. Logged {self.captured_count} packets.")

    def _flush_buffer(self):
        """Flush buffered packets to database in single batch write."""
        with self._buffer_lock:
            if not self._packet_buffer:
                return
            batch = self._packet_buffer[:]
            self._packet_buffer.clear()
        try:
            queries = [
                ("INSERT INTO packets (source_ip, destination_ip, protocol, length, information) VALUES (?, ?, ?, ?, ?)", rec)
                for rec in batch
            ]
            self.db.execute_bulk_write(queries)
        except Exception as ex:
            logger.debug(f"Buffer flush error: {ex}")

    def stop_capture(self):
        """Request to stop capture by signaling the internal stop event."""
        if self._stop_event is not None:
            self._stop_event.set()

    def pause_capture(self):
        """Temporarily discards incoming packets in the callback without closing socket."""
        self.is_paused = True
        logger.info("Sniffer capture paused.")

    def resume_capture(self):
        """Resumes processing of packet callbacks."""
        self.is_paused = False
        logger.info("Sniffer capture resumed.")
