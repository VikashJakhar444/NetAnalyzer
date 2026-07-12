"""
Controller Module.
Mediates between the presentation layer (UI) and business logic layer.
Ensures all backend access goes through a single orchestration point.
"""
import os
import sys
import threading
from typing import Dict, Any, List, Optional

try:
    from core.network_scanner import NetworkScanner
    from core.port_scanner import PortScanner
    from core.packet_sniffer import PacketSniffer
    from core.protocol_analyzer import ProtocolAnalyzer
    from core.statistics_engine import StatisticsEngine
    from core.risk_engine import RiskEngine
    from core.report_generator import ReportGenerator
    from core.database import DatabaseManager
    from core.thread_manager import ThreadManager
    from core.event_bus import EventBus
    from core.validators import validate_ip, validate_network, validate_network_scope, validate_port
    from core.helpers import get_local_subnet, get_default_interface
    from core.vuln_checker import VulnerabilityChecker
    from core.logger import logger
except ImportError:
    from core.compat import DummyLogger
    logger = DummyLogger()


class Controller:
    """
    Central controller that coordinates all backend operations.
    UI pages use this controller instead of instantiating backend services directly.
    """

    def __init__(self):
        self.db = DatabaseManager()
        self.thread_mgr = ThreadManager()
        self.event_bus = EventBus()
        self.network_scanner = NetworkScanner()
        self.port_scanner = PortScanner()
        self.sniffer = PacketSniffer()
        self.stats = StatisticsEngine()
        self.risk = RiskEngine()
        self.reporter = ReportGenerator()
        self.vuln_checker = VulnerabilityChecker()
        # Purge old data beyond retention limits on startup
        self.db.clean_old_packets(max_limit=5000)
        self.db.clean_old_logs(max_limit=10000)

    # --- Network Scanner ---

    def start_subnet_scan(self, subnet_cidr: str, scan_type: str = "Quick", target_ips: Optional[List[str]] = None):
        """Validates and starts a subnet discovery scan in background thread."""
        if not validate_network(subnet_cidr):
            self.event_bus.publish("SCAN_ERROR", f"Invalid subnet: {subnet_cidr}")
            return False
        if not validate_network_scope(subnet_cidr):
            self.event_bus.publish("SCAN_ERROR", f"Subnet not in private range (RFC 1918 / RFC 4193): {subnet_cidr}")
            return False
        self.thread_mgr.start_worker(
            "subnet_scan",
            self.network_scanner.scan_subnet,
            args=(subnet_cidr, scan_type, target_ips)
        )
        return True

    def stop_subnet_scan(self):
        """Stops the subnet scan worker."""
        return self.thread_mgr.stop_worker("subnet_scan", timeout=2.0)

    # --- Port Scanner ---

    def start_port_scan(self, target_ip: str, scan_mode: str = "Quick", custom_ports: Optional[List[int]] = None, protocol: str = "TCP"):
        """Validates and starts a port scan in background thread."""
        if not validate_ip(target_ip):
            self.event_bus.publish("PORT_SCAN_ERROR", f"Invalid IP: {target_ip}")
            return False
        self.thread_mgr.start_worker(
            "port_scan",
            self.port_scanner.run_scan,
            args=(target_ip, scan_mode, custom_ports),
            kwargs={"protocol": protocol}
        )
        return True

    def stop_port_scan(self):
        """Stops the port scan worker."""
        return self.thread_mgr.stop_worker("port_scan", timeout=2.0)

    # --- Packet Sniffer ---

    def start_packet_capture(self, interface_name: str, packet_limit: int = 1000):
        """Starts live packet capture on selected interface."""
        self.thread_mgr.start_worker(
            "packet_sniff",
            self.sniffer.start_capture,
            args=(interface_name, packet_limit)
        )

    def stop_packet_capture(self):
        """Stops packet capture."""
        self.sniffer.stop_capture()
        return self.thread_mgr.stop_worker("packet_sniff", timeout=2.0)

    def pause_capture(self):
        """Pauses live packet capture."""
        self.sniffer.pause_capture()

    def resume_capture(self):
        """Resumes live packet capture."""
        self.sniffer.resume_capture()

    def is_capturing_paused(self) -> bool:
        """Returns whether packet capture is currently paused."""
        return getattr(self.sniffer, "is_paused", False)

    # --- Dashboard & Statistics ---

    def get_dashboard_metrics(self) -> Dict[str, Any]:
        return self.stats.get_dashboard_metrics()

    def get_network_score(self):
        return self.risk.calculate_network_score()

    def get_protocol_distribution(self) -> Dict[str, int]:
        return self.stats.get_protocol_distribution()

    def get_traffic_timeline(self, limit: int = 10) -> List[Dict[str, Any]]:
        return self.stats.get_traffic_timeline(limit=limit)

    # --- Reports ---

    def generate_pdf_report(self, filename: str) -> str:
        return self.reporter.generate_pdf(filename)

    def generate_csv_report(self, filename: str) -> str:
        return self.reporter.generate_csv(filename)

    def generate_json_report(self, filename: str) -> str:
        return self.reporter.generate_json(filename)

    def get_reports_dir(self) -> str:
        """Returns the directory where reports are stored."""
        return str(self.reporter._get_reports_dir())

    def get_reports_history(self) -> List[Dict[str, Any]]:
        return self.db.execute_read("SELECT * FROM reports ORDER BY created_at DESC")

    def get_report_detail(self, report_id: int) -> Optional[Dict[str, Any]]:
        """Returns full report record by ID."""
        rows = self.db.execute_read("SELECT * FROM reports WHERE report_id = ?", (report_id,))
        return rows[0] if rows else None

    def get_report_filepath(self, report_id: int) -> str:
        """Resolves the full filesystem path for a report."""
        row = self.get_report_detail(report_id)
        if not row:
            return ""
        loc = row.get("location", "")
        if os.path.isfile(loc):
            return loc
        reports_dir = self.get_reports_dir()
        candidate = os.path.join(reports_dir, loc)
        if os.path.isfile(candidate):
            return candidate
        return ""

    def delete_report(self, report_id: int):
        """Deletes report record from DB and removes file from disk."""
        filepath = self.get_report_filepath(report_id)
        if filepath:
            try:
                os.remove(filepath)
            except Exception as e:
                logger.warning(f"Failed to remove report file {filepath}: {e}")
        ok = self.db.execute_write("DELETE FROM reports WHERE report_id = ?", (report_id,))
        if ok:
            logger.info(f"Report {report_id} deleted.")
            self.event_bus.publish("REPORT_DELETED", {})

    def open_report_file(self, report_id: int):
        """Opens report file with default system application."""
        filepath = self.get_report_filepath(report_id)
        if filepath:
            try:
                os.startfile(filepath)
            except Exception as e:
                logger.error(f"Failed to open report file: {e}")

    def get_devices(self) -> List[Dict[str, Any]]:
        return self.db.execute_read("SELECT * FROM devices WHERE status != 'Cleared' ORDER BY ip_address ASC")

    def clear_devices(self):
        """Marks all devices as 'Cleared' so port scan history is preserved."""
        ok = self.db.execute_write("UPDATE devices SET status = 'Cleared'")
        if ok:
            logger.info("All device records marked as Cleared.")
            self.event_bus.publish("DEVICES_CLEARED", {})
        else:
            logger.error("Failed to clear device records.")

    def clean_port_scan_data(self):
        """Deletes all port scan records from DB, refreshes dashboard and port table."""
        ok = self.db.delete_all_port_scans()
        if ok:
            logger.info("All port scan records deleted.")
            self.event_bus.publish("PORT_DATA_CLEARED", {})
        else:
            logger.error("Failed to delete port scan records.")

    def clean_packet_data(self):
        """Deletes all packet records from DB, refreshes dashboard."""
        ok = self.db.delete_all_packets()
        if ok:
            logger.info("All packet records deleted.")
            self.event_bus.publish("PACKET_DATA_CLEARED", {})
        else:
            logger.error("Failed to delete packet records.")

    def get_port_scans(self) -> List[Dict[str, Any]]:
        return self.db.execute_read("""
            SELECT d.ip_address, ps.port, ps.protocol, ps.service, ps.state, ps.risk, ps.banner, ps.scan_time
            FROM port_scans ps
            JOIN devices d ON ps.device_id = d.device_id
            ORDER BY d.ip_address ASC, ps.port ASC
        """)

    def get_packets(self, limit: int = 200) -> List[Dict[str, Any]]:
        return self.db.execute_read("""
            SELECT timestamp, source_ip, destination_ip, protocol, length, information
            FROM packets
            ORDER BY packet_id DESC
            LIMIT ?
        """, (limit,))

    def get_interfaces(self) -> List[str]:
        return self.sniffer.get_interfaces()

    def get_local_subnet(self, version: int = 4) -> str:
        return get_local_subnet(version=version)

    def get_default_interface(self, version: int = 4):
        return get_default_interface(version=version)

    def get_devices_count(self) -> int:
        return len(self.get_devices())

    def get_device_detail(self, ip: str) -> Optional[Dict[str, Any]]:
        rows = self.db.execute_read("SELECT * FROM devices WHERE ip_address = ?", (ip,))
        if not rows:
            return None
        dev = rows[0]
        port_rows = self.db.execute_read(
            "SELECT COUNT(*) as cnt FROM port_scans ps JOIN devices d ON ps.device_id = d.device_id WHERE d.ip_address = ? AND ps.state IN ('Open', 'Open|Filtered')",
            (ip,),
        )
        dev["open_port_count"] = port_rows[0]["cnt"] if port_rows else 0
        tcp_rows = self.db.execute_read(
            "SELECT COUNT(*) as cnt FROM port_scans ps JOIN devices d ON ps.device_id = d.device_id WHERE d.ip_address = ? AND ps.protocol = 'TCP' AND ps.state IN ('Open', 'Open|Filtered')",
            (ip,),
        )
        dev["tcp_open"] = tcp_rows[0]["cnt"] if tcp_rows else 0
        udp_rows = self.db.execute_read(
            "SELECT COUNT(*) as cnt FROM port_scans ps JOIN devices d ON ps.device_id = d.device_id WHERE d.ip_address = ? AND ps.protocol = 'UDP' AND ps.state IN ('Open', 'Open|Filtered')",
            (ip,),
        )
        dev["udp_open"] = udp_rows[0]["cnt"] if udp_rows else 0
        risk_rows = self.db.execute_read(
            "SELECT risk, COUNT(*) as cnt FROM port_scans ps JOIN devices d ON ps.device_id = d.device_id WHERE d.ip_address = ? AND ps.state IN ('Open', 'Open|Filtered') GROUP BY risk",
            (ip,),
        )
        dev["risk_breakdown"] = {r["risk"]: r["cnt"] for r in risk_rows} if risk_rows else {}
        scan_time_rows = self.db.execute_read(
            "SELECT MAX(ps.scan_time) as last_scan FROM port_scans ps JOIN devices d ON ps.device_id = d.device_id WHERE d.ip_address = ?",
            (ip,),
        )
        dev["last_port_scan"] = scan_time_rows[0]["last_scan"] if scan_time_rows and scan_time_rows[0]["last_scan"] else "\u2014"
        return dev

    def toggle_device_trusted(self, ip: str) -> Optional[bool]:
        """Toggles the trusted flag for a device. Returns the new state or None."""
        rows = self.db.execute_read("SELECT device_id, trusted FROM devices WHERE ip_address = ?", (ip,))
        if not rows:
            return None
        dev = rows[0]
        new_state = not dev["trusted"]
        ok = self.db.set_device_trusted(dev["device_id"], new_state)
        if ok:
            self.event_bus.publish("DEVICE_TRUSTED_TOGGLED", {"ip": ip, "trusted": new_state})
            return new_state
        return None

    def get_port_detail(self, ip: str, port: int, protocol: str) -> Optional[Dict[str, Any]]:
        rows = self.db.execute_read("""
            SELECT ps.*, d.ip_address, d.hostname
            FROM port_scans ps
            JOIN devices d ON ps.device_id = d.device_id
            WHERE d.ip_address = ? AND ps.port = ? AND ps.protocol = ?
        """, (ip, port, protocol))
        return rows[0] if rows else None

    # --- Vulnerability Checker ---

    def get_device_vulnerabilities(self, ip: str) -> Dict[str, Any]:
        """Returns CVE data for all open ports on a device."""
        ports = self.db.execute_read("""
            SELECT ps.port, ps.protocol, ps.service, ps.banner, ps.risk
            FROM port_scans ps
            JOIN devices d ON ps.device_id = d.device_id
            WHERE d.ip_address = ? AND ps.state IN ('Open', 'Open|Filtered')
        """, (ip,))
        return self.vuln_checker.check_device_ports(ports)

    def get_all_vulnerability_stats(self) -> Dict[str, Any]:
        """Returns aggregate vulnerability statistics across all devices."""
        rows = self.db.execute_read("""
            SELECT d.ip_address, ps.port, ps.protocol, ps.service, ps.banner, ps.risk
            FROM port_scans ps
            JOIN devices d ON ps.device_id = d.device_id
            WHERE d.status != 'Cleared' AND ps.state IN ('Open', 'Open|Filtered')
            ORDER BY d.ip_address
        """)
        all_ports = {}
        for r in rows:
            ip = r["ip_address"]
            if ip not in all_ports:
                all_ports[ip] = []
            all_ports[ip].append(r)
        return self.vuln_checker.get_statistics(all_ports)

    def get_topology_data(self) -> Dict[str, Any]:
        """Returns device and connection data for topology visualization."""
        devices = self.get_devices()
        ips = [d["ip_address"] for d in devices]
        if not ips:
            return {"nodes": []}

        placeholders = ",".join("?" * len(ips))
        port_rows = self.db.execute_read(f"""
            SELECT d.ip_address, ps.port, ps.protocol, ps.service, ps.state
            FROM port_scans ps
            JOIN devices d ON ps.device_id = d.device_id
            WHERE d.ip_address IN ({placeholders}) AND ps.state IN ('Open', 'Open|Filtered')
        """, ips)
        risk_rows = self.db.execute_read(f"""
            SELECT d.ip_address, ps.risk, COUNT(*) as cnt
            FROM port_scans ps
            JOIN devices d ON ps.device_id = d.device_id
            WHERE d.ip_address IN ({placeholders}) AND ps.state IN ('Open', 'Open|Filtered')
            GROUP BY d.ip_address, ps.risk
        """, ips)

        ports_by_ip = {}
        for r in port_rows:
            ports_by_ip.setdefault(r["ip_address"], []).append(r)
        risk_by_ip = {}
        for r in risk_rows:
            risk_by_ip.setdefault(r["ip_address"], {})[r["risk"]] = r["cnt"]

        nodes = []
        for d in devices:
            ip = d["ip_address"]
            ports = ports_by_ip.get(ip, [])
            risk_bd = risk_by_ip.get(ip, {})
            high_risk = risk_bd.get("High", 0) + risk_bd.get("Critical", 0) * 2
            nodes.append({
                "ip": ip,
                "hostname": d.get("hostname", ""),
                "vendor": d.get("vendor", ""),
                "status": d.get("status", "Offline"),
                "mac": d.get("mac_address", ""),
                "risk_score": high_risk,
                "port_count": len(ports),
                "trusted": d.get("trusted", 0),
            })
        return {"nodes": nodes}

    # --- Cleanup ---

    def shutdown(self):
        """Gracefully stops all workers and closes database."""
        self.thread_mgr.stop_worker("subnet_scan", timeout=5.0)
        self.thread_mgr.stop_worker("port_scan", timeout=5.0)
        self.thread_mgr.stop_worker("packet_sniff", timeout=5.0)
        self.db.close()
