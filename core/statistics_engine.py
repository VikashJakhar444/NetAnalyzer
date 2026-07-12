"""
Statistics Engine Module.
Calculates dashboard metrics, protocol counts, traffic histories, and top host rankings.
"""
import sys
from typing import Dict, Any, List

# Setup import compatibility for testing and main execution
try:
    from core.logger import logger
    from core.database import DatabaseManager
except ImportError:
    from core.compat import DummyLogger
    logger = DummyLogger()


class StatisticsEngine:
    """
    Compiles real-time metrics and network traffic analysis summaries.
    """

    def __init__(self):
        self.db = DatabaseManager()

    def get_dashboard_metrics(self) -> Dict[str, Any]:
        """
        Calculates high-level counts displayed on dashboard cards.
        """
        metrics = {
            "total_devices": 0,
            "online_devices": 0,
            "total_open_ports": 0,
            "total_packets": 0,
            "average_response_time": 0.0
        }

        try:
            # Device counters (exclude cleared devices)
            dev_counts = self.db.execute_read(
                "SELECT COUNT(*) as total, SUM(CASE WHEN status='Online' THEN 1 ELSE 0 END) as online FROM devices WHERE status != 'Cleared'"
            )
            if dev_counts and dev_counts[0]["total"] > 0:
                metrics["total_devices"] = dev_counts[0]["total"]
                metrics["online_devices"] = dev_counts[0]["online"] or 0

            # Avg response time
            avg_rtt = self.db.execute_read("SELECT AVG(response_time) as avg_rtt FROM devices WHERE status='Online'")
            if avg_rtt and avg_rtt[0]["avg_rtt"] is not None:
                metrics["average_response_time"] = round(avg_rtt[0]["avg_rtt"], 4)

            # Open port counters
            port_counts = self.db.execute_read("""
                SELECT COUNT(*) as total FROM port_scans ps
                JOIN devices d ON ps.device_id = d.device_id
                WHERE ps.state='Open' AND d.status != 'Cleared'
            """)
            if port_counts:
                metrics["total_open_ports"] = port_counts[0]["total"]

            # Packet counters
            pkt_counts = self.db.execute_read("SELECT COUNT(*) as total FROM packets")
            if pkt_counts:
                metrics["total_packets"] = pkt_counts[0]["total"]

        except Exception as e:
            logger.error(f"Error calculating dashboard metrics: {e}")

        return metrics

    def get_protocol_distribution(self) -> Dict[str, int]:
        """
        Returns protocol distribution counts from logged packets.
        """
        distribution = {}
        try:
            query = "SELECT protocol, COUNT(*) as count FROM packets GROUP BY protocol ORDER BY count DESC"
            rows = self.db.execute_read(query)
            for row in rows:
                protocol = row["protocol"] or "Unknown"
                distribution[protocol] = row["count"]
        except Exception as e:
            logger.error(f"Error calculating protocol distribution: {e}")
        return distribution

    def get_top_active_hosts(self, limit: int = 5) -> List[Dict[str, Any]]:
        """
        Calculates the devices associated with the most captured traffic.
        """
        hosts = []
        try:
            # We join packets on source or destination matching devices IP
            query = """
                SELECT d.device_id, d.ip_address, d.hostname, d.vendor, COUNT(p.packet_id) as packet_count
                FROM devices d
                JOIN packets p ON p.source_ip = d.ip_address OR p.destination_ip = d.ip_address
                WHERE d.status != 'Cleared'
                GROUP BY d.device_id
                ORDER BY packet_count DESC
                LIMIT ?
            """
            rows = self.db.execute_read(query, (limit,))
            for row in rows:
                hosts.append(dict(row))
        except Exception as e:
            logger.error(f"Error calculating top active hosts: {e}")
        return hosts

    def get_traffic_timeline(self, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Groups packet capture logs by timestamp increments for chart timeline plotting.
        """
        timeline = []
        try:
            # Group by seconds (substr(timestamp, 1, 19) gets YYYY-MM-DD HH:MM:SS)
            query = """
                SELECT substr(timestamp, 1, 19) as time_bucket, COUNT(*) as count, SUM(length) as bytes
                FROM packets
                GROUP BY time_bucket
                ORDER BY time_bucket DESC
                LIMIT ?
            """
            rows = self.db.execute_read(query, (limit,))
            # Reverse to display in chronological ascending order
            timeline = [dict(row) for row in reversed(rows)]
        except Exception as e:
            logger.error(f"Error compiling traffic timeline: {e}")
        return timeline
