"""
Risk Engine Module.
Calculates security ratings, parses open ports risk impact, and generates recommendations.
"""
import sys
from typing import Dict, Any, List

# Setup import compatibility for testing and main execution
try:
    from core.constants import VULNERABLE_PORTS
    from core.logger import logger
    from core.database import DatabaseManager
except ImportError:
    VULNERABLE_PORTS = {
        21: {"service": "FTP", "risk": "Medium", "recommendation": "FTP transmits credentials in plaintext. Use SFTP or FTPS instead."},
        23: {"service": "Telnet", "risk": "High", "recommendation": "Telnet sends data unencrypted. Disable and use SSH on port 22."},
        80: {"service": "HTTP", "risk": "Low", "recommendation": "Web traffic is unencrypted. Enforce HTTPS (port 443) where possible."},
        445: {"service": "SMB", "risk": "High", "recommendation": "SMB port is often targeted for exploits. Restrict access."},
        3389: {"service": "RDP", "risk": "Medium", "recommendation": "Remote Desktop should not be exposed directly to the LAN. Use VPN."},
    }
    from core.compat import DummyLogger
    logger = DummyLogger()


class RiskEngine:
    """
    Computes system risk scores and maps vulnerability remediations.
    """

    def __init__(self):
        self.db = DatabaseManager()

    def calculate_network_score(self):
        """
        Calculates the overall network security score out of 100.
        Only counts ports from the most recent scan per device per protocol.
        Deducts points for open ports depending on risk level:
        - High: -15
        - Medium: -8
        - Low: -3
        Returns None if no scan data exists.
        """
        try:
            # Only consider ports from the latest scan session per device+protocol
            open_ports = self.db.execute_read("""
                SELECT ps.port, ps.risk FROM port_scans ps
                JOIN devices d ON ps.device_id = d.device_id
                JOIN (
                    SELECT device_id, protocol, MAX(scan_time) AS max_time
                    FROM port_scans GROUP BY device_id, protocol
                ) latest ON ps.device_id = latest.device_id
                    AND ps.protocol = latest.protocol
                    AND ps.scan_time = latest.max_time
                WHERE ps.state = 'Open' AND d.status != 'Cleared'
            """)
            if not open_ports:
                return None

            deductions = 0
            for entry in open_ports:
                risk = entry.get("risk", "Low")
                if risk == "High":
                    deductions += 15
                elif risk == "Medium":
                    deductions += 8
                else:
                    deductions += 3

            score = 100 - deductions
            score = max(0, score)
        except Exception as e:
            logger.error(f"Error calculating network risk score: {e}")
            return None

        return score

    def generate_recommendations(self) -> List[Dict[str, Any]]:
        """
        Scans SQLite database to locate open vulnerable ports and returns actionable recommendations.
        Only considers ports from the most recent scan per device+protocol.
        """
        recommendations = []
        try:
            # Group open ports to list distinct targets (latest scan only)
            query = """
                SELECT ps.port, ps.service, ps.risk, d.ip_address, d.hostname
                FROM port_scans ps
                JOIN devices d ON ps.device_id = d.device_id
                JOIN (
                    SELECT device_id, protocol, MAX(scan_time) AS max_time
                    FROM port_scans GROUP BY device_id, protocol
                ) latest ON ps.device_id = latest.device_id
                    AND ps.protocol = latest.protocol
                    AND ps.scan_time = latest.max_time
                WHERE ps.state = 'Open' AND d.status != 'Cleared'
                ORDER BY ps.port ASC
            """
            rows = self.db.execute_read(query)
            
            seen_issues = set()
            for row in rows:
                port = row["port"]
                ip = row["ip_address"]
                hostname = row["hostname"] if row["hostname"] != "Unknown" else ip
                
                # Check if this port is flagged as a vulnerable port
                if port in VULNERABLE_PORTS:
                    vuln_info = VULNERABLE_PORTS[port]
                    rec_key = f"{port}_{ip}"
                    
                    if rec_key not in seen_issues:
                        seen_issues.add(rec_key)
                        recommendations.append({
                            "port": port,
                            "service": row["service"],
                            "risk": row["risk"],
                            "target": f"{hostname} ({ip})",
                            "description": vuln_info["recommendation"]
                        })
                else:
                    # Generic low-risk recommendation for any open TCP port
                    rec_key = f"generic_{port}_{ip}"
                    if rec_key not in seen_issues:
                        seen_issues.add(rec_key)
                        recommendations.append({
                            "port": port,
                            "service": row["service"] or f"TCP-{port}",
                            "risk": "Low",
                            "target": f"{hostname} ({ip})",
                            "description": f"Port {port} is open. Ensure that this service is intended and firewall access rules are locked down."
                        })
        except Exception as e:
            logger.error(f"Error generating security recommendations: {e}")

        return recommendations
