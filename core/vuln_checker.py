"""
Vulnerability Checker Module.
Loads CVE data from a local JSON database and matches it against
discovered open ports, services, and banners.
"""
import json
from pathlib import Path
from typing import List, Dict, Any, Optional

try:
    from core.logger import logger
except ImportError:
    from core.compat import DummyLogger
    logger = DummyLogger()


VULN_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "vulnerabilities.json"


class VulnerabilityChecker:
    """Loads vulnerability definitions and matches them against port scan results."""

    def __init__(self):
        self._db: Dict[str, List[Dict[str, Any]]] = {}
        self._load()

    def _load(self):
        try:
            if VULN_DB_PATH.exists():
                with open(VULN_DB_PATH, "r") as f:
                    raw = json.load(f)
                for k, v in raw.items():
                    if k.startswith("_"):
                        continue
                    self._db[k] = v
                logger.info(f"Loaded {sum(len(v) for v in self._db.values())} CVE entries")
            else:
                logger.warning("Vulnerability database not found")
        except Exception as e:
            logger.error(f"Failed to load vulnerability database: {e}")

    def check_port(self, port: int, service: str = "", banner: str = "", risk: str = "") -> List[Dict[str, Any]]:
        """Return matching CVEs for a given port and optional service/banner.
        Only reports CVEs for ports with Medium, High, or Critical risk.
        """
        if risk.lower() not in ("medium", "high", "critical"):
            return []
        results = []
        port_str = str(port)
        if port_str in self._db:
            for entry in self._db[port_str]:
                svc_match = True
                if entry.get("service"):
                    svc_match = entry["service"].lower() in service.lower()
                results.append({**entry, "port": port, "match": svc_match})
        return results

    def check_device_ports(self, ports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Check all open ports of a device and return aggregated vulnerability data."""
        all_cves = []
        vuln_count = 0
        for p in ports:
            port = p.get("port", 0)
            service = p.get("service", "")
            banner = p.get("banner", "")
            risk = p.get("risk", "")
            matches = self.check_port(port, service, banner, risk)
            for m in matches:
                all_cves.append({"port": port, **m})
                if m["match"]:
                    vuln_count += 1
        critical = sum(1 for c in all_cves if c.get("severity") == "Critical" and c["match"])
        high = sum(1 for c in all_cves if c.get("severity") == "High" and c["match"])
        medium = sum(1 for c in all_cves if c.get("severity") == "Medium" and c["match"])
        return {
            "total_cves": len(all_cves),
            "matching_cves": vuln_count,
            "critical": critical,
            "high": high,
            "medium": medium,
            "entries": all_cves,
        }

    def get_all_vulnerable_ports(self) -> List[str]:
        """Return list of port strings that have CVE entries."""
        return list(self._db.keys())

    def get_statistics(self, all_device_ports: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Aggregate vulnerability statistics across all devices."""
        total_cves = 0
        total_critical = 0
        total_high = 0
        total_medium = 0
        vuln_devices = 0
        for device_ip, ports in all_device_ports.items():
            result = self.check_device_ports(ports)
            if result["matching_cves"] > 0:
                vuln_devices += 1
                total_cves += result["matching_cves"]
                total_critical += result["critical"]
                total_high += result["high"]
                total_medium += result["medium"]
        return {
            "total_cves": total_cves,
            "critical": total_critical,
            "high": total_high,
            "medium": total_medium,
            "vulnerable_devices": vuln_devices,
        }
