"""
Unit tests for Phase 4: Risk, Statistics & Report Engines.
Tests database calculations, risk score deductions, and file generators (PDF, CSV, JSON).
"""
import os
import shutil
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.database import DatabaseManager
from core.statistics_engine import StatisticsEngine
from core.risk_engine import RiskEngine
from core.report_generator import ReportGenerator


class TestPhase4Engines(unittest.TestCase):
    def setUp(self):
        # Create temp folder for testing DB
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = Path(self.temp_dir) / "test_scanner.db"
        
        # Patch database.py settings
        import core.database as db_mod
        self.original_db_file = db_mod.DATABASE_FILE
        self.original_db_dir = db_mod.DATABASE_DIR
        db_mod.DATABASE_FILE = self.test_db_path
        db_mod.DATABASE_DIR = Path(self.temp_dir)

        # Patch report_generator.py directories
        import core.report_generator as rg_mod
        self.original_reports_dir = rg_mod.REPORTS_DIR
        self.original_exports_dir = rg_mod.EXPORTS_DIR
        rg_mod.REPORTS_DIR = Path(self.temp_dir) / "reports"
        rg_mod.EXPORTS_DIR = Path(self.temp_dir) / "exports"

        # Force fresh instances
        DatabaseManager._instance = None
        self.db = DatabaseManager()
        self.stats = StatisticsEngine()
        self.risk = RiskEngine()
        self.generator = ReportGenerator()

        # Insert Mock Data
        self._insert_mock_data()

    def tearDown(self):
        self.db.close()
        
        # Restore database.py settings
        import core.database as db_mod
        db_mod.DATABASE_FILE = self.original_db_file
        db_mod.DATABASE_DIR = self.original_db_dir

        # Restore report_generator.py directories
        import core.report_generator as rg_mod
        rg_mod.REPORTS_DIR = self.original_reports_dir
        rg_mod.EXPORTS_DIR = self.original_exports_dir

        shutil.rmtree(self.temp_dir)
        DatabaseManager._instance = None

    def _insert_mock_data(self):
        # Insert Device 1 (Target with ports)
        self.dev1_id = self.db.upsert_device("192.168.1.10", "00:11:22:33:44:55", "host-10", "Apple, Inc.", "Online", 0.04)
        
        # Open port 80 (Low Risk) and 23 (High Risk) on Device 1
        scans1 = [
            {"port": 80, "protocol": "TCP", "service": "HTTP", "state": "Open", "risk": "Low"},
            {"port": 23, "protocol": "TCP", "service": "Telnet", "state": "Open", "risk": "High"}
        ]
        self.db.save_port_scans(self.dev1_id, scans1)

        # Insert Device 2 (Target with no open ports)
        self.dev2_id = self.db.upsert_device("192.168.1.20", "aa:bb:cc:dd:ee:ff", "host-20", "Intel Corporation", "Online", 0.01)
        self.db.save_port_scans(self.dev2_id, [])

        # Log some packets
        self.db.log_packet("192.168.1.10", "192.168.1.20", "TCP", 64, "SYN Probe")
        self.db.log_packet("192.168.1.20", "192.168.1.10", "TCP", 60, "SYN-ACK Probe")
        self.db.log_packet("192.168.1.10", "8.8.8.8", "DNS", 80, "DNS Query: google.com")

    def test_statistics_calculations(self):
        metrics = self.stats.get_dashboard_metrics()
        self.assertEqual(metrics["total_devices"], 2)
        self.assertEqual(metrics["online_devices"], 2)
        self.assertEqual(metrics["total_open_ports"], 2)
        self.assertEqual(metrics["total_packets"], 3)
        self.assertAlmostEqual(metrics["average_response_time"], 0.025, places=3)

        # Test protocol distribution
        proto_dist = self.stats.get_protocol_distribution()
        self.assertEqual(proto_dist.get("TCP"), 2)
        self.assertEqual(proto_dist.get("DNS"), 1)

        # Test top hosts (returns devices that sent/received packets)
        top_hosts = self.stats.get_top_active_hosts()
        self.assertTrue(len(top_hosts) > 0)
        # Device 1 was involved in 3 packets, Device 2 in 2 packets. Device 1 should be first.
        self.assertEqual(top_hosts[0]["ip_address"], "192.168.1.10")

    def test_risk_calculations_and_recommendations(self):
        # High Risk deduction: -15, Low Risk: -3. Total score should be 100 - 18 = 82
        score = self.risk.calculate_network_score()
        self.assertEqual(score, 82)

        # Recommendations should generate 2 issues: Telnet (High) and HTTP (Low)
        recs = self.risk.generate_recommendations()
        self.assertEqual(len(recs), 2)
        
        # Verify recommendation details
        telnet_rec = next(r for r in recs if r["port"] == 23)
        self.assertEqual(telnet_rec["risk"], "High")
        self.assertIn("Telnet sends data unencrypted", telnet_rec["description"])

    def test_report_generation(self):
        # 1. JSON Export
        json_path = self.generator.generate_json("test_scan.json")
        self.assertTrue(os.path.exists(json_path))
        self.assertTrue(json_path.endswith(".json"))

        # 2. CSV Export
        csv_path = self.generator.generate_csv("test_scan.csv")
        self.assertTrue(os.path.exists(csv_path))
        self.assertTrue(csv_path.endswith(".csv"))

        # 3. PDF Export
        pdf_path = self.generator.generate_pdf("test_scan.pdf")
        # Assertions will only evaluate if reportlab was successfully imported
        import core.report_generator as rg_mod
        if rg_mod.REPORTLAB_AVAILABLE:
            self.assertTrue(os.path.exists(pdf_path))
            self.assertTrue(pdf_path.endswith(".pdf"))

        # Check DB holds generated reports history records
        reports_history = self.db.execute_read("SELECT * FROM reports")
        self.assertEqual(len(reports_history), 3)  # JSON, CSV, and PDF logged successfully


if __name__ == "__main__":
    unittest.main()
