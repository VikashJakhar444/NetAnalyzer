"""
Unit tests for Phase 3: Port Scan & Live Sniffer Core.
Verifies port scanners, Scapy packet protocol decoders, and interfaces enumeration.
"""
import os
import shutil
import tempfile
import threading
import time
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.port_scanner import PortScanner
from core.protocol_analyzer import ProtocolAnalyzer
from core.packet_sniffer import PacketSniffer
from core.database import DatabaseManager
from core.event_bus import EventBus

try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class TestProtocolAnalyzer(unittest.TestCase):
    @unittest.skipUnless(SCAPY_AVAILABLE, "Scapy is required to construct mock packets")
    def test_arp_packet_parsing(self):
        # Construct Scapy ARP query frame
        pkt = scapy.ARP(op=1, psrc="192.168.1.50", pdst="192.168.1.1")
        analysis = ProtocolAnalyzer.analyze(pkt)
        self.assertEqual(analysis["protocol"], "ARP")
        self.assertEqual(analysis["src"], "192.168.1.50")
        self.assertEqual(analysis["dst"], "192.168.1.1")
        self.assertIn("Who has 192.168.1.1", analysis["info"])

    @unittest.skipUnless(SCAPY_AVAILABLE, "Scapy is required to construct mock packets")
    def test_icmp_packet_parsing(self):
        # ICMP echo request (ping)
        pkt = scapy.IP(src="10.0.0.2", dst="10.0.0.1")/scapy.ICMP(type=8)
        analysis = ProtocolAnalyzer.analyze(pkt)
        self.assertEqual(analysis["protocol"], "ICMP")
        self.assertEqual(analysis["src"], "10.0.0.2")
        self.assertEqual(analysis["dst"], "10.0.0.1")
        self.assertEqual(analysis["info"], "ICMP Echo Request (Ping)")

    @unittest.skipUnless(SCAPY_AVAILABLE, "Scapy is required to construct mock packets")
    def test_tcp_web_parsing(self):
        # TCP SYN request to HTTP port 80
        pkt = scapy.IP(src="10.0.0.5", dst="10.0.0.1")/scapy.TCP(sport=54321, dport=80, flags="S")
        analysis = ProtocolAnalyzer.analyze(pkt)
        self.assertEqual(analysis["protocol"], "HTTP")
        self.assertEqual(analysis["src"], "10.0.0.5")
        self.assertEqual(analysis["dst"], "10.0.0.1")

        # TCP traffic on port 443 (HTTPS)
        pkt_https = scapy.IP(src="10.0.0.5", dst="10.0.0.1")/scapy.TCP(sport=54321, dport=443, flags="A")
        analysis_https = ProtocolAnalyzer.analyze(pkt_https)
        self.assertEqual(analysis_https["protocol"], "HTTPS")
        self.assertIn("Encrypted TLS Traffic", analysis_https["info"])

    @unittest.skipUnless(SCAPY_AVAILABLE, "Scapy is required to construct mock packets")
    def test_dns_packet_parsing(self):
        # DNS Query request
        pkt = scapy.IP(src="192.168.1.10", dst="8.8.8.8")/\
              scapy.UDP(sport=44556, dport=53)/\
              scapy.DNS(qr=0, qd=scapy.DNSQR(qname=b"yahoo.com"))
        analysis = ProtocolAnalyzer.analyze(pkt)
        self.assertEqual(analysis["protocol"], "DNS")
        self.assertEqual(analysis["src"], "192.168.1.10")
        self.assertEqual(analysis["dst"], "8.8.8.8")
        self.assertIn("DNS Query: yahoo.com", analysis["info"])


class TestPortScanner(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = Path(self.temp_dir) / "test_scanner.db"
        
        import core.database as db_mod
        self.original_db_file = db_mod.DATABASE_FILE
        self.original_db_dir = db_mod.DATABASE_DIR
        db_mod.DATABASE_FILE = self.test_db_path
        db_mod.DATABASE_DIR = Path(self.temp_dir)

        # Re-initialize DB
        DatabaseManager._instance = None
        self.db = DatabaseManager()
        self.scanner = PortScanner()

    def tearDown(self):
        self.db.close()
        import core.database as db_mod
        db_mod.DATABASE_FILE = self.original_db_file
        db_mod.DATABASE_DIR = self.original_db_dir
        shutil.rmtree(self.temp_dir)
        DatabaseManager._instance = None

    def test_service_and_risk_lookup(self):
        # Port 23: Telnet / High Risk
        self.assertEqual(self.scanner._resolve_service(23), "Telnet")
        self.assertEqual(self.scanner._resolve_risk(23), "High")

        # Port 80: HTTP / Low Risk
        self.assertEqual(self.scanner._resolve_service(80), "HTTP")
        self.assertEqual(self.scanner._resolve_risk(80), "Low")

    def test_port_scan_database_logging(self):
        # Verify socket scanner can execute on localhost loopback
        # Note: connect_ex might fail if no services are listening, but the scan function itself must execute successfully.
        results = self.scanner.run_scan("127.0.0.1", scan_mode="Custom", custom_ports=[80, 443])
        # DB check to make sure scanner registered the device in devices table
        devices = self.db.execute_read("SELECT * FROM devices WHERE ip_address = '127.0.0.1'")
        self.assertEqual(len(devices), 1)


class TestPacketSniffer(unittest.TestCase):
    def setUp(self):
        self.sniffer = PacketSniffer()

    def test_interfaces_listing(self):
        ifaces = self.sniffer.get_interfaces()
        self.assertTrue(len(ifaces) > 0)
        self.assertIsNotNone(ifaces[0])


if __name__ == "__main__":
    unittest.main()
