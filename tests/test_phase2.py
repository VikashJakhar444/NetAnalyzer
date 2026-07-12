"""
Unit tests for Phase 2: Network Discovery Module.
Tests MAC vendor lookups and subnet scanners.
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

from core.vendor_lookup import VendorLookup
from core.network_scanner import NetworkScanner
from core.database import DatabaseManager
from core.event_bus import EventBus


class TestVendorLookup(unittest.TestCase):
    def test_known_oui_resolution(self):
        # VMware MAC prefix
        self.assertEqual(VendorLookup.lookup("00:50:56:12:34:56"), "VMware, Inc.")
        # Raspberry Pi MAC prefix
        self.assertEqual(VendorLookup.lookup("b8-27-eb-aa-bb-cc"), "Raspberry Pi Foundation")
        # Apple MAC prefix
        self.assertEqual(VendorLookup.lookup("E8:80:2E:11:22:33"), "Apple, Inc.")

    def test_unknown_oui_resolution(self):
        self.assertEqual(VendorLookup.lookup("00:11:ff:11:22:33"), "Unknown")
        self.assertEqual(VendorLookup.lookup("invalid_mac"), "Unknown")
        self.assertEqual(VendorLookup.lookup(""), "Unknown")
        self.assertEqual(VendorLookup.lookup(None), "Unknown")


class TestNetworkScanner(unittest.TestCase):
    def setUp(self):
        # Create temp folder for testing DB
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
        self.event_bus = EventBus()
        self.scanner = NetworkScanner()

    def tearDown(self):
        self.db.close()
        import core.database as db_mod
        db_mod.DATABASE_FILE = self.original_db_file
        db_mod.DATABASE_DIR = self.original_db_dir
        shutil.rmtree(self.temp_dir)
        DatabaseManager._instance = None

    def test_scanner_events_and_db_integration(self):
        started_events = []
        finished_events = []
        discovered_devices = []

        def on_start(cidr):
            started_events.append(cidr)

        def on_discovered(device):
            discovered_devices.append(device)

        def on_finish(devices):
            finished_events.append(devices)

        # Subscribe to Event Bus
        self.event_bus.subscribe("SCAN_STARTED", on_start)
        self.event_bus.subscribe("DEVICE_DISCOVERED", on_discovered)
        self.event_bus.subscribe("SCAN_FINISHED", on_finish)

        # Scan our loopback CIDR block: 127.0.0.1/32 (will respond rapidly)
        results = self.scanner.scan_subnet("127.0.0.1/32", scan_type="Full")

        # Unsubscribe
        self.event_bus.unsubscribe("SCAN_STARTED", on_start)
        self.event_bus.unsubscribe("DEVICE_DISCOVERED", on_discovered)
        self.event_bus.unsubscribe("SCAN_FINISHED", on_finish)

        # Verify Events
        self.assertEqual(len(started_events), 1)
        self.assertEqual(started_events[0], "127.0.0.1/32")
        self.assertEqual(len(finished_events), 1)

        # Check Database holds the device scan record
        devices_in_db = self.db.execute_read("SELECT * FROM devices WHERE ip_address = '127.0.0.1'")
        self.assertEqual(len(devices_in_db), 1)
        self.assertEqual(devices_in_db[0]["status"], "Online")

    def test_scanner_cancellation(self):
        # Create a stop event flag and set it immediately to verify quick cancellation
        stop_event = threading.Event()
        stop_event.set()

        # Scan target
        results = self.scanner.scan_subnet("192.168.1.0/24", scan_type="Full", stop_event=stop_event)
        
        # Verify that scan returns immediately due to cancellation (no results should be produced)
        self.assertEqual(len(results), 0)


if __name__ == "__main__":
    unittest.main()
