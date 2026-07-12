"""
Unit tests for Phase 1: Foundation and Infrastructure.
Exercises validators, configuration management, database connections/queries, helpers, thread managers, and event buses.
"""
import os
import shutil
import tempfile
import threading
import time
import unittest
from pathlib import Path

# Adjust path context for importing project modules
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.validators import validate_ip, validate_mac, validate_port, validate_network, validate_path
from core.helpers import format_bytes, format_time, get_default_interface, get_local_subnet
from config.config import ConfigurationManager
from core.database import DatabaseManager
from core.thread_manager import ThreadManager
from core.event_bus import EventBus


class TestValidators(unittest.TestCase):
    def test_ip_validation(self):
        self.assertTrue(validate_ip("192.168.1.1"))
        self.assertTrue(validate_ip("10.0.0.1"))
        self.assertTrue(validate_ip("  172.16.0.1  "))
        self.assertFalse(validate_ip("256.100.1.1"))
        self.assertFalse(validate_ip("abc"))
        self.assertFalse(validate_ip(""))

    def test_mac_validation(self):
        self.assertTrue(validate_mac("00:11:22:33:44:55"))
        self.assertTrue(validate_mac("00-11-22-33-44-55"))
        self.assertTrue(validate_mac("AA:BB:CC:DD:EE:FF"))
        self.assertFalse(validate_mac("00:11:22:33:44"))
        self.assertFalse(validate_mac("00:11:22:33:44:55:66"))
        self.assertFalse(validate_mac("abc"))

    def test_port_validation(self):
        self.assertTrue(validate_port(80))
        self.assertTrue(validate_port("443"))
        self.assertTrue(validate_port(1))
        self.assertTrue(validate_port(65535))
        self.assertFalse(validate_port(0))
        self.assertFalse(validate_port(65536))
        self.assertFalse(validate_port("abc"))

    def test_network_validation(self):
        self.assertTrue(validate_network("192.168.1.0/24"))
        self.assertTrue(validate_network("10.0.0.0/8"))
        self.assertTrue(validate_network("172.16.0.0/16"))
        self.assertFalse(validate_network("192.168.1.300/24"))
        self.assertFalse(validate_network("192.168.1.0"))
        self.assertFalse(validate_network("abc"))


class TestHelpers(unittest.TestCase):
    def test_format_bytes(self):
        self.assertEqual(format_bytes(500), "500.00 B")
        self.assertEqual(format_bytes(1024), "1.00 KB")
        self.assertEqual(format_bytes(1024 * 1024), "1.00 MB")
        self.assertEqual(format_bytes(-100), "0 B")

    def test_format_time(self):
        t_str = format_time()
        self.assertTrue(len(t_str) > 0)
        self.assertIn("-", t_str)
        self.assertIn(":", t_str)

    def test_interface_and_subnet_discovery(self):
        nic, ip = get_default_interface()
        self.assertIsNotNone(nic)
        self.assertIsNotNone(ip)
        subnet = get_local_subnet()
        self.assertIsNotNone(subnet)
        self.assertIn("/", subnet)


class TestConfigurationManager(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.patch_config_file = Path(self.temp_dir) / "settings.json"
        
        # Monkey patch values in config.py dynamically for safety during testing
        import config.config as config_mod
        self.original_config_file = config_mod.CONFIG_FILE
        self.original_config_dir = config_mod.CONFIG_DIR
        config_mod.CONFIG_FILE = self.patch_config_file
        config_mod.CONFIG_DIR = Path(self.temp_dir)

    def tearDown(self):
        import config.config as config_mod
        config_mod.CONFIG_FILE = self.original_config_file
        config_mod.CONFIG_DIR = self.original_config_dir
        shutil.rmtree(self.temp_dir)

    def test_config_operations(self):
        mgr = ConfigurationManager()
        # Verify defaults load
        self.assertEqual(mgr.get("theme"), "dark")
        self.assertEqual(mgr.get("timeout"), 2)

        # Verify custom updates save successfully
        self.assertTrue(mgr.set("theme", "light"))
        self.assertEqual(mgr.get("theme"), "light")

        # Test validation constraints
        self.assertFalse(mgr.set("timeout", -1))  # Invalid timeout value
        self.assertEqual(mgr.get("timeout"), 2)  # Should remain unchanged

        # Test reset restores configuration file settings
        self.assertTrue(mgr.reset())
        self.assertEqual(mgr.get("theme"), "dark")


class TestDatabaseManager(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = Path(self.temp_dir) / "test_scanner.db"
        
        # Patch database.py settings
        import core.database as db_mod
        self.original_db_file = db_mod.DATABASE_FILE
        self.original_db_dir = db_mod.DATABASE_DIR
        db_mod.DATABASE_FILE = self.test_db_path
        db_mod.DATABASE_DIR = Path(self.temp_dir)

        # Force fresh instance initialization
        DatabaseManager._instance = None
        self.db = DatabaseManager()

    def tearDown(self):
        self.db.close()
        import core.database as db_mod
        db_mod.DATABASE_FILE = self.original_db_file
        db_mod.DATABASE_DIR = self.original_db_dir
        shutil.rmtree(self.temp_dir)
        DatabaseManager._instance = None

    def test_database_crud(self):
        # Insert Device
        dev_id = self.db.upsert_device("192.168.1.150", "00:aa:bb:cc:dd:ee", "test-host", "Intel", "Online", 0.05)
        self.assertIsNotNone(dev_id)

        # Read Device
        devices = self.db.execute_read("SELECT * FROM devices WHERE device_id = ?", (dev_id,))
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["hostname"], "test-host")

        # Upsert (Update) Device
        dev_id2 = self.db.upsert_device("192.168.1.150", "00:aa:bb:cc:dd:ee", "new-host", "Intel", "Online", 0.02)
        self.assertEqual(dev_id, dev_id2)
        devices = self.db.execute_read("SELECT hostname FROM devices WHERE device_id = ?", (dev_id,))
        self.assertEqual(devices[0]["hostname"], "new-host")

        # Port scans
        ports = [{"port": 80, "protocol": "TCP", "service": "HTTP", "state": "Open", "risk": "Low"}]
        self.assertTrue(self.db.save_port_scans(dev_id, ports))
        scans = self.db.execute_read("SELECT port, service FROM port_scans WHERE device_id = ?", (dev_id,))
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0]["port"], 80)

        # Sniff packets
        self.assertTrue(self.db.log_packet("192.168.1.150", "192.168.1.1", "TCP", 64, "Flags=S"))
        packets = self.db.execute_read("SELECT protocol, length FROM packets")
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0]["protocol"], "TCP")


class TestThreadManagerAndEventBus(unittest.TestCase):
    def setUp(self):
        self.thread_mgr = ThreadManager()
        self.event_bus = EventBus()

    def test_event_bus(self):
        callback_received = []

        def test_callback(data):
            callback_received.append(data)

        self.event_bus.subscribe("TEST_TOPIC", test_callback)
        self.event_bus.publish("TEST_TOPIC", "success_value")
        
        self.assertEqual(len(callback_received), 1)
        self.assertEqual(callback_received[0], "success_value")

        self.event_bus.unsubscribe("TEST_TOPIC", test_callback)
        self.event_bus.publish("TEST_TOPIC", "ignored_value")
        self.assertEqual(len(callback_received), 1)

    def test_thread_manager(self):
        run_flag = threading.Event()

        def test_worker(stop_event):
            run_flag.set()
            while not stop_event.is_set():
                time.sleep(0.01)

        self.assertTrue(self.thread_mgr.start_worker("test_thread", test_worker))
        self.assertTrue(self.thread_mgr.is_alive("test_thread"))
        self.assertTrue(run_flag.wait(timeout=1.0))
        self.assertTrue(self.thread_mgr.stop_worker("test_thread"))
        self.assertFalse(self.thread_mgr.is_alive("test_thread"))


if __name__ == "__main__":
    unittest.main()
