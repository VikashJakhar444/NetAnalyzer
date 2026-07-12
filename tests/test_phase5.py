"""
Unit tests for Phase 5: UI Construction and Integration.
Verifies module imports and page instantiations.
"""
import os
import shutil
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.database import DatabaseManager
from ui.app_window import AppWindow
from ui.dashboard import DashboardPage
from ui.scanner_page import NetworkScannerPage
from ui.port_page import PortScannerPage
from ui.packet_page import PacketSnifferPage
from ui.reports_page import ReportsPage
from ui.settings_page import SettingsPage
from ui.about_page import AboutPage


class TestPhase5UI(unittest.TestCase):
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

        # Patch report_generator.py directories to prevent test folder creation on base DIR
        import core.report_generator as rg_mod
        self.original_reports_dir = rg_mod.REPORTS_DIR
        self.original_exports_dir = rg_mod.EXPORTS_DIR
        rg_mod.REPORTS_DIR = Path(self.temp_dir) / "reports"
        rg_mod.EXPORTS_DIR = Path(self.temp_dir) / "exports"

        # Force fresh database instance
        DatabaseManager._instance = None
        self.db = DatabaseManager()

        # Initialize Window frame for UI testing (prevents mainloop blocking)
        self.app = AppWindow()

    def tearDown(self):
        self.app.destroy()
        self.db.close()
        
        # Restore settings
        import core.database as db_mod
        db_mod.DATABASE_FILE = self.original_db_file
        db_mod.DATABASE_DIR = self.original_db_dir

        import core.report_generator as rg_mod
        rg_mod.REPORTS_DIR = self.original_reports_dir
        rg_mod.EXPORTS_DIR = self.original_exports_dir

        shutil.rmtree(self.temp_dir)
        DatabaseManager._instance = None

    def test_page_instantiations(self):
        # Verify all frames are registered correctly in AppWindow frames dictionary
        self.assertIn("DashboardPage", self.app.frames)
        self.assertIn("NetworkScannerPage", self.app.frames)
        self.assertIn("PortScannerPage", self.app.frames)
        self.assertIn("PacketSnifferPage", self.app.frames)
        self.assertIn("ReportsPage", self.app.frames)
        self.assertIn("SettingsPage", self.app.frames)
        self.assertIn("AboutPage", self.app.frames)

        # Verify page classes
        self.assertIsInstance(self.app.frames["DashboardPage"], DashboardPage)
        self.assertIsInstance(self.app.frames["NetworkScannerPage"], NetworkScannerPage)
        self.assertIsInstance(self.app.frames["PortScannerPage"], PortScannerPage)
        self.assertIsInstance(self.app.frames["PacketSnifferPage"], PacketSnifferPage)


if __name__ == "__main__":
    unittest.main()
