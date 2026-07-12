"""
Main Application Bootstrap Loader.
Checks for Admin rights and Npcap, initializes databases, and launches the UI loop.
"""
import ctypes
import os
import sys
from pathlib import Path
from tkinter import messagebox

# Setup import paths
sys.path.insert(0, str(Path(__file__).resolve().parent))

# Import core configurations and services
from config.config import ConfigurationManager
from core.database import DatabaseManager
from core.logger import logger
from ui.app_window import AppWindow

try:
    import scapy.all as scapy
    NPCAP_AVAILABLE = True
except Exception as e:
    logger.warning(f"Scapy failed to initialize (Npcap driver likely missing): {e}")
    NPCAP_AVAILABLE = False


def is_admin() -> bool:
    """Checks if the script is running with Windows Administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except AttributeError:
        # Fallback for non-Windows test environments
        return False


def main():
    """Application bootstrap entry point."""
    logger.info("Application bootstrap initiated.")

    # 1. Admin Rights Check
    admin_status = is_admin()
    if not admin_status:
        logger.warning("Application is running without Administrator privileges. Packet capture features will be disabled.")
        # Non-blocking warning (launches window and shows message)
        messagebox.showwarning(
            "Administrator Rights Required",
            "The application is running in Standard Mode.\n\n"
            "Live Packet Sniffing requires Windows Administrator privileges. "
            "To unlock all features, please restart the application as Administrator."
        )

    # 2. Npcap Driver Availability Check
    if not NPCAP_AVAILABLE:
        logger.error("Npcap driver not detected. Packet capture features will be disabled.")
        messagebox.showwarning(
            "Npcap Driver Missing",
            "The Npcap packet capture driver was not detected on this system.\n\n"
            "Live Packet Sniffing will be unavailable. Please download and install Npcap from: "
            "https://npcap.com/\n\n"
            "Subnet scanning and port auditing will continue to function using standard TCP/IP socket fallbacks."
        )

    # 3. Database Initialization
    try:
        db = DatabaseManager()
        db.log_event("INFO", "Bootstrap", "Application started successfully.")
    except Exception as e:
        logger.critical(f"Critical error initializing database: {e}")
        messagebox.showerror(
            "Database Initialization Error",
            "Failed to open the local database file.\n"
            "Please ensure the application has write permissions to its directory."
        )
        sys.exit(1)

    # 4. Config Initialization
    try:
        config_mgr = ConfigurationManager()
        # Set theme based on saved preferences
        theme = config_mgr.get("theme", "dark")
        import customtkinter as ctk
        ctk.set_appearance_mode(theme)
        ctk.set_default_color_theme("dark-blue")
        ctk.set_widget_scaling(1.0)
    except Exception as e:
        logger.error(f"Error loading system configurations: {e}")

    # 5. Launch Main Window
    try:
        logger.info("Starting main GUI viewport event loop.")
        app = AppWindow()
        app.mainloop()
    except Exception as e:
        logger.critical(f"Unhandled runtime GUI exception: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
