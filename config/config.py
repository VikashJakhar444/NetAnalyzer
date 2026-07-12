"""
Configuration Manager module for reading, writing, and resetting configuration settings.
"""
import json
import os
import sys
from pathlib import Path

# Setup import compatibility for testing and main execution
try:
    from core.constants import CONFIG_FILE, CONFIG_DIR, DEFAULT_THEME, DEFAULT_TIMEOUT, DEFAULT_PACKET_LIMIT, DEFAULT_REPORT_PATH
    from core.logger import logger
except ImportError:
    BASE_DIR = Path(__file__).resolve().parent.parent
    CONFIG_DIR = BASE_DIR / "config"
    CONFIG_FILE = CONFIG_DIR / "settings.json"
    DEFAULT_THEME = "dark"
    DEFAULT_TIMEOUT = 2
    DEFAULT_PACKET_LIMIT = 1000
    DEFAULT_REPORT_PATH = str(BASE_DIR / "reports")
    # Stub logger if not imported
    from core.compat import DummyLogger
    logger = DummyLogger()


class ConfigurationManager:
    """
    Manages loading, updating, saving, and resetting application settings.
    Ensures parameters are validated correctly.
    """

    def __init__(self):
        self.settings = {}
        # Ensure config directory exists
        try:
            os.makedirs(CONFIG_DIR, exist_ok=True)
        except Exception as e:
            logger.error(f"Failed to create configuration directory: {e}")
        self.load()

    def get_default_settings(self) -> dict:
        """
        Returns default settings structure.
        """
        return {
            "theme": DEFAULT_THEME,
            "timeout": DEFAULT_TIMEOUT,
            "packet_limit": DEFAULT_PACKET_LIMIT,
            "default_network": "",
            "report_path": DEFAULT_REPORT_PATH
        }

    def load(self) -> dict:
        """
        Loads settings from configuration file. Falls back to defaults if missing or corrupted.
        """
        if not os.path.exists(CONFIG_FILE):
            logger.info("Configuration file not found. Creating default settings.")
            self.reset()
            return self.settings

        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                # Validate keys and types
                validated = self.validate_settings(data)
                self.settings = validated
                logger.info("Configuration settings loaded successfully.")
        except Exception as e:
            logger.error(f"Error loading configuration file: {e}. Resetting to defaults.")
            self.reset()

        return self.settings

    def save(self) -> bool:
        """
        Saves current settings dict to file.
        """
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(self.settings, f, indent=4, ensure_ascii=False)
            logger.info("Configuration settings saved successfully.")
            return True
        except Exception as e:
            logger.error(f"Error saving configuration file: {e}")
            return False

    def reset(self) -> bool:
        """
        Resets settings back to default values and saves.
        """
        self.settings = self.get_default_settings()
        return self.save()

    def get(self, key: str, default=None):
        """
        Safely retrieves a configuration key.
        """
        return self.settings.get(key, default)

    def set(self, key: str, value) -> bool:
        """
        Sets a configuration key and validates it. Saves automatically.
        """
        temp_settings = self.settings.copy()
        temp_settings[key] = value
        try:
            validated = self.validate_settings(temp_settings)
            self.settings = validated
            return self.save()
        except ValueError as e:
            logger.error(f"Invalid configuration value for key '{key}': {e}")
            return False

    def validate_settings(self, data: dict) -> dict:
        """
        Validates input configuration data types and values.
        Raises ValueError if invalid, returns updated valid dict.
        """
        defaults = self.get_default_settings()
        validated = {}

        # Validate theme
        theme = data.get("theme", defaults["theme"])
        if not isinstance(theme, str) or theme.lower() not in ["dark", "light"]:
            raise ValueError("Theme must be 'dark' or 'light'")
        validated["theme"] = theme.lower()

        # Validate timeout
        timeout = data.get("timeout", defaults["timeout"])
        try:
            timeout = int(timeout)
            if timeout <= 0 or timeout > 300:
                raise ValueError
            validated["timeout"] = timeout
        except (ValueError, TypeError):
            raise ValueError("Timeout must be an integer between 1 and 300")

        # Validate packet_limit
        packet_limit = data.get("packet_limit", defaults["packet_limit"])
        try:
            packet_limit = int(packet_limit)
            if packet_limit <= 0 or packet_limit > 100000:
                raise ValueError
            validated["packet_limit"] = packet_limit
        except (ValueError, TypeError):
            raise ValueError("Packet limit must be an integer between 1 and 100000")

        # Validate default_network
        default_network = data.get("default_network", "")
        if not isinstance(default_network, str):
            validated["default_network"] = ""
        else:
            validated["default_network"] = default_network.strip()

        # Validate report_path — keep relative, don't resolve to absolute
        report_path = data.get("report_path", defaults["report_path"])
        if not isinstance(report_path, str) or not report_path:
            validated["report_path"] = defaults["report_path"]
        else:
            validated["report_path"] = report_path.strip()

        return validated
