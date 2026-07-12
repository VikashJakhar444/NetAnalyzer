"""
Constants and default configurations for the Network Analyzer & Security Scanner.
"""
import os
from pathlib import Path

# Application Metadata
APP_NAME = "Network Analyzer & Security Scanner"
VERSION = "1.0.0"
AUTHOR = "Vikash Jakhar & Anisha Verma"

# Directories
BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = BASE_DIR / "config"
DATABASE_DIR = BASE_DIR / "database"
LOGS_DIR = BASE_DIR / "logs"
REPORTS_DIR = BASE_DIR / "reports"
EXPORTS_DIR = BASE_DIR / "exports"
ASSETS_DIR = BASE_DIR / "assets"

# File Paths
CONFIG_FILE = CONFIG_DIR / "settings.json"
DATABASE_FILE = DATABASE_DIR / "scanner.db"
LOG_FILE = LOGS_DIR / "scanner.log"

# Default Configuration Settings
DEFAULT_THEME = "dark"
DEFAULT_TIMEOUT = 2  # seconds
DEFAULT_PACKET_LIMIT = 1000
DEFAULT_REPORT_PATH = str(BASE_DIR / "reports")
DEFAULT_SCAN_MODE = "Quick"  # Quick, Full, Custom

# Network Scanning Constants (comprehensive - covers all common services)
TOP_COMMON_PORTS = [
    # Web & Proxy
    80, 443, 8080, 8443, 9090, 3128, 8000, 8888,
    # Mail
    25, 110, 143, 465, 587, 993, 995,
    # File Transfer
    20, 21, 69, 989, 990,
    # Remote Access
    22, 23, 3389, 5900, 5901, 5938, 5999,
    # Database
    1433, 1521, 3306, 5432, 6379, 27017, 27018,
    # Directory Services
    389, 636, 3268, 3269,
    # Windows Services
    135, 137, 138, 139, 445,
    # Network Services
    53, 67, 68, 123, 161, 162, 514, 1701,
    # Management
    111, 512, 513, 514, 873, 1999, 2049, 6666,
    # VoIP & Messaging
    5060, 5061, 5222, 5223, 8448,
    # Development & Misc
    3000, 4200, 5000, 8000, 3001, 5555, 8081, 8082,
    # Legacy & Vulnerable
    7, 9, 13, 17, 19, 37, 79, 94, 98, 666, 1723, 6667,
    # Game & Streaming
    1935, 3478, 3479, 8800, 27015, 27016,
    # Container & Orchestration
     2375, 2376, 6443, 8088, 8448, 10250, 10255,
]

TOP_COMMON_UDP_PORTS = [
    53, 67, 68, 69, 88, 123, 137, 138, 161, 162,
    389, 500, 514, 520, 546, 547, 1900, 2049,
    3702, 4500, 5353, 5355, 5683,
]

# Vulnerable/Risky Ports and Services
VULNERABLE_PORTS = {
    21: {"service": "FTP", "risk": "Medium", "recommendation": "FTP transmits credentials in plaintext. Use SFTP or FTPS instead."},
    23: {"service": "Telnet", "risk": "High", "recommendation": "Telnet sends data unencrypted. Disable and use SSH on port 22."},
    80: {"service": "HTTP", "risk": "Low", "recommendation": "Web traffic is unencrypted. Enforce HTTPS (port 443) where possible."},
    445: {"service": "SMB", "risk": "High", "recommendation": "SMB port is often targeted for exploits (e.g. EternalBlue). Restrict access."},
    3389: {"service": "RDP", "risk": "Medium", "recommendation": "Remote Desktop should not be exposed directly to the LAN. Use VPN or MFA."},
}

# Protocol Definitions
PROTOCOLS = {
    "ARP": 2054,
    "IP": 2048,
    "ICMP": 1,
    "TCP": 6,
    "UDP": 17,
    "DNS": 53,
    "HTTP": 80,
    "HTTPS": 443
}
