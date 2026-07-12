"""
Database Manager module for SQLite interactions.
Handles connections, schema generation, queries, and thread safety.
"""
import os
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional

# Setup import compatibility for testing and main execution
try:
    from core.constants import DATABASE_FILE, DATABASE_DIR
    from core.logger import logger
except ImportError:
    BASE_DIR = Path(__file__).resolve().parent.parent
    DATABASE_DIR = BASE_DIR / "database"
    DATABASE_FILE = DATABASE_DIR / "scanner.db"
    # Stub logger if not imported
    from core.compat import DummyLogger
    logger = DummyLogger()


class DatabaseManager:
    """
    Manages SQLite database connections, schema updates, queries, backups, and restores.
    Utilizes threading.Lock for thread safety in multi-threaded environment.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        """Singleton pattern to ensure only one DatabaseManager instance exists."""
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(DatabaseManager, cls).__new__(cls, *args, **kwargs)
            return cls._instance

    def __init__(self):
        if getattr(self, '_initialized', False):
            return
        with self._lock:
            if getattr(self, '_initialized', False):
                return
            self.db_path = DATABASE_FILE
            self.conn_lock = threading.Lock()
            self.conn = None
            self._initialized = True
            self.initialize_database()

    def _get_connection(self) -> sqlite3.Connection:
        """
        Creates and returns a connection. In WAL mode, SQLite supports multiple readers,
        but only one writer. We share connections using a single local connection or thread-locked connection.
        """
        if self.conn is None:
            try:
                os.makedirs(DATABASE_DIR, exist_ok=True)
                # check_same_thread=False allows sharing connection between threads, guarded by our conn_lock
                self.conn = sqlite3.connect(
                    str(self.db_path),
                    check_same_thread=False,
                    detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES
                )
                self.conn.row_factory = sqlite3.Row
                # Enable foreign key support
                self.conn.execute("PRAGMA foreign_keys = ON;")
                # Enable WAL mode for concurrent reads and writes
                self.conn.execute("PRAGMA journal_mode = WAL;")
            except sqlite3.Error as e:
                logger.error(f"SQLite Connection Error: {e}")
                raise e
        return self.conn

    def initialize_database(self):
        """Creates tables, foreign keys, and indices if they do not exist."""
        with self.conn_lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            try:
                # Devices Table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS devices (
                        device_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip_address TEXT NOT NULL,
                        mac_address TEXT,
                        hostname TEXT,
                        vendor TEXT,
                        status TEXT,
                        response_time REAL,
                        first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                        trusted INTEGER DEFAULT 0,
                        UNIQUE(mac_address)
                    )
                """)
                # Migration: add trusted column if missing (existing DBs)
                try:
                    cursor.execute("ALTER TABLE devices ADD COLUMN trusted INTEGER DEFAULT 0")
                except sqlite3.OperationalError:
                    pass  # column already exists

                # Port Scans Table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS port_scans (
                        scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        device_id INTEGER,
                        port INTEGER NOT NULL,
                        protocol TEXT NOT NULL,
                        service TEXT,
                        state TEXT NOT NULL,
                        risk TEXT,
                        banner TEXT DEFAULT '',
                        scan_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
                    )
                """)

                # Packets Table (Educational capture cache)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS packets (
                        packet_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        source_ip TEXT,
                        destination_ip TEXT,
                        protocol TEXT,
                        length INTEGER,
                        information TEXT
                    )
                """)

                # Reports History Table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS reports (
                        report_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        filename TEXT NOT NULL,
                        format TEXT NOT NULL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        security_score INTEGER,
                        location TEXT NOT NULL
                    )
                """)

                # Logs Table (Audit Trail)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS logs (
                        log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        level TEXT NOT NULL,
                        module TEXT NOT NULL,
                        message TEXT NOT NULL
                    )
                """)

                # Index creation to boost search performance
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip_address)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_port_scans_device ON port_scans(device_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(protocol)")

                # Migration: add banner column if missing (existing databases)
                try:
                    cursor.execute("ALTER TABLE port_scans ADD COLUMN banner TEXT DEFAULT ''")
                except sqlite3.OperationalError:
                    pass

                # Remove orphaned hidden column + fix any devices wrongly cleared
                try:
                    cursor.execute("SELECT hidden FROM devices LIMIT 1")
                    # Column exists — restore devices affected by the old buggy migration
                    cursor.execute("UPDATE devices SET status = 'Online' WHERE hidden = 1")
                    # Then drop the column (SQLite 3.35+)
                    try:
                        cursor.execute("ALTER TABLE devices DROP COLUMN hidden")
                    except sqlite3.OperationalError:
                        pass  # older SQLite — column stays but is harmless
                except sqlite3.OperationalError:
                    pass  # column doesn't exist — clean

                # Dedup: remove duplicate device entries for same IP
                try:
                    cursor.execute("""
                        DELETE FROM devices WHERE device_id NOT IN (
                            SELECT MIN(device_id) FROM devices GROUP BY ip_address
                        )
                    """)
                    if cursor.rowcount:
                        logger.info(f"Cleaned up {cursor.rowcount} duplicate device(s)")
                except sqlite3.Error as e:
                    logger.debug(f"Device dedup skipped: {e}")

                conn.commit()
                logger.info("Database initialized successfully.")
            except sqlite3.Error as e:
                conn.rollback()
                logger.error(f"Failed to initialize database tables: {e}")
                raise e

    def execute_write(self, query: str, params: tuple = ()) -> bool:
        """Executes a single write operation (INSERT, UPDATE, DELETE) inside lock thread boundary."""
        with self.conn_lock:
            conn = self._get_connection()
            try:
                conn.execute(query, params)
                conn.commit()
                return True
            except sqlite3.Error as e:
                conn.rollback()
                logger.error(f"SQL Write Error: {e} | Query: {query}")
                return False

    def execute_bulk_write(self, queries: List[Tuple[str, tuple]]) -> bool:
        """Executes multiple write operations in a single transaction."""
        with self.conn_lock:
            conn = self._get_connection()
            try:
                for query, params in queries:
                    conn.execute(query, params)
                conn.commit()
                return True
            except sqlite3.Error as e:
                conn.rollback()
                logger.error(f"SQL Bulk Write Error: {e}")
                return False

    def execute_read(self, query: str, params: tuple = ()) -> List[Dict[str, Any]]:
        """Executes a read query and returns results as a list of dicts."""
        with self.conn_lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(query, params)
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
            except sqlite3.Error as e:
                logger.error(f"SQL Read Error: {e} | Query: {query}")
                return []

    def close(self):
        """Closes the database connection."""
        with self.conn_lock:
            if self.conn:
                try:
                    self.conn.close()
                    self.conn = None
                    logger.info("Database connection closed.")
                except sqlite3.Error as e:
                    logger.error(f"Failed to close database: {e}")

    def delete_all_port_scans(self) -> bool:
        """Deletes all records from the port_scans table. Returns True on success."""
        return self.execute_write("DELETE FROM port_scans")

    def delete_all_packets(self) -> bool:
        """Deletes all records from the packets table. Returns True on success."""
        return self.execute_write("DELETE FROM packets")

    # --- Domain Specific CRUD APIs ---

    def upsert_device(self, ip_address: str, mac_address: str, hostname: str, vendor: str, status: str, response_time: float) -> Optional[int]:
        """
        Inserts a new device or updates last seen details if MAC already exists.
        Merges duplicate entries for same IP (one with MAC, one without).
        Returns the device_id of the upserted device.
        """
        now = datetime.now().isoformat()
        normalized_mac = mac_address if mac_address else None

        with self.conn_lock:
            conn = self._get_connection()
            try:
                if normalized_mac:
                    cursor = conn.execute("SELECT device_id FROM devices WHERE mac_address = ?", (normalized_mac,))
                else:
                    cursor = conn.execute(
                        "SELECT device_id FROM devices WHERE ip_address = ? AND mac_address IS NULL",
                        (ip_address,)
                    )
                row = cursor.fetchone()

                if row:
                    device_id = row[0]
                    conn.execute("""
                        UPDATE devices
                        SET ip_address = ?, mac_address = COALESCE(?, mac_address),
                            hostname = ?, vendor = ?, status = ?, response_time = ?, last_seen = ?
                        WHERE device_id = ?
                    """, (ip_address, normalized_mac, hostname, vendor, status, response_time, now, device_id))
                else:
                    # Check if IP exists with different MAC state, merge instead of insert
                    merged_id = None
                    if normalized_mac:
                        cursor = conn.execute(
                            "SELECT device_id FROM devices WHERE ip_address = ? AND mac_address IS NULL",
                            (ip_address,)
                        )
                    else:
                        cursor = conn.execute(
                            "SELECT device_id FROM devices WHERE ip_address = ? AND mac_address IS NOT NULL",
                            (ip_address,)
                        )
                    row2 = cursor.fetchone()
                    if row2:
                        merged_id = row2[0]
                        conn.execute("""
                            UPDATE devices
                            SET mac_address = COALESCE(?, mac_address), hostname = ?,
                                vendor = ?, status = ?, response_time = ?, last_seen = ?
                            WHERE device_id = ?
                        """, (normalized_mac, hostname, vendor, status, response_time, now, merged_id))
                    if merged_id:
                        device_id = merged_id
                    else:
                        cursor = conn.execute("""
                            INSERT INTO devices (ip_address, mac_address, hostname, vendor, status, response_time, first_seen, last_seen)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """, (ip_address, normalized_mac, hostname, vendor, status, response_time, now, now))
                        device_id = cursor.lastrowid
                conn.commit()
                return device_id
            except sqlite3.Error as e:
                conn.rollback()
                logger.error(f"Device upsert failed: {e}")
                return None

    def set_device_trusted(self, device_id: int, trusted: bool) -> bool:
        """Sets the trusted flag on a device (whitelist/ignore)."""
        return self.execute_write(
            "UPDATE devices SET trusted = ? WHERE device_id = ?",
            (1 if trusted else 0, device_id),
        )

    def save_port_scans(self, device_id: int, scans: List[Dict[str, Any]]) -> bool:
        """
        Saves a list of scanned ports for a specific device.
        Deletes only old scans for same device+protocol before inserting fresh results,
        allowing TCP and UDP results to coexist.
        """
        now = datetime.now().isoformat()
        delete_query = "DELETE FROM port_scans WHERE device_id = ? AND protocol = ?"
        insert_query = """
            INSERT INTO port_scans (device_id, port, protocol, service, state, risk, banner, scan_time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        protocols = set(s["protocol"] for s in scans)
        bulk = [(delete_query, (device_id, proto)) for proto in protocols]
        for s in scans:
            bulk.append((
                insert_query,
                (device_id, s["port"], s["protocol"], s["service"], s["state"], s["risk"], s.get("banner", ""), now)
            ))
        return self.execute_bulk_write(bulk)

    def log_packet(self, source_ip: str, destination_ip: str, protocol: str, length: int, information: str) -> bool:
        """Logs a single sniffed packet event."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        query = """
            INSERT INTO packets (timestamp, source_ip, destination_ip, protocol, length, information)
            VALUES (?, ?, ?, ?, ?, ?)
        """
        return self.execute_write(query, (now, source_ip, destination_ip, protocol, length, information))

    def save_report(self, filename: str, format_type: str, security_score: int, location: str) -> bool:
        """Logs a report generation event to the database history."""
        now = datetime.now().isoformat()
        query = """
            INSERT INTO reports (filename, format, created_at, security_score, location)
            VALUES (?, ?, ?, ?, ?)
        """
        return self.execute_write(query, (filename, format_type, now, security_score, location))

    def log_event(self, level: str, module: str, message: str) -> bool:
        """Logs an event audit log entry directly to the sqlite database logs table."""
        now = datetime.now().isoformat()
        query = """
            INSERT INTO logs (timestamp, level, module, message)
            VALUES (?, ?, ?, ?)
        """
        return self.execute_write(query, (now, level, module, message))

    def clean_old_packets(self, max_limit: int = 5000) -> bool:
        """Purges old packets if count exceeds max_limit (Default retention policy)."""
        with self.conn_lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM packets")
                count = cursor.fetchone()[0]
                if count > max_limit:
                    diff = count - max_limit
                    cursor.execute(
                        "SELECT packet_id FROM packets ORDER BY packet_id ASC LIMIT ?",
                        (diff,)
                    )
                    cursor.execute(
                        "DELETE FROM packets WHERE packet_id IN (SELECT packet_id FROM packets ORDER BY packet_id ASC LIMIT ?)",
                        (diff,)
                    )
                    conn.commit()
                    logger.info(f"Purged {diff} old packet database logs.")
                return True
            except sqlite3.Error as e:
                conn.rollback()
                logger.error(f"Failed to purge old packets: {e}")
                return False

    def clean_old_logs(self, max_limit: int = 10000) -> bool:
        """Purges old log entries if count exceeds max_limit."""
        with self.conn_lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM logs")
                count = cursor.fetchone()[0]
                if count > max_limit:
                    diff = count - max_limit
                    cursor.execute(
                        "DELETE FROM logs WHERE log_id IN (SELECT log_id FROM logs ORDER BY log_id ASC LIMIT ?)",
                        (diff,)
                    )
                    conn.commit()
                    logger.info(f"Purged {diff} old log entries.")
                return True
            except sqlite3.Error as e:
                conn.rollback()
                logger.error(f"Failed to purge old logs: {e}")
                return False
