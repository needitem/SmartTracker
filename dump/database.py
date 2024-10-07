import sqlite3
import os
import logging
import threading
from typing import List, Dict, Any, Union

from .memory_entry import MemoryEntry

logger = logging.getLogger(__name__)

class SingletonMeta(type):
    """A thread-safe implementation of Singleton."""
    _instances: Dict[Any, Any] = {}
    _lock: threading.Lock = threading.Lock()

    def __call__(cls, *args, **kwargs):
        # Double-checked locking to ensure thread safety
        if cls not in cls._instances:
            with cls._lock:
                if cls not in cls._instances:
                    instance = super().__call__(*args, **kwargs)
                    cls._instances[cls] = instance
        return cls._instances[cls]

class Database(metaclass=SingletonMeta):
    def __init__(self, db_path: str = "memory_analysis.db"):
        self.db_path = db_path
        self.lock = threading.Lock()
        path = os.path.dirname(self.db_path)
        if path:
            os.makedirs(path, exist_ok=True)
        # Ensure the database file is initialized correctly
        if not os.path.exists(self.db_path):
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30)
            self.conn.row_factory = sqlite3.Row  # Enable accessing columns by name
            self.set_wal_mode()
            self.create_tables()
            self.migrate_tables()
            logger.info(f"Database created at {self.db_path}.")
        else:
            # Verify if the existing file is a valid SQLite database
            try:
                self.conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30)
                self.conn.row_factory = sqlite3.Row  # Ensure row_factory is set
                self.conn.execute("SELECT name FROM sqlite_master WHERE type='table';")
                logger.info(f"Connected to existing database at {self.db_path}.")
            except sqlite3.Error as e:
                logger.error(f"Invalid database file: {e}. Reinitializing the database.")
                os.remove(self.db_path)
                self.conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30)
                self.conn.row_factory = sqlite3.Row
                self.set_wal_mode()
                self.create_tables()
                self.migrate_tables()

    def set_wal_mode(self):
        """Set the database to use Write-Ahead Logging for better concurrency."""
        try:
            self.conn.execute("PRAGMA journal_mode=WAL;")
            logger.debug("Set WAL mode for the database.")
        except sqlite3.Error as e:
            logger.error(f"Failed to set WAL mode: {e}")

    def create_tables(self):
        """Create necessary tables if they do not exist."""
        try:
            cursor = self.conn.cursor()
            # Create modules table with size and exe_path columns
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS modules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    exe_path TEXT,
                    base_address TEXT,
                    size INTEGER
                );
            """)
            # Create memory_entries table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS memory_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    address TEXT,
                    offset TEXT,
                    raw TEXT,
                    string TEXT,
                    integer INTEGER,
                    float_num REAL,
                    module TEXT
                );
            """)
            self.conn.commit()
            logger.debug("Database tables created or verified successfully.")
        except sqlite3.Error as e:
            logger.error(f"Failed to create tables: {e}")

    def migrate_tables(self):
        """Handle any necessary migrations (if applicable)."""
        # Implement migration logic if your database schema evolves over time
        pass

    def insert_module(self, name: str, base_address: str, size: int, exe_path: str):
        """Insert a module into the modules table."""
        try:
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute("""
                    INSERT INTO modules (name, exe_path, base_address, size)
                    VALUES (?, ?, ?, ?);
                """, (name, exe_path, base_address, size))
                self.conn.commit()
                logger.debug(f"Inserted module: {name}, Base Address: {base_address}, Size: {size}, Exe Path: {exe_path}")
        except sqlite3.Error as e:
            logger.error(f"Failed to insert module {name}: {e}")

    def insert_memory_entry(self, entry: Union[MemoryEntry, Dict[str, Any]]):
        """Insert a memory entry into the memory_entries table.

        Args:
            entry (MemoryEntry or Dict[str, Any]): The memory entry to insert.
        """
        try:
            with self.lock:
                cursor = self.conn.cursor()
                
                if isinstance(entry, MemoryEntry):
                    data = (
                        entry.address,
                        entry.offset,
                        entry.raw,
                        entry.string,
                        entry.integer,
                        entry.float_num,
                        entry.module
                    )
                elif isinstance(entry, dict):
                    data = (
                        entry.get('address'),
                        entry.get('offset'),
                        entry.get('raw'),
                        entry.get('string'),
                        entry.get('integer'),
                        entry.get('float_num'),
                        entry.get('module')
                    )
                else:
                    raise TypeError("entry must be a MemoryEntry instance or a dictionary")

                cursor.execute("""
                    INSERT INTO memory_entries (address, offset, raw, string, integer, float_num, module)
                    VALUES (?, ?, ?, ?, ?, ?, ?);
                """, data)
                self.conn.commit()
                if isinstance(entry, MemoryEntry):
                    logger.debug(f"Inserted memory entry at {entry.address}.")
                else:
                    logger.debug(f"Inserted memory entry at {entry.get('address', 'Unknown Address')}.")
        except sqlite3.Error as e:
            logger.error(f"Failed to insert memory entry: {e}")
        except TypeError as te:
            logger.error(f"Invalid memory entry type: {te}")

    def fetch_all_modules(self) -> List[Dict[str, Any]]:
        """Fetch all modules from the database."""
        try:
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute("SELECT * FROM modules;")
                rows = cursor.fetchall()
                if not rows:
                    logger.warning("No modules found in the database.")
                    return []

                # Ensure that row_factory is set to sqlite3.Row
                if not isinstance(rows[0], sqlite3.Row):
                    logger.error("Row factory is not set to sqlite3.Row. Cannot convert rows to dictionaries.")
                    raise TypeError("Row objects are not sqlite3.Row instances.")

                modules = [dict(row) for row in rows]
                logger.info(f"Fetched {len(modules)} modules from the database.")
                return modules
        except sqlite3.Error as e:
            logger.error(f"Failed to fetch modules: {e}")
            return []
        except TypeError as te:
            logger.error(f"Type error while fetching modules: {te}")
            return []

    def fetch_all_memory_entries(self) -> List[Dict[str, Any]]:
        """Fetch all memory entries from the database."""
        try:
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute("SELECT * FROM memory_entries;")
                rows = cursor.fetchall()
                if not rows:
                    logger.warning("No memory entries found in the database.")
                    return []

                # Ensure that row_factory is set to sqlite3.Row
                if not isinstance(rows[0], sqlite3.Row):
                    logger.error("Row factory is not set to sqlite3.Row. Cannot convert rows to dictionaries.")
                    raise TypeError("Row objects are not sqlite3.Row instances.")

                entries = [dict(row) for row in rows]
                logger.info(f"Fetched {len(entries)} memory entries from the database.")
                return entries
        except sqlite3.Error as e:
            logger.error(f"Failed to fetch memory entries: {e}")
            return []
        except TypeError as te:
            logger.error(f"Type error while fetching memory entries: {te}")
            return []

    def close(self):
        """Close the database connection."""
        try:
            with self.lock:
                if self.conn:
                    self.conn.close()
                    logger.debug("Database connection closed.")
        except sqlite3.Error as e:
            logger.error(f"Failed to close database connection: {e}")