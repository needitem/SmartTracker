import sqlite3
import logging
from typing import List, Dict
import threading

logger = logging.getLogger(__name__)


class Database:
    _thread_local = threading.local()

    def __init__(self, db_path: str = "memory_analysis.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row  # Enable accessing columns by name
        self.create_tables()
        self.migrate_tables()

    def get_connection(self):
        if not hasattr(self._thread_local, "connection"):
            self._thread_local.connection = sqlite3.connect(self.db_path)
            self._thread_local.connection.row_factory = sqlite3.Row  # Set row_factory
        return self._thread_local.connection

    def create_tables(self):
        """Create the memory_entries and modules tables if they don't exist."""
        try:
            with self.conn:
                # Create memory_entries table
                self.conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS memory_entries (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        address TEXT,
                        offset TEXT,
                        raw TEXT,
                        string TEXT,
                        integer INTEGER,
                        float_num REAL,
                        module TEXT
                    )
                    """
                )
                # Create modules table
                self.conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS modules (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT,
                        base_address TEXT,
                        rss INTEGER
                    )
                    """
                )
                logger.debug("Database tables are set up.")
        except sqlite3.Error as e:
            logger.error(f"Error creating tables: {e}")

    def migrate_tables(self):
        """Handle schema migrations by adding missing columns and creating new tables."""
        try:
            with self.conn:
                # Check if 'memory_entries' has 'module' column
                cursor = self.conn.execute("PRAGMA table_info(memory_entries)")
                columns = [row["name"] for row in cursor.fetchall()]
                if "module" not in columns:
                    self.conn.execute(
                        "ALTER TABLE memory_entries ADD COLUMN module TEXT"
                    )
                    logger.info("Added 'module' column to 'memory_entries' table.")

                # Check if 'modules' table exists by attempting to query it
                try:
                    self.conn.execute("SELECT 1 FROM modules LIMIT 1")
                except sqlite3.Error:
                    self.create_tables()
                    logger.info("Created 'modules' table as it did not exist.")
        except sqlite3.Error as e:
            logger.error(f"Error migrating tables: {e}")

    def fetch_all_entries(self) -> List[Dict[str, str]]:
        """Fetch all memory entries from the memory_entries table."""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, address, offset, raw, string, integer, float_num, module
                FROM memory_entries
                """
            )
            rows = cursor.fetchall()
            results = [dict(row) for row in rows]
            logger.info(f"Fetched {len(results)} entries from the database.")
            return results
        except sqlite3.Error as e:
            logger.error(f"Error fetching entries: {e}")
            return []

    def fetch_all_modules(self) -> List[Dict[str, str]]:
        """Fetch all modules from the modules table."""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, name, base_address, rss FROM modules
                """
            )
            rows = cursor.fetchall()
            results = [dict(row) for row in rows]
            logger.info(f"Fetched {len(results)} modules from the database.")
            return results
        except sqlite3.Error as e:
            logger.error(f"Error fetching modules: {e}")
            return []

    def search_entries(self, field: str, query: str) -> List[Dict[str, str]]:
        """Search memory entries based on a specific field and query."""
        valid_fields = {
            "Address": "address",
            "Offset": "offset",
            "Raw": "raw",
            "String": "string",
            "Int": "integer",
            "Float": "float_num",
        }

        if field not in valid_fields:
            logger.error(f"Invalid search field: {field}")
            return []

        db_field = valid_fields[field]

        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            if db_field in {"integer", "float_num"}:
                # For numeric fields, attempt exact match or range search
                if db_field == "integer":
                    try:
                        int_query = int(query)
                        cursor.execute(
                            f"""
                            SELECT id, address, offset, raw, string, integer, float_num, module
                            FROM memory_entries
                            WHERE {db_field} = ?
                            """,
                            (int_query,),
                        )
                    except ValueError:
                        # If not a valid integer, return no results
                        logger.error(f"Invalid integer query: {query}")
                        return []
                elif db_field == "float_num":
                    try:
                        float_query = float(query)
                        cursor.execute(
                            f"""
                            SELECT id, address, offset, raw, string, integer, float_num, module
                            FROM memory_entries
                            WHERE {db_field} = ?
                            """,
                            (float_query,),
                        )
                    except ValueError:
                        # If not a valid float, return no results
                        logger.error(f"Invalid float query: {query}")
                        return []
            else:
                # For text fields, use LIKE for partial matches
                cursor.execute(
                    f"""
                    SELECT id, address, offset, raw, string, integer, float_num, module
                    FROM memory_entries
                    WHERE {db_field} LIKE ?
                    """,
                    (f"%{query}%",),
                )

            rows = cursor.fetchall()
            results = [dict(row) for row in rows]
            logger.info(
                f"Search for '{query}' in '{field}' returned {len(results)} results."
            )
            return results
        except sqlite3.Error as e:
            logger.error(f"Error searching entries: {e}")
            return []

    def update_entry(self, entry_id: int, update_fields: Dict[str, str]):
        """Update a memory entry with new fields."""
        try:
            conn = self.get_connection()
            with conn:
                placeholders = ", ".join(
                    [f"{key} = :{key}" for key in update_fields.keys()]
                )
                update_fields["id"] = entry_id
                conn.execute(
                    f"""
                    UPDATE memory_entries
                    SET {placeholders}
                    WHERE id = :id
                    """,
                    update_fields,
                )
                logger.debug(f"Updated entry ID {entry_id} with {update_fields}")
        except sqlite3.Error as e:
            logger.error(f"Error updating entry ID {entry_id}: {e}")

    def bulk_insert_entries(self, entries: List[Dict[str, str]]):
        """Bulk insert memory entries into the memory_entries table."""
        try:
            conn = self.get_connection()
            with conn:
                conn.executemany(
                    """
                    INSERT INTO memory_entries (address, offset, raw, string, integer, float_num, module)
                    VALUES (:Address, :Offset, :Raw, :String, :Int, :Float, :Module)
                    """,
                    entries,
                )
                logger.debug(
                    f"Inserted {len(entries)} memory entries into the database."
                )
        except sqlite3.Error as e:
            logger.error(f"Error bulk inserting entries: {e}")

    def bulk_insert_modules(self, modules: List[Dict[str, str]]):
        """Bulk insert modules into the modules table."""
        try:
            conn = self.get_connection()
            with conn:
                conn.executemany(
                    """
                    INSERT INTO modules (name, base_address, rss)
                    VALUES (:Name, :BaseAddress, :RSS)
                    """,
                    modules,
                )
                logger.debug(f"Inserted {len(modules)} modules into the database.")
        except sqlite3.Error as e:
            logger.error(f"Error bulk inserting modules: {e}")

    def close(self):
        """Close the database connection."""
        try:
            conn = getattr(self._thread_local, "connection", None)
            if conn:
                conn.close()
                del self._thread_local.connection
            self.conn.close()  # Close the main connection
            logger.debug("Database connections closed.")
        except sqlite3.Error as e:
            logger.error(f"Error closing the database connections: {e}")
