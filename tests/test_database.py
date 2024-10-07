import unittest
from dump.database import Database
from dump.memory_entry import MemoryEntry


class TestDatabase(unittest.TestCase):
    def setUp(self):
        # Use an in-memory database for testing
        self.db = Database(db_path=":memory:")

    def test_insert_and_fetch_module(self):
        self.db.insert_module("test_module", "0x1000", 4096, "C:\\Path\\To\\test_module.exe")
        modules = self.db.fetch_all_modules()
        self.assertEqual(len(modules), 1)
        self.assertEqual(modules[0]['name'], "test_module")
        self.assertEqual(modules[0]['exe_path'], "C:\\Path\\To\\test_module.exe")

    def test_insert_and_fetch_memory_entry(self):
        entry = MemoryEntry(
            address="0x1000",
            offset="0x0",
            raw="deadbeef",
            string="test",
            integer=1234,
            float_num=56.78,
            module="test_module"
        )
        self.db.insert_memory_entry(entry)
        entries = self.db.fetch_all_memory_entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]['address'], "0x1000")
        self.assertEqual(entries[0]['string'], "test")
        self.assertEqual(entries[0]['integer'], 1234)
        self.assertEqual(entries[0]['float_num'], 56.78)
        self.assertEqual(entries[0]['module'], "test_module")

    def tearDown(self):
        self.db.close()


if __name__ == "__main__":
    unittest.main()