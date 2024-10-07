import unittest
from dump.database import Database


class TestDatabase(unittest.TestCase):
    def setUp(self):
        self.db = Database(db_path=":memory:")  # Use in-memory database for testing
        self.db.create_tables()

    def test_bulk_insert_entries(self):
        entries = [
            {
                "address": "0x1000",
                "offset": "0x0",
                "raw": "deadbeef",
                "string": "test",
                "integer": "3735928559",
                "float_num": 3.14,
                "module": "test_module",
            },
            {
                "address": "0x2000",
                "offset": "0x1000",
                "raw": "cafebabe",
                "string": "example",
                "integer": "3405691582",
                "float_num": 2.718,
                "module": "example_module",
            },
        ]
        self.db.bulk_insert_entries(entries)
        fetched_entries = self.db.fetch_all_entries()
        self.assertEqual(len(fetched_entries), 2)
        self.assertEqual(fetched_entries[0]["address"], "0x1000")
        self.assertEqual(fetched_entries[1]["module"], "example_module")

    def tearDown(self):
        self.db.close()


if __name__ == "__main__":
    unittest.main()
