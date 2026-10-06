import unittest

from science_strategy_foundation.acceptance import run


class AcceptanceTest(unittest.TestCase):
    def test_offline_acceptance(self):
        result = run()
        self.assertEqual("ok", result["status"])
        self.assertTrue(result["chain_valid"])
        self.assertEqual(["run-A", "run-B"], result["lineage_runs"])
        self.assertEqual(2, result["impact_analyses"])
        self.assertEqual(3, result["quarantined_total"])
        self.assertTrue(result["released_snapshot"])


if __name__ == "__main__":
    unittest.main()
