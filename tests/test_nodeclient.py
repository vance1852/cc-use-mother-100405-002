import tempfile
import unittest
from pathlib import Path

from science_strategy_foundation.nodeclient import LocalEventLog


class LocalEventLogTest(unittest.TestCase):
    def test_local_chain_is_sequential_and_hash_linked(self):
        log = LocalEventLog("n1")
        e1 = log.build("environment_registered", {"environment_id": "e"},
                       occurred_at="2026-10-06T08:00:00Z")
        e2 = log.build("workflow_registered", {"workflow_id": "w"},
                       occurred_at="2026-10-06T08:01:00Z")
        self.assertEqual(1, e1["seq"])
        self.assertEqual(2, e2["seq"])
        self.assertEqual(e1["event_hash"], e2["previous_hash"])

    def test_local_log_rejects_clock_regression(self):
        log = LocalEventLog("n1")
        log.build("environment_registered", {"environment_id": "e"},
                  occurred_at="2026-10-06T08:00:00Z")
        with self.assertRaises(ValueError):
            log.build("workflow_registered", {"workflow_id": "w"},
                      occurred_at="2026-09-01T00:00:00Z")

    def test_persisted_jsonl_survives_restart_for_offline_catchup(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "node.jsonl"
            log = LocalEventLog("n1")
            log.build("environment_registered", {"environment_id": "e"},
                      occurred_at="2026-10-06T08:00:00Z")
            log.build("workflow_registered", {"workflow_id": "w"},
                      occurred_at="2026-10-06T08:01:00Z")
            log.append_to_file(path)

            # 节点重启后从 JSONL 恢复链状态，继续追加
            recovered = LocalEventLog.from_file(path)
            self.assertEqual(2, recovered.last_seq)
            e3 = recovered.build("artifact_put", {"artifact_id": "a" * 64},
                                  occurred_at="2026-10-06T08:02:00Z")
            self.assertEqual(3, e3["seq"])
            self.assertEqual(2, len(path.read_text().splitlines()))
            recovered.append_to_file(path)
            self.assertEqual(3, len(path.read_text().splitlines()))
            # 只追加新事件，不重复写旧事件
            recovered.append_to_file(path)
            self.assertEqual(3, len(path.read_text().splitlines()))

    def test_corrupted_local_log_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "node.jsonl"
            log = LocalEventLog("n1")
            event = log.build("environment_registered", {"environment_id": "e"},
                              occurred_at="2026-10-06T08:00:00Z")
            event["payload"] = {"environment_id": "tampered"}
            path.write_text(__import__("json").dumps(event, ensure_ascii=False))
            with self.assertRaises(ValueError):
                LocalEventLog.from_file(path)


if __name__ == "__main__":
    unittest.main()
