import base64
import unittest
from datetime import datetime, timezone

from science_strategy_foundation.api import route
from science_strategy_foundation.audit import digest_bytes
from science_strategy_foundation.clock import FixedClock
from science_strategy_foundation.nodeclient import LocalEventLog
from science_strategy_foundation.provenance import ProvenanceService
from science_strategy_foundation.service import DomainService
from science_strategy_foundation.storage import Database


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


class ProvenanceApiTest(unittest.TestCase):
    def setUp(self):
        self.database = Database()
        clock = FixedClock(datetime(2026, 10, 6, tzinfo=timezone.utc))
        self.service = DomainService(self.database, clock)
        self.provenance = ProvenanceService(self.database, clock)
        self.service.register_organization(request_id="org", actor_id="bootstrap",
                                           organization_id="o1", name="平台")
        self.service.register_actor(request_id="admin", actor_id="bootstrap", new_actor_id="a1",
                                    display_name="管理员", role="admin", organization_id="o1")
        self.service.register_actor(request_id="op", actor_id="a1", new_actor_id="op1",
                                    display_name="研究员", role="operator", organization_id="o1")
        self.service.register_actor(request_id="rev", actor_id="a1", new_actor_id="rv1",
                                    display_name="审核员", role="reviewer", organization_id="o1")
        self.service.register_actor(request_id="au", actor_id="a1", new_actor_id="au1",
                                    display_name="诚信员", role="auditor", organization_id="o1")
        status, _ = self.call("POST", "/nodes", {"node_id": "n1", "organization_id": "o1",
                                                  "name": "节点"}, {"X-Actor-Id": "a1"})
        self.assertEqual(201, status)

    def tearDown(self):
        self.database.close()

    def call(self, method, path, body=None, headers=None):
        return route(self.service, method, path, body or {}, headers, self.provenance)

    def test_health_still_reports_chain(self):
        status, payload = self.call("GET", "/health", None)
        self.assertEqual(200, status)
        self.assertEqual("ok", payload["status"])

    def test_full_pipeline_over_http(self):
        log = LocalEventLog("n1")
        events = []

        def emit(event_type, payload, minute):
            envelope = log.build(event_type, payload,
                                 occurred_at=f"2026-10-06T08:{minute:02d}:00Z")
            events.append(envelope)
            return envelope

        emit("environment_registered",
             {"environment_id": "env", "fingerprint": {"os": "linux"}}, 0)
        emit("workflow_registered", {"workflow_id": "wf", "definition": {}}, 1)
        data = b"dataset"
        data_id = digest_bytes(data)
        emit("artifact_put", {"artifact_id": data_id, "media_type": "application/json",
                              "content_base64": b64(data)}, 2)
        emit("dataset_registered",
             {"dataset_id": "D", "version": "v1", "artifact_id": data_id,
              "license": {"name": "CC-BY", "publish_allowed": True}}, 3)
        result = b"candidate"
        result_id = digest_bytes(result)
        emit("artifact_put", {"artifact_id": result_id, "media_type": "application/json",
                              "content_base64": b64(result)}, 4)
        emit("run_recorded",
             {"run_id": "run-1", "workflow_id": "wf", "environment_id": "env", "seed": "42",
              "steps": [{"step_order": 1, "action": "screen",
                         "inputs": [{"kind": "dataset", "dataset_id": "D", "version": "v1"}],
                         "outputs": [result_id]}]}, 5)

        status, payload = self.call("POST", "/ingest-batch", {"events": events},
                                    {"X-Actor-Id": "op1"})
        self.assertEqual(200, status)
        self.assertTrue(all(item["status"] == "admitted" for item in payload["items"]))

        # 重复批量上传保持幂等
        status, payload = self.call("POST", "/ingest-batch", {"events": events},
                                    {"X-Actor-Id": "op1"})
        self.assertTrue(all(item["replayed"] for item in payload["items"]))

        # 复原结果版本组合
        status, record = self.call("GET", f"/results/{result_id}", None, {"X-Actor-Id": "op1"})
        self.assertEqual(200, status)
        self.assertEqual("42", record["runs"][0]["seed"])

        # 创建并发布
        status, _ = self.call("POST", "/releases",
                              {"release_id": "rel", "result_artifacts": [result_id]},
                              {"X-Actor-Id": "rv1"})
        self.assertEqual(201, status)
        status, published = self.call("POST", "/releases/rel/publish", {}, {"X-Actor-Id": "rv1"})
        self.assertEqual(200, status)
        status, ref = self.call("GET", "/references/rel", None, {"X-Actor-Id": "rv1"})
        self.assertEqual(200, status)
        self.assertEqual(published["snapshot_hash"], ref["snapshot_hash"])

        # 撤回 → 影响分析 → 发布被标记
        status, outcome = self.call("POST", "/datasets/withdraw",
                                    {"dataset_id": "D", "version": "v1", "reason": "污染"},
                                    {"X-Actor-Id": "a1"})
        self.assertEqual(200, status)
        status, impacts = self.call("GET", "/impact-analyses", None, {"X-Actor-Id": "au1"})
        self.assertEqual(200, status)
        self.assertEqual(1, len(impacts["items"]))

    def test_quarantined_event_returns_422(self):
        log = LocalEventLog("n1")
        envelope = log.build("environment_registered",
                             {"environment_id": "e", "fingerprint": {"os": "linux"}},
                             occurred_at="2026-10-06T08:00:00Z")
        envelope["payload"]["fingerprint"] = {"os": "tampered"}
        status, payload = self.call("POST", "/ingest", envelope, {"X-Actor-Id": "op1"})
        self.assertEqual(422, status)
        self.assertEqual("hash_mismatch", payload["reason"])
        status, listing = self.call("GET", "/quarantine", None, {"X-Actor-Id": "au1"})
        self.assertEqual(200, status)
        self.assertEqual(1, len(listing["items"]))

    def test_batch_with_one_bad_event_returns_207(self):
        good_log = LocalEventLog("n1")
        good = good_log.build("environment_registered",
                              {"environment_id": "e", "fingerprint": {}},
                              occurred_at="2026-10-06T08:00:00Z")
        bad = dict(good)
        bad["event_id"] = "bad"
        bad["payload"] = {"environment_id": "e", "fingerprint": {"os": "x"}}
        # 先提交 good，再提交 bad（bad 的 seq/前驱基于链首，篡改载荷即哈希不符）
        self.call("POST", "/ingest", good, {"X-Actor-Id": "op1"})
        status, payload = self.call("POST", "/ingest-batch", {"events": [good, bad]},
                                    {"X-Actor-Id": "op1"})
        self.assertEqual(207, status)
        self.assertEqual("admitted", payload["items"][0]["status"])
        self.assertEqual("quarantined", payload["items"][1]["status"])

    def test_operator_cannot_list_quarantine(self):
        status, payload = self.call("GET", "/quarantine", None, {"X-Actor-Id": "op1"})
        self.assertEqual(403, status)
        self.assertEqual("permission_denied", payload["error"])

    def test_lineage_verify_route(self):
        status, payload = self.call("GET", "/lineage/verify", None, {"X-Actor-Id": "au1"})
        self.assertEqual(200, status)
        self.assertTrue(payload["valid"])

    def test_forward_trace_route(self):
        status, payload = self.call("GET", "/trace/forward", None, {"X-Actor-Id": "op1"})
        self.assertEqual(403, status)


if __name__ == "__main__":
    unittest.main()
