import base64
import unittest
from datetime import datetime, timezone

from science_strategy_foundation.audit import digest, digest_bytes
from science_strategy_foundation.clock import FixedClock
from science_strategy_foundation.errors import (
    ConflictError, NotFoundError, PermissionDenied, ValidationError,
)
from science_strategy_foundation.nodeclient import LocalEventLog
from science_strategy_foundation.provenance import ProvenanceService
from science_strategy_foundation.service import DomainService
from science_strategy_foundation.storage import Database


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


class ProvenanceTestBase(unittest.TestCase):
    def setUp(self):
        self.database = Database()
        self.clock = FixedClock(datetime(2026, 10, 6, tzinfo=timezone.utc))
        self.service = DomainService(self.database, self.clock)
        self.provenance = ProvenanceService(self.database, self.clock)
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
        self.service.register_actor(request_id="owner", actor_id="a1", new_actor_id="owner1",
                                    display_name="权利人", role="operator", organization_id="o1")
        self.provenance.register_node(actor_id="a1", node_id="n1", organization_id="o1", name="节点一")

    def tearDown(self):
        self.database.close()

    def chain(self, node_id="n1"):
        return LocalEventLog(node_id)

    def send(self, log, event_type, payload, *, minute=0, submitted_by="op1"):
        envelope = log.build(event_type, payload,
                             occurred_at=f"2026-10-06T08:{minute:02d}:00Z")
        return envelope, self.provenance.ingest(envelope, submitted_by=submitted_by)

    def artifact(self, log, data: bytes, *, minute: int, media_type="application/json"):
        aid = digest_bytes(data)
        _, result = self.send(log, "artifact_put",
                              {"artifact_id": aid, "media_type": media_type,
                               "content_base64": b64(data)}, minute=minute)
        self.assertEqual("admitted", result["status"], result)
        return aid

    def minimal_pipeline(self, *, dataset_license=None, publish_allowed=True,
                         calibration_valid=True, seed="42", model_id="m1"):
        """构造 env/wf/数据集/模型/结果/运行 的完整链，返回关键字段。"""
        log = self.chain()
        minute = 0
        _, r = self.send(log, "environment_registered",
                         {"environment_id": "env", "fingerprint": {"os": "linux", "cuda": "12.4"}},
                         minute=minute); minute += 1
        _, r = self.send(log, "workflow_registered",
                         {"workflow_id": "wf", "definition": {"steps": ["打分"]}},
                         minute=minute); minute += 1
        data = b"dataset-bytes-v1"
        data_id = self.artifact(log, data, minute=minute); minute += 1
        _, r = self.send(log, "dataset_registered",
                         {"dataset_id": "D", "version": "v1", "artifact_id": data_id,
                          "license": dataset_license or {"name": "CC-BY-4.0",
                                                          "publish_allowed": publish_allowed},
                          "calibration": {"method": "std-a"}}, minute=minute); minute += 1
        weights = b"weights"
        weights_id = self.artifact(log, weights, minute=minute,
                                   media_type="application/octet-stream"); minute += 1
        _, r = self.send(log, "model_registered",
                         {"model_config_id": model_id, "params": {"layers": 6},
                          "weights_artifact_id": weights_id,
                          "calibration_status": "valid" if calibration_valid else "invalid"},
                         minute=minute); minute += 1
        result = b"candidate-result"
        result_id = self.artifact(log, result, minute=minute); minute += 1
        _, r = self.send(log, "run_recorded",
                         {"run_id": "run-1", "workflow_id": "wf", "environment_id": "env",
                          "seed": seed,
                          "steps": [{"step_order": 1, "action": "screen",
                                     "model_config_id": model_id,
                                     "inputs": [{"kind": "dataset", "dataset_id": "D", "version": "v1"}],
                                     "outputs": [result_id]}]}, minute=minute)
        return {"log": log, "data_id": data_id, "weights_id": weights_id,
                "result_id": result_id, "minute": minute + 1}


class IngestionTest(ProvenanceTestBase):
    def test_admits_well_formed_chain(self):
        pipe = self.minimal_pipeline()
        events = self.provenance.list_lineage_events("au1", node_id="n1")
        self.assertEqual(8, len(events))
        chain = self.provenance.verify_lineage_chain("au1")
        self.assertTrue(chain["valid"])
        self.assertEqual(8, chain["nodes"]["n1"]["last_seq"])

    def test_duplicate_upload_is_idempotent(self):
        log = self.chain()
        envelope, first = self.send(log, "environment_registered",
                                    {"environment_id": "e", "fingerprint": {"os": "linux"}}, minute=0)
        self.assertFalse(first["replayed"])
        replay = self.provenance.ingest(envelope, submitted_by="op1")
        self.assertTrue(replay["replayed"])
        self.assertEqual("admitted", replay["status"])
        self.assertEqual(1, len(self.provenance.list_lineage_events("au1")))

    def test_tampered_payload_hash_mismatch_quarantines(self):
        log = self.chain()
        envelope = log.build("environment_registered",
                             {"environment_id": "e", "fingerprint": {"os": "linux"}},
                             occurred_at="2026-10-06T08:00:00Z")
        bad = dict(envelope)
        bad["payload"] = {"environment_id": "e", "fingerprint": {"os": "windows"}}
        result = self.provenance.ingest(bad, submitted_by="op1")
        self.assertEqual("quarantined", result["status"])
        self.assertEqual("hash_mismatch", result["reason"])

    def test_content_address_mismatch_quarantines(self):
        log = self.chain()
        data = b"abc"
        envelope = log.build("artifact_put",
                             {"artifact_id": "f" * 64, "media_type": "application/json",
                              "content_base64": b64(data)},
                             occurred_at="2026-10-06T08:00:00Z")
        result = self.provenance.ingest(envelope, submitted_by="op1")
        self.assertEqual("hash_mismatch", result["reason"])

    def test_unknown_node_quarantines(self):
        log = LocalEventLog("ghost-node")
        envelope = log.build("environment_registered",
                             {"environment_id": "e", "fingerprint": {}},
                             occurred_at="2026-10-06T08:00:00Z")
        result = self.provenance.ingest(envelope, submitted_by="op1")
        self.assertEqual("unknown_node", result["reason"])

    def test_sequence_gap_quarantines_until_predecessor_arrives(self):
        pipe = self.minimal_pipeline()
        log = pipe["log"]
        e17 = log.build("artifact_put",
                        {"artifact_id": digest_bytes(b"x1"), "media_type": "application/json",
                         "content_base64": b64(b"x1")},
                        occurred_at="2026-10-06T09:00:00Z")
        e18 = log.build("artifact_put",
                        {"artifact_id": digest_bytes(b"x2"), "media_type": "application/json",
                         "content_base64": b64(b"x2")},
                        occurred_at="2026-10-06T09:01:00Z")
        gap = self.provenance.ingest(e18, submitted_by="op1")
        self.assertEqual("predecessor_missing", gap["reason"])
        self.provenance.ingest(e17, submitted_by="op1")
        rescanned = self.provenance.rescan_pending("au1")
        self.assertEqual([gap["qid"]], rescanned["admitted_qids"])
        self.assertEqual([], [q for q in self.provenance.list_quarantine("au1")])

    def test_clock_regression_quarantined_and_adjudicable(self):
        pipe = self.minimal_pipeline()
        old = {
            "event_id": "n1-clock-fault", "node_id": "n1",
            "seq": pipe["log"].last_seq + 1,
            "occurred_at": "2020-01-01T00:00:00Z",
            "event_type": "environment_registered",
            "payload": {"environment_id": "env-old", "fingerprint": {"os": "old"}},
            "previous_hash": pipe["log"].last_hash,
        }
        old["event_hash"] = digest(old)
        result = self.provenance.ingest(old, submitted_by="op1")
        self.assertEqual("clock_regression", result["reason"])
        accepted = self.provenance.adjudicate_quarantine(
            actor_id="au1", qid=result["qid"], decision="accept",
            rationale="设备时钟故障，内容已人工核验")
        self.assertEqual("accept", accepted["decision"])

    def test_hash_mismatch_cannot_be_force_accepted(self):
        log = self.chain()
        envelope = log.build("environment_registered",
                             {"environment_id": "e", "fingerprint": {"os": "linux"}},
                             occurred_at="2026-10-06T08:00:00Z")
        bad = dict(envelope)
        bad["payload"] = {"environment_id": "e", "fingerprint": {"os": "windows"}}
        result = self.provenance.ingest(bad, submitted_by="op1")
        with self.assertRaises(ConflictError):
            self.provenance.adjudicate_quarantine(
                actor_id="au1", qid=result["qid"], decision="accept", rationale="不应被接受")

    def test_missing_reference_quarantines(self):
        log = self.chain()
        env = log.build("environment_registered",
                        {"environment_id": "env", "fingerprint": {}},
                        occurred_at="2026-10-06T08:00:00Z")
        self.provenance.ingest(env, submitted_by="op1")
        wf = log.build("workflow_registered",
                       {"workflow_id": "wf", "definition": {}},
                       occurred_at="2026-10-06T08:01:00Z")
        self.provenance.ingest(wf, submitted_by="op1")
        run = log.build("run_recorded",
                        {"run_id": "r", "workflow_id": "wf", "environment_id": "missing-env",
                         "seed": "1", "steps": [{"step_order": 1, "action": "a", "inputs": [],
                                                  "outputs": []}]},
                        occurred_at="2026-10-06T08:02:00Z")
        result = self.provenance.ingest(run, submitted_by="op1")
        self.assertEqual("reference_missing", result["reason"])

    def test_auditor_cannot_ingest(self):
        log = self.chain()
        envelope = log.build("environment_registered",
                             {"environment_id": "e", "fingerprint": {}},
                             occurred_at="2026-10-06T08:00:00Z")
        with self.assertRaises(PermissionDenied):
            self.provenance.ingest_event(envelope, submitted_by="au1")

    def test_quarantined_event_replay_returns_same_qid(self):
        log = self.chain()
        envelope = log.build("environment_registered",
                             {"environment_id": "e", "fingerprint": {}},
                             occurred_at="2026-10-06T08:00:00Z")
        future = dict(envelope)
        future["seq"] = 99
        first = self.provenance.ingest(future, submitted_by="op1")
        second = self.provenance.ingest(future, submitted_by="op1")
        self.assertEqual(first["qid"], second["qid"])
        self.assertTrue(second["replayed"])

    def test_same_event_id_with_changed_content_is_quarantined(self):
        log = self.chain()
        envelope = log.build("environment_registered",
                             {"environment_id": "e", "fingerprint": {"os": "linux"}},
                             occurred_at="2026-10-06T08:00:00Z")
        admitted = self.provenance.ingest(envelope, submitted_by="op1")
        self.assertEqual("admitted", admitted["status"])
        changed = dict(envelope)
        changed["payload"] = {"environment_id": "e", "fingerprint": {"os": "windows"}}
        result = self.provenance.ingest(changed, submitted_by="op1")
        self.assertEqual("quarantined", result["status"])
        self.assertEqual("sequence_conflict", result["reason"])
        # 原始事件仍在链上且链有效
        self.assertTrue(self.provenance.verify_lineage_chain("au1")["valid"])


class ReconstructionTest(ProvenanceTestBase):
    def test_result_reconstructs_full_version_combo(self):
        pipe = self.minimal_pipeline()
        record = self.provenance.reconstruct_result(
            actor_id="op1", artifact_id=pipe["result_id"])
        run = record["runs"][0]
        self.assertEqual("run-1", run["run_id"])
        self.assertEqual("42", run["seed"])
        self.assertEqual({"os": "linux", "cuda": "12.4"}, run["environment"]["fingerprint"])
        self.assertEqual({"layers": 6}, run["models"]["m1"]["params"])
        self.assertIn("D@v1", record["datasets"])
        self.assertTrue(record["compliance"]["publishable"])
        artifact_ids = {a["artifact_id"] for a in record["artifacts"]}
        self.assertIn(pipe["weights_id"], artifact_ids)
        self.assertIn(pipe["data_id"], artifact_ids)

    def test_two_runs_same_output_keep_distinct_lineage(self):
        pipe = self.minimal_pipeline(seed="42", model_id="m1")
        log = pipe["log"]
        # 第二条运行使用不同种子与模型，产出同一结果制品
        weights2 = self.artifact(log, b"w2", minute=pipe["minute"],
                                 media_type="application/octet-stream")
        self.send(log, "model_registered",
                  {"model_config_id": "m2", "params": {"layers": 8},
                   "weights_artifact_id": weights2}, minute=pipe["minute"] + 1)
        self.send(log, "run_recorded",
                  {"run_id": "run-2", "workflow_id": "wf", "environment_id": "env",
                   "seed": "7",
                   "steps": [{"step_order": 1, "action": "screen", "model_config_id": "m2",
                              "inputs": [{"kind": "dataset", "dataset_id": "D", "version": "v1"}],
                              "outputs": [pipe["result_id"]]}]}, minute=pipe["minute"] + 2)
        record = self.provenance.reconstruct_result(
            actor_id="op1", artifact_id=pipe["result_id"])
        self.assertEqual({"run-1", "run-2"}, {r["run_id"] for r in record["runs"]})
        self.assertEqual({"42", "7"}, {r["seed"] for r in record["runs"]})
        self.assertEqual({"m1", "m2"},
                         {mid for r in record["runs"] for mid in r["models"]})


class VisibilityTest(ProvenanceTestBase):
    def test_owner_sees_only_granted_dataset_artifacts(self):
        pipe = self.minimal_pipeline()
        # 第二个数据集 v2，不授权给 owner1
        log = pipe["log"]
        data2 = self.artifact(log, b"dataset-v2-bytes", minute=pipe["minute"])
        self.send(log, "dataset_registered",
                  {"dataset_id": "D", "version": "v2", "artifact_id": data2,
                   "license": {"name": "RESTRICTED", "publish_allowed": False}},
                  minute=pipe["minute"] + 1)
        self.provenance.grant_license(actor_id="a1", grant_id="g1", grantee_actor_id="owner1",
                                      dataset_id="D", version="v1", actions=["read"])
        visible = self.provenance.get_artifact(
            actor_id="owner1", artifact_id=pipe["data_id"], include_content=True)
        self.assertTrue(visible["visible"])
        with self.assertRaises(PermissionDenied):
            self.provenance.get_artifact(actor_id="owner1", artifact_id=data2, include_content=True)

    def test_metadata_endpoint_hides_content_without_grant(self):
        pipe = self.minimal_pipeline()
        meta = self.provenance.get_artifact(
            actor_id="owner1", artifact_id=pipe["data_id"])
        self.assertFalse(meta["visible"])
        self.assertNotIn("content_base64", meta)

    def test_reference_filters_artifacts_for_non_privileged_actor(self):
        pipe = self.minimal_pipeline()
        self.provenance.create_release(actor_id="rv1", release_id="rel",
                                       result_artifacts=[pipe["result_id"]],
                                       scope={"public": False})
        self.provenance.publish_release(actor_id="rv1", release_id="rel")
        self.provenance.grant_license(actor_id="a1", grant_id="g1", grantee_actor_id="owner1",
                                      dataset_id="D", version="v1", actions=["read"])
        view = self.provenance.get_reference(actor_id="owner1", release_id="rel")
        self.assertIn(pipe["data_id"], view["artifacts"])
        auditor = self.provenance.get_reference(actor_id="au1", release_id="rel")
        self.assertIn(pipe["weights_id"], auditor["artifacts"])


class ReleaseTest(ProvenanceTestBase):
    def test_published_snapshot_is_immutable(self):
        pipe = self.minimal_pipeline()
        self.provenance.create_release(actor_id="rv1", release_id="rel",
                                       result_artifacts=[pipe["result_id"]])
        published = self.provenance.publish_release(actor_id="rv1", release_id="rel")
        with self.assertRaises(ConflictError):
            self.provenance.publish_release(actor_id="rv1", release_id="rel")
        ref = self.provenance.get_reference(actor_id="au1", release_id="rel")
        self.assertEqual(published["snapshot_hash"], ref["snapshot_hash"])

    def test_license_forbidding_publication_blocks_release(self):
        pipe = self.minimal_pipeline(publish_allowed=False)
        self.provenance.create_release(actor_id="rv1", release_id="rel",
                                       result_artifacts=[pipe["result_id"]])
        with self.assertRaises(ConflictError) as context:
            self.provenance.publish_release(actor_id="rv1", release_id="rel")
        self.assertTrue(any(b["type"] == "license_publish_denied" for b in context.exception.detail))

    def test_invalid_calibration_blocks_release(self):
        pipe = self.minimal_pipeline(calibration_valid=False)
        self.provenance.create_release(actor_id="rv1", release_id="rel",
                                       result_artifacts=[pipe["result_id"]])
        with self.assertRaises(ConflictError) as context:
            self.provenance.publish_release(actor_id="rv1", release_id="rel")
        self.assertTrue(any(b["type"] == "model_calibration_invalid"
                            for b in context.exception.detail))

    def test_operator_cannot_publish(self):
        pipe = self.minimal_pipeline()
        self.provenance.create_release(actor_id="rv1", release_id="rel",
                                       result_artifacts=[pipe["result_id"]])
        with self.assertRaises(PermissionDenied):
            self.provenance.publish_release(actor_id="op1", release_id="rel")

    def test_unknown_result_artifact_rejected(self):
        with self.assertRaises(NotFoundError):
            self.provenance.create_release(actor_id="rv1", release_id="rel",
                                           result_artifacts=["deadbeef" * 8])


class WithdrawalTest(ProvenanceTestBase):
    def _published_release(self):
        pipe = self.minimal_pipeline()
        self.provenance.create_release(actor_id="rv1", release_id="rel",
                                       result_artifacts=[pipe["result_id"]],
                                       scope={"public": True})
        self.provenance.publish_release(actor_id="rv1", release_id="rel")
        return pipe

    def test_withdrawal_creates_impact_analysis_and_flags_release(self):
        pipe = self._published_release()
        outcome = self.provenance.withdraw_dataset(
            actor_id="a1", dataset_id="D", version="v1", reason="标注污染")
        impact = self.provenance.get_impact_analysis(
            actor_id="au1", analysis_id=outcome["impact_analysis_id"])
        self.assertIn(pipe["result_id"], impact["affected_artifacts"])
        self.assertIn("run-1", impact["affected_runs"])
        self.assertEqual(["rel"], impact["affected_releases"])
        release = self.provenance.get_release("au1", "rel")
        self.assertEqual("published", release["state"])
        self.assertTrue(release["status_marks"])

    def test_history_is_not_deleted_and_remains_reconstructable(self):
        pipe = self._published_release()
        before = self.provenance.get_reference(actor_id="au1", release_id="rel")
        self.provenance.withdraw_dataset(actor_id="a1", dataset_id="D", version="v1",
                                         reason="污染")
        after = self.provenance.get_reference(actor_id="au1", release_id="rel")
        self.assertEqual(before["snapshot_hash"], after["snapshot_hash"])

    def test_withdrawal_blocks_future_publications(self):
        pipe = self._published_release()
        self.provenance.withdraw_dataset(actor_id="a1", dataset_id="D", version="v1",
                                         reason="污染")
        self.provenance.create_release(actor_id="rv1", release_id="rel-2",
                                       result_artifacts=[pipe["result_id"]])
        with self.assertRaises(ConflictError) as context:
            self.provenance.publish_release(actor_id="rv1", release_id="rel-2")
        self.assertTrue(any(b["type"] == "dataset_withdrawn" for b in context.exception.detail))

    def test_calibration_invalidation_traces_only_affected_lineage(self):
        pipe_a = self.minimal_pipeline()
        self.provenance.create_release(actor_id="rv1", release_id="rel-a",
                                       result_artifacts=[pipe_a["result_id"]])
        self.provenance.publish_release(actor_id="rv1", release_id="rel-a")
        # 独立数据集 D2 谱系不受 D@v1 通告影响
        log = LocalEventLog("n1")
        # 让本地链从 n1 当前链尾继续：直接基于服务端状态无法重建 log，
        # 因此这里通过补交缺口机制不合适；改为复用 pipe_a 的 log 构造 D2 运行。
        # n1 链尾 seq=7，继续追加。
        log = pipe_a["log"]
        minute = 20
        d2 = self.artifact(log, b"dataset-2", minute=minute); minute += 1
        self.send(log, "dataset_registered",
                  {"dataset_id": "D2", "version": "v1", "artifact_id": d2,
                   "license": {"name": "CC0", "publish_allowed": True}}, minute=minute)
        minute += 1
        r2 = self.artifact(log, b"result-2", minute=minute); minute += 1
        self.send(log, "run_recorded",
                  {"run_id": "run-2", "workflow_id": "wf", "environment_id": "env",
                   "seed": "9",
                   "steps": [{"step_order": 1, "action": "screen", "model_config_id": "m1",
                              "inputs": [{"kind": "dataset", "dataset_id": "D2", "version": "v1"}],
                              "outputs": [r2]}]}, minute=minute)
        outcome = self.provenance.invalidate_calibration(
            actor_id="a1", dataset_id="D", version="v1", reason="基准漂移")
        impact = self.provenance.get_impact_analysis(
            actor_id="au1", analysis_id=outcome["impact_analysis_id"])
        self.assertIn("run-1", impact["affected_runs"])
        self.assertNotIn("run-2", impact["affected_runs"])
        self.assertNotIn(r2, impact["affected_artifacts"])

    def test_repeated_advisory_is_conflict(self):
        self._published_release()
        self.provenance.withdraw_dataset(actor_id="a1", dataset_id="D", version="v1",
                                         reason="第一次")
        with self.assertRaises(ConflictError):
            self.provenance.withdraw_dataset(actor_id="a1", dataset_id="D", version="v1",
                                             reason="第二次")


class ForwardTraceTest(ProvenanceTestBase):
    def test_forward_trace_from_dataset_covers_all_downstream(self):
        pipe = self.minimal_pipeline()
        trace = self.provenance.trace_forward(actor_id="au1", dataset_id="D", version="v1")
        self.assertIn(pipe["result_id"], trace["affected_artifacts"])
        self.assertIn("run-1", trace["affected_runs"])

    def test_forward_trace_requires_integrity_role(self):
        pipe = self.minimal_pipeline()
        with self.assertRaises(PermissionDenied):
            self.provenance.trace_forward(actor_id="op1", dataset_id="D", version="v1")


if __name__ == "__main__":
    unittest.main()
