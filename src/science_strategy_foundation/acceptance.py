"""运行科研计算溯源与发布系统的离线端到端验收。

故事线：两份候选材料结果分子结构相同，但训练数据授权、模型参数、筛选步骤
版本组合不一致。系统必须让离线节点可补交、异常进隔离区、发布快照不可变、
撤回产生影响分析并阻断后续发布，并按角色给出不同的可见范围。
"""

from __future__ import annotations

import base64
import copy
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .audit import digest, digest_bytes
from .clock import FixedClock
from .errors import ConflictError, PermissionDenied
from .nodeclient import LocalEventLog
from .provenance import ProvenanceService
from .service import DomainService
from .storage import Database


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _artifact_event(data: bytes, media_type: str = "application/json") -> tuple[str, dict]:
    artifact_id = digest_bytes(data)
    return artifact_id, {
        "artifact_id": artifact_id,
        "media_type": media_type,
        "content_base64": _b64(data),
    }


def run() -> dict[str, object]:
    with tempfile.TemporaryDirectory() as directory:
        database = Database(Path(directory) / "provenance.sqlite3")
        clock = FixedClock(datetime(2026, 10, 6, 9, 0, tzinfo=timezone.utc))
        service = DomainService(database, clock)
        provenance = ProvenanceService(database, clock)

        # ── 组织与角色 ─────────────────────────────────────────
        service.register_organization(request_id="org", actor_id="bootstrap",
                                      organization_id="o1", name="计算科学平台")
        service.register_actor(request_id="admin", actor_id="bootstrap", new_actor_id="a1",
                               display_name="管理员", role="admin", organization_id="o1")
        service.register_actor(request_id="op", actor_id="a1", new_actor_id="op1",
                               display_name="计算研究员", role="operator", organization_id="o1")
        service.register_actor(request_id="rev", actor_id="a1", new_actor_id="rv1",
                               display_name="发布审核员", role="reviewer", organization_id="o1")
        service.register_actor(request_id="au", actor_id="a1", new_actor_id="au1",
                               display_name="科研诚信员", role="auditor", organization_id="o1")
        service.register_actor(request_id="owner", actor_id="a1", new_actor_id="owner1",
                               display_name="数据权利人", role="operator", organization_id="o1")

        provenance.register_node(actor_id="a1", node_id="node-001",
                                 organization_id="o1", name="离线算力节点一")

        # ── 离线节点构造本地事件链 ─────────────────────────────
        log = LocalEventLog("node-001")
        t0 = 1

        def at(minute: int) -> str:
            return f"2026-10-06T08:{minute:02d}:00Z"

        def emit(event_type: str, payload: dict) -> dict:
            nonlocal t0
            envelope = log.build(event_type, payload, occurred_at=at(t0))
            t0 += 1
            return envelope

        emit("environment_registered", {
            "environment_id": "env-001",
            "fingerprint": {"os": "linux-6.6", "python": "3.11.9", "cuda": "12.4",
                            "packages": {"torch": "2.5.0", "numpy": "2.1.0"}},
        })
        emit("workflow_registered", {
            "workflow_id": "wf-screen-001",
            "definition": {"name": "候选材料筛选",
                           "steps": ["数据加载", "特征化", "模型打分", "人工复核"]},
        })

        data_v1 = json.dumps({"dataset": "DS1", "version": "v1", "rows": 12000}).encode()
        d1, d1_payload = _artifact_event(data_v1)
        emit("artifact_put", d1_payload)
        emit("dataset_registered", {
            "dataset_id": "DS1", "version": "v1", "artifact_id": d1,
            "license": {"name": "CC-BY-4.0", "publish_allowed": True},
            "calibration": {"method": "standard-a", "checked_at": "2026-09-01"},
        })

        data_v2 = json.dumps({"dataset": "DS1", "version": "v2", "rows": 15300}).encode()
        d2, d2_payload = _artifact_event(data_v2)
        emit("artifact_put", d2_payload)
        emit("dataset_registered", {
            "dataset_id": "DS1", "version": "v2", "artifact_id": d2,
            "license": {"name": "PROPRIETARY-RESTRICTED", "publish_allowed": False},
            "calibration": {"method": "standard-b", "checked_at": "2026-09-20"},
        })

        weights = b"WEIGHTS-BLOB-v1"
        wid, w_payload = _artifact_event(weights, "application/octet-stream")
        emit("artifact_put", w_payload)
        emit("model_registered", {
            "model_config_id": "model-001",
            "params": {"arch": "matformer", "layers": 6, "learning_rate": 0.001},
            "weights_artifact_id": wid, "calibration_status": "valid",
        })
        emit("model_registered", {
            "model_config_id": "model-002",
            "params": {"arch": "matformer", "layers": 8, "learning_rate": 0.0003},
            "weights_artifact_id": wid, "calibration_status": "valid",
        })

        candidate = json.dumps({"molecule": "C6H6-X1", "smiles": "c1ccccc1", "score": 0.91}).encode()
        cand_id, cand_payload = _artifact_event(candidate)
        emit("artifact_put", cand_payload)

        emit("run_recorded", {
            "run_id": "run-A", "workflow_id": "wf-screen-001", "environment_id": "env-001",
            "seed": "42",
            "steps": [{"step_order": 1, "action": "screen", "model_config_id": "model-001",
                       "inputs": [{"kind": "dataset", "dataset_id": "DS1", "version": "v1"}],
                       "outputs": [cand_id]}],
        })
        emit("run_recorded", {
            "run_id": "run-B", "workflow_id": "wf-screen-001", "environment_id": "env-001",
            "seed": "7",
            "steps": [{"step_order": 1, "action": "screen", "model_config_id": "model-002",
                       "inputs": [{"kind": "dataset", "dataset_id": "DS1", "version": "v2"}],
                       "outputs": [cand_id]}],
        })
        emit("decision_recorded", {
            "decision_id": "dec-run-a", "subject_kind": "run", "subject_id": "run-A",
            "verdict": "approved", "rationale": "参数与种子可复算，建议交实验验证",
        })
        emit("decision_recorded", {
            "decision_id": "dec-cand", "subject_kind": "artifact", "subject_id": cand_id,
            "verdict": "needs_recheck", "rationale": "存在两份不一致的版本组合，暂缓公开",
        })

        # 合规重跑：使用授权允许发布的 v1 与相同种子，产出独立确认制品
        confirmed = json.dumps({"molecule": "C6H6-X1", "smiles": "c1ccccc1", "score": 0.91,
                                "confirmed_by": "run-C"}).encode()
        confirmed_id, confirmed_payload = _artifact_event(confirmed)
        emit("artifact_put", confirmed_payload)
        emit("run_recorded", {
            "run_id": "run-C", "workflow_id": "wf-screen-001", "environment_id": "env-001",
            "seed": "42",
            "steps": [{"step_order": 1, "action": "screen", "model_config_id": "model-001",
                       "inputs": [{"kind": "dataset", "dataset_id": "DS1", "version": "v1"}],
                       "outputs": [confirmed_id]}],
        })

        # 节点恢复后准备补交的额外事件（用于演示缺前驱）
        extra1 = b"EXTRA-ARTIFACT-1"
        extra1_id, extra1_payload = _artifact_event(extra1)
        env_gap1 = emit("artifact_put", extra1_payload)   # seq 17
        extra2 = b"EXTRA-ARTIFACT-2"
        extra2_id, extra2_payload = _artifact_event(extra2)
        env_gap2 = emit("artifact_put", extra2_payload)   # seq 18

        # ── 恢复连接，批量补交主链（seq 1..16）─────────────────
        main_events = log.events[:16]
        results = provenance.ingest_batch(main_events, submitted_by="op1")
        assert all(r["status"] == "admitted" and not r["replayed"] for r in results), results

        # 重复上传保持幂等
        replay = provenance.ingest(main_events[0], submitted_by="op1")
        assert replay["status"] == "admitted" and replay["replayed"] is True, replay

        # ── 异常一：前驱缺失（seq 18 先于 17 到达）──────────────
        q_gap = provenance.ingest(env_gap2, submitted_by="op1")
        assert q_gap["status"] == "quarantined" and q_gap["reason"] == "predecessor_missing", q_gap
        # 补交缺口事件 seq 17
        assert provenance.ingest(env_gap1, submitted_by="op1")["status"] == "admitted"
        # 自动重扫隔离区，seq 18 放行
        rescanned = provenance.rescan_pending("au1")
        assert q_gap["qid"] in rescanned["admitted_qids"], rescanned

        # ── 异常二：时钟倒退 ───────────────────────────────────
        clock_material = {
            "event_id": "node-001-19", "node_id": "node-001", "seq": 19,
            "occurred_at": "2026-09-01T00:00:00Z", "event_type": "artifact_put",
            "payload": {"artifact_id": extra2_id, "media_type": "application/octet-stream",
                        "content_base64": _b64(b"old-device-export")},
            "previous_hash": env_gap2["event_hash"],
        }
        # 注意：内容与 artifact_id 不符会先报 hash_mismatch，这里让内容自洽
        old_content = b"old-device-export"
        clock_material["payload"]["artifact_id"] = digest_bytes(old_content)
        clock_material["payload"]["content_base64"] = _b64(old_content)
        clock_env = {**clock_material, "event_hash": digest(clock_material)}
        q_clock = provenance.ingest(clock_env, submitted_by="op1")
        assert q_clock["status"] == "quarantined" and q_clock["reason"] == "clock_regression", q_clock
        # 重复提交隔离事件保持幂等
        q_clock_replay = provenance.ingest(clock_env, submitted_by="op1")
        assert q_clock_replay["replayed"] is True, q_clock_replay
        # 诚信员核查后强制接受（时钟类异常允许接受，内容类异常不允许）
        adj = provenance.adjudicate_quarantine(actor_id="au1", qid=q_clock["qid"],
                                               decision="accept", rationale="确认为设备时钟故障，人工核验内容无误")
        assert adj["decision"] == "accept", adj

        # ── 异常三：哈希不符（篡改载荷）────────────────────────
        tampered = copy.deepcopy(env_gap1)
        tampered["event_id"] = "node-001-20"
        tampered["seq"] = 20
        tampered["payload"] = {"artifact_id": "x" * 64, "media_type": "application/json",
                               "content_base64": _b64(b"tampered")}
        # event_hash 保持原值，重算必然不符
        q_bad = provenance.ingest(tampered, submitted_by="op1")
        assert q_bad["status"] == "quarantined" and q_bad["reason"] == "hash_mismatch", q_bad
        provenance.adjudicate_quarantine(actor_id="au1", qid=q_bad["qid"],
                                         decision="dismiss", rationale="载荷与哈希不符，驳回")

        chain = provenance.verify_lineage_chain("au1")
        assert chain["valid"] is True, chain

        # ── 研究人员复原：同一候选分子有两条不一致谱系 ─────────
        record = provenance.reconstruct_result(actor_id="op1", artifact_id=cand_id)
        run_ids = {run["run_id"] for run in record["runs"]}
        assert run_ids == {"run-A", "run-B"}, run_ids
        seeds = {run["seed"] for run in record["runs"]}
        assert seeds == {"42", "7"}, seeds
        models_used = {mid for run in record["runs"] for mid in run["models"]}
        assert models_used == {"model-001", "model-002"}, models_used
        assert record["datasets"]["DS1@v1"]["license"]["name"] == "CC-BY-4.0"
        assert record["datasets"]["DS1@v2"]["license"]["publish_allowed"] is False

        # ── 发布：含不合规谱系的结果被阻断 ─────────────────────
        provenance.create_release(actor_id="rv1", release_id="rel-mixed",
                                  result_artifacts=[cand_id], scope={"public": False})
        blocked = False
        try:
            provenance.publish_release(actor_id="rv1", release_id="rel-mixed")
        except ConflictError as exc:
            blocked = True
            assert any(b["type"] == "license_publish_denied" and b["version"] == "v2"
                       for b in exc.detail), exc.detail
        assert blocked

        # 合规重跑结果可以发布，快照固化完整版本组合
        provenance.create_release(actor_id="rv1", release_id="rel-ok",
                                  result_artifacts=[confirmed_id], scope={"public": True})
        published = provenance.publish_release(actor_id="rv1", release_id="rel-ok")
        snapshot_hash = published["snapshot_hash"]
        try:
            provenance.publish_release(actor_id="rv1", release_id="rel-ok")
            raise AssertionError("已发布快照不得再次发布")
        except ConflictError:
            pass

        snapshot = provenance.get_reference(actor_id="rv1", release_id="rel-ok")
        assert snapshot["snapshot_hash"] == snapshot_hash
        assert snapshot["runs"]["run-C"]["seed"] == "42"
        assert snapshot["runs"]["run-C"]["environment"]["fingerprint"]["cuda"] == "12.4"
        assert snapshot["datasets"]["DS1@v1"]["license"]["name"] == "CC-BY-4.0"

        # ── 数据权利人只能看见授权范围内的制品 ────────────────
        provenance.grant_license(actor_id="a1", grant_id="grant-1", grantee_actor_id="owner1",
                                 dataset_id="DS1", version="v1", actions=["read"])
        assert provenance.get_artifact(actor_id="owner1", artifact_id=d1, include_content=True)["visible"]
        denied = False
        try:
            provenance.get_artifact(actor_id="owner1", artifact_id=d2, include_content=True)
        except PermissionDenied:
            denied = True
        assert denied
        owner_view = provenance.get_reference(actor_id="owner1", release_id="rel-ok")
        assert set(owner_view["artifacts"]) == {confirmed_id, d1, wid}

        # 诚信员不受授权限制，可看到全部制品
        auditor_view = provenance.get_reference(actor_id="au1", release_id="rel-ok")
        assert len(auditor_view["artifacts"]) >= 3

        # ── 数据撤回：产生影响分析，历史发布被标记但不删除 ─────
        withdrawal = provenance.withdraw_dataset(actor_id="a1", dataset_id="DS1", version="v1",
                                                 reason="发现标注污染，v1 全部撤回")
        impact = provenance.get_impact_analysis(actor_id="au1",
                                                analysis_id=withdrawal["impact_analysis_id"])
        assert confirmed_id in impact["affected_artifacts"]
        assert cand_id in impact["affected_artifacts"]
        assert "run-A" in impact["affected_runs"] and "run-C" in impact["affected_runs"]
        assert "rel-ok" in impact["affected_releases"], impact

        historical = provenance.get_release("rv1", "rel-ok")
        assert historical["state"] == "published"
        assert historical["snapshot_hash"] == snapshot_hash
        assert any(m["advisory_id"] == withdrawal["advisory_id"]
                   for m in historical["status_marks"]), historical
        # 历史引用仍可复原，不删除历史
        assert provenance.get_reference(actor_id="au1", release_id="rel-ok")["snapshot_hash"] == snapshot_hash
        # 撤回阻断一切后续不合规发布（即使是此前合规的谱系）
        try:
            provenance.create_release(actor_id="rv1", release_id="rel-after-withdraw",
                                      result_artifacts=[confirmed_id], scope={"public": True})
            provenance.publish_release(actor_id="rv1", release_id="rel-after-withdraw")
            raise AssertionError("撤回后新发布必须被阻断")
        except ConflictError as exc:
            assert any(b["type"] == "dataset_withdrawn" for b in exc.detail), exc.detail

        # ── 校准失效：独立影响分析，精确追到 v2 谱系 ───────────
        calibration = provenance.invalidate_calibration(
            actor_id="a1", dataset_id="DS1", version="v2", reason="校准基准漂移")
        impact_v2 = provenance.get_impact_analysis(actor_id="au1",
                                                   analysis_id=calibration["impact_analysis_id"])
        assert "run-B" in impact_v2["affected_runs"]
        assert "run-C" not in impact_v2["affected_runs"], impact_v2
        assert cand_id in impact_v2["affected_artifacts"]

        # ── 诚信追溯：从异常来源正向追到所有受影响成果 ─────────
        forward = provenance.trace_forward(actor_id="au1", dataset_id="DS1", version="v1")
        assert confirmed_id in forward["affected_artifacts"]
        assert "rel-ok" in forward["affected_releases"], forward["affected_releases"]
        try:
            provenance.trace_forward(actor_id="owner1", dataset_id="DS1", version="v1")
            raise AssertionError("正向影响追踪仅限诚信/管理员角色")
        except PermissionDenied:
            pass

        quarantined_history = provenance.list_quarantine("au1", status="dismissed")
        assert any(item["qid"] == q_bad["qid"] for item in quarantined_history)

        database.close()
        return {
            "status": "ok",
            "candidate_artifact": cand_id,
            "lineage_runs": sorted(run_ids),
            "released_snapshot": snapshot_hash,
            "impact_analyses": 2,
            "quarantined_total": 3,
            "chain_valid": chain["valid"],
        }


def main() -> int:
    result = run()
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
