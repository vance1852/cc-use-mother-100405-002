"""科研计算溯源：内容寻址制品、谱系事件链、隔离区与不可变发布。"""

from __future__ import annotations

import base64
import json
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from .audit import GENESIS_HASH, append_event, canonical_json, digest, digest_bytes
from .clock import Clock, SystemClock
from .errors import ConflictError, NotFoundError, PermissionDenied, ValidationError

EVENT_TYPES = frozenset({
    "artifact_put",
    "dataset_registered",
    "model_registered",
    "environment_registered",
    "workflow_registered",
    "run_recorded",
    "decision_recorded",
})
QUARANTINE_REASONS = frozenset({
    "malformed", "invalid_payload", "hash_mismatch", "unknown_node",
    "predecessor_missing", "chain_break", "clock_regression",
    "reference_missing", "sequence_conflict",
})
WRITE_ROLES = frozenset({"admin", "operator", "reviewer"})
GOVERNANCE_ROLES = frozenset({"admin", "auditor"})


class _Quarantine(Exception):
    """内部控制流：事件未通过准入，需要进入隔离区。"""

    def __init__(self, reason: str, detail: str, parsed: dict[str, Any] | None) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail
        self.parsed = parsed or {}


@dataclass
class LineageGraph:
    """内存中的谱系图索引，供闭包遍历复用。"""

    runs: dict[str, Any] = field(default_factory=dict)
    steps: dict[str, Any] = field(default_factory=dict)
    inputs: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    outputs: dict[str, list[str]] = field(default_factory=dict)
    output_to_steps: dict[str, list[str]] = field(default_factory=dict)

    def run_steps(self, run_id: str) -> list[Any]:
        return sorted((self.steps[s] for s in self.steps
                       if self.steps[s]["run_id"] == run_id),
                      key=lambda row: row["step_order"])


def _parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("occurred_at 必须是 ISO 8601 字符串")
    text = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        raise ValueError("occurred_at 必须携带时区")
    return parsed.astimezone()


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _norm_ts(value: Any) -> str:
    return _utc_text(_parse_timestamp(value))


class ProvenanceService:
    """协调离线事件准入、谱系查询、发布合规与影响分析。"""

    def __init__(self, database, clock: Clock | None = None) -> None:
        self.database = database
        self.clock = clock or SystemClock()

    def _now(self) -> str:
        return self.clock.now().isoformat().replace("+00:00", "Z")

    # ── 主体与角色 ──────────────────────────────────────────────

    def _actor(self, connection, actor_id: str):
        row = connection.execute("SELECT * FROM actors WHERE actor_id=?", (actor_id,)).fetchone()
        if row is None:
            raise NotFoundError("操作者不存在")
        if not row["active"]:
            raise PermissionDenied("操作者已停用")
        return row

    def _require(self, actor, *roles: str) -> None:
        if actor["role"] not in roles:
            raise PermissionDenied("当前角色不能执行该动作")

    def _node(self, connection, node_id: str, parsed: dict[str, Any] | None = None):
        row = connection.execute("SELECT * FROM compute_nodes WHERE node_id=?", (node_id,)).fetchone()
        if row is None:
            raise _Quarantine("unknown_node", f"算力节点 {node_id} 未登记", parsed)
        return row

    # ── 治理面：节点登记与授权 ─────────────────────────────────

    def register_node(self, *, actor_id: str, node_id: str,
                      organization_id: str, name: str) -> dict[str, Any]:
        name = str(name or "").strip()
        if not name:
            raise ValidationError("name 不能为空")
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "operator")
            if connection.execute("SELECT 1 FROM organizations WHERE organization_id=?",
                                  (organization_id,)).fetchone() is None:
                raise NotFoundError("组织不存在")
            try:
                connection.execute(
                    "INSERT INTO compute_nodes(node_id,organization_id,name,last_seq,last_event_hash,created_at) "
                    "VALUES(?,?,?,0,?,?)",
                    (node_id, organization_id, name, GENESIS_HASH, self._now()),
                )
            except Exception as exc:
                raise ConflictError("节点编号已经存在") from exc
            append_event(connection, actor_id=actor_id, action="node.registered",
                         resource_type="compute_node", resource_id=node_id,
                         detail={"organization_id": organization_id, "name": name},
                         occurred_at=self._now())
            return {"node_id": node_id, "organization_id": organization_id, "name": name}

    def list_nodes(self, actor_id: str) -> list[dict[str, Any]]:
        with self.database.transaction() as connection:
            self._actor(connection, actor_id)
            rows = connection.execute("SELECT * FROM compute_nodes ORDER BY node_id").fetchall()
        return [{"node_id": r["node_id"], "organization_id": r["organization_id"], "name": r["name"],
                 "last_seq": r["last_seq"], "last_event_hash": r["last_event_hash"],
                 "last_occurred_at": r["last_occurred_at"]} for r in rows]

    def grant_license(self, *, actor_id: str, grant_id: str, grantee_actor_id: str,
                      dataset_id: str, version: str | None = None,
                      actions: Iterable[str] = ("read",)) -> dict[str, Any]:
        actions = list(actions)
        if not actions:
            raise ValidationError("actions 不能为空")
        scope = {"actions": sorted(set(actions))}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin")
            if connection.execute("SELECT 1 FROM actors WHERE actor_id=? AND active=1",
                                  (grantee_actor_id,)).fetchone() is None:
                raise NotFoundError("被授权主体不存在或已停用")
            if version is not None and connection.execute(
                    "SELECT 1 FROM dataset_versions WHERE dataset_id=? AND version=?",
                    (dataset_id, version)).fetchone() is None:
                raise NotFoundError("数据集版本不存在")
            try:
                connection.execute(
                    "INSERT INTO license_grants(grant_id,grantee_actor_id,dataset_id,version,scope_json,"
                    "created_by,created_at) VALUES(?,?,?,?,?,?,?)",
                    (grant_id, grantee_actor_id, dataset_id, version, canonical_json(scope),
                     actor_id, self._now()),
                )
            except Exception as exc:
                raise ConflictError("授权编号已经存在或授权重复") from exc
            append_event(connection, actor_id=actor_id, action="license.granted",
                         resource_type="license_grant", resource_id=grant_id,
                         detail={"grantee_actor_id": grantee_actor_id, "dataset_id": dataset_id,
                                 "version": version, "scope": scope}, occurred_at=self._now())
            return {"grant_id": grant_id, "grantee_actor_id": grantee_actor_id,
                    "dataset_id": dataset_id, "version": version, "scope": scope}

    def _artifact_visible(self, connection, actor, artifact_id: str) -> bool:
        if actor["role"] in ("admin", "auditor"):
            return True
        row = connection.execute("SELECT 1 FROM artifacts WHERE artifact_id=?", (artifact_id,)).fetchone()
        if row is None:
            raise NotFoundError("制品不存在")
        if connection.execute(
                "SELECT 1 FROM artifacts WHERE artifact_id=? AND created_by=?",
                (artifact_id, actor["actor_id"])).fetchone():
            return True
        public_release = connection.execute(
            "SELECT 1 FROM releases r JOIN release_results rr ON rr.release_id=r.release_id "
            "WHERE r.state='published' AND rr.artifact_id=? AND json_extract(r.scope_json,'$.public')=1",
            (artifact_id,)).fetchone()
        dataset_row = connection.execute(
            "SELECT 1 FROM dataset_versions WHERE artifact_id=?", (artifact_id,)).fetchone()
        if dataset_row is not None:
            # 数据集内容制品严格按授权范围可见，不走组织默认可见。
            grant = connection.execute(
                "SELECT 1 FROM license_grants WHERE grantee_actor_id=? AND dataset_id IN "
                "(SELECT dataset_id FROM dataset_versions WHERE artifact_id=?) AND "
                "(version IS NULL OR version IN (SELECT version FROM dataset_versions WHERE artifact_id=?)) "
                "AND json_extract(scope_json,'$.actions') LIKE '%\"read\"%' LIMIT 1",
                (actor["actor_id"], artifact_id, artifact_id)).fetchone()
            return grant is not None
        # 非数据制品：同组织成员、公开出版物或创建者可见。
        if public_release is not None:
            return True
        same_org = connection.execute(
            "SELECT 1 FROM compute_nodes n JOIN actors a ON a.organization_id=n.organization_id "
            "WHERE n.node_id=(SELECT created_by FROM artifacts WHERE artifact_id=?) AND a.actor_id=?",
            (artifact_id, actor["actor_id"])).fetchone()
        return same_org is not None

    def get_artifact(self, *, actor_id: str, artifact_id: str, include_content: bool = False) -> dict[str, Any]:
        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            row = connection.execute("SELECT * FROM artifacts WHERE artifact_id=?", (artifact_id,)).fetchone()
            if row is None:
                raise NotFoundError("制品不存在")
            visible = self._artifact_visible(connection, actor, artifact_id)
            result: dict[str, Any] = {"artifact_id": artifact_id, "media_type": row["media_type"],
                                      "size_bytes": row["size_bytes"], "visible": visible}
            if include_content:
                if not visible:
                    raise PermissionDenied("该制品不在你的授权范围内")
                result["content_base64"] = base64.b64encode(row["content"]).decode("ascii")
            return result

    # ── 离线事件准入 ───────────────────────────────────────────

    HASH_FIELDS = ("event_id", "node_id", "seq", "occurred_at", "event_type", "payload", "previous_hash")

    def _validate_envelope(self, connection, envelope: Any) -> dict[str, Any]:
        if not isinstance(envelope, dict):
            raise _Quarantine("malformed", "事件必须是 JSON 对象", None)
        missing = [f for f in self.HASH_FIELDS if f not in envelope]
        if missing:
            raise _Quarantine("malformed", f"事件缺少字段: {','.join(missing)}",
                              {k: envelope.get(k) for k in ("event_id", "node_id", "seq")})
        parsed = {f: envelope[f] for f in self.HASH_FIELDS}
        if not isinstance(parsed["event_id"], str) or not parsed["event_id"]:
            raise _Quarantine("invalid_payload", "event_id 必须是非空字符串", parsed)
        if not isinstance(parsed["node_id"], str) or not parsed["node_id"]:
            raise _Quarantine("invalid_payload", "node_id 必须是非空字符串", parsed)
        if not isinstance(parsed["seq"], int) or isinstance(parsed["seq"], bool) or parsed["seq"] < 1:
            raise _Quarantine("invalid_payload", "seq 必须是正整数", parsed)
        if parsed["event_type"] not in EVENT_TYPES:
            raise _Quarantine("invalid_payload", f"未知事件类型 {parsed['event_type']}", parsed)
        if not isinstance(parsed["payload"], dict):
            raise _Quarantine("invalid_payload", "payload 必须是对象", parsed)
        if not isinstance(parsed["previous_hash"], str):
            raise _Quarantine("invalid_payload", "previous_hash 必须是字符串", parsed)
        try:
            parsed["_occurred"] = _parse_timestamp(parsed["occurred_at"])
        except ValueError as exc:
            raise _Quarantine("invalid_payload", str(exc), parsed) from exc
        material = {f: parsed[f] for f in self.HASH_FIELDS}
        if not isinstance(envelope.get("event_hash"), str) or digest(material) != envelope["event_hash"]:
            raise _Quarantine("hash_mismatch", "重算事件哈希与 event_hash 不符", parsed)
        parsed["event_hash"] = envelope["event_hash"]
        node = self._node(connection, parsed["node_id"], parsed)
        expected_seq = node["last_seq"] + 1
        if parsed["seq"] != expected_seq:
            raise _Quarantine("predecessor_missing",
                              f"节点本地序列断档：期望 {expected_seq}，收到 {parsed['seq']}", parsed)
        if parsed["previous_hash"] != node["last_event_hash"]:
            raise _Quarantine("chain_break",
                              "前驱哈希与节点链尾不一致，事件链无法衔接", parsed)
        if node["last_occurred_at"] is not None:
            last = _parse_timestamp(node["last_occurred_at"])
            if parsed["_occurred"] < last:
                raise _Quarantine("clock_regression",
                                  f"事件时间 {parsed['occurred_at']} 早于链尾时间 {node['last_occurred_at']}",
                                  parsed)
        self._validate_references(connection, parsed)
        return parsed

    def _validate_references(self, connection, event: dict[str, Any]) -> None:
        kind = event["event_type"]
        payload = event["payload"]
        require_artifact = lambda aid: (
            None if connection.execute("SELECT 1 FROM artifacts WHERE artifact_id=?", (aid,)).fetchone()
            else f"制品 {aid} 不存在")
        if kind == "artifact_put":
            try:
                content = base64.b64decode(payload["content_base64"], validate=True)
            except Exception as exc:
                raise _Quarantine("invalid_payload", "content_base64 不是合法 Base64", event) from exc
            if digest_bytes(content) != payload["artifact_id"]:
                raise _Quarantine("hash_mismatch",
                                  "artifact_id 不是内容的 SHA-256，内容寻址失败", event)
            return
        if kind == "dataset_registered":
            missing = require_artifact(payload["artifact_id"])
            if missing:
                raise _Quarantine("reference_missing", missing, event)
            return
        if kind == "model_registered":
            weights = payload.get("weights_artifact_id")
            if weights:
                missing = require_artifact(weights)
                if missing:
                    raise _Quarantine("reference_missing", missing, event)
            return
        if kind in ("environment_registered", "workflow_registered"):
            return
        if kind == "run_recorded":
            if connection.execute("SELECT 1 FROM workflows WHERE workflow_id=?",
                                  (payload["workflow_id"],)).fetchone() is None:
                raise _Quarantine("reference_missing", f"工作流 {payload['workflow_id']} 不存在", event)
            if connection.execute("SELECT 1 FROM environments WHERE environment_id=?",
                                  (payload["environment_id"],)).fetchone() is None:
                raise _Quarantine("reference_missing", f"环境指纹 {payload['environment_id']} 不存在", event)
            steps = payload.get("steps", [])
            if not isinstance(steps, list) or not steps:
                raise _Quarantine("invalid_payload", "steps 必须是非空数组", event)
            orders = sorted(s.get("step_order") for s in steps)
            if orders != list(range(1, len(steps) + 1)):
                raise _Quarantine("invalid_payload", "step_order 必须从 1 连续编号", event)
            for index, step in enumerate(steps, start=1):
                if not isinstance(step.get("action"), str) or not step["action"]:
                    raise _Quarantine("invalid_payload", f"步骤 {index} 缺少 action", event)
                model_id = step.get("model_config_id")
                if model_id and connection.execute(
                        "SELECT 1 FROM model_configs WHERE model_config_id=?", (model_id,)).fetchone() is None:
                    raise _Quarantine("reference_missing", f"步骤 {index} 的模型配置 {model_id} 不存在", event)
                for ref in step.get("inputs", []):
                    self._validate_ref(connection, event, ref, index)
                for output in step.get("outputs", []):
                    missing = require_artifact(output)
                    if missing:
                        raise _Quarantine("reference_missing",
                                          f"步骤 {index} 的输出{missing}", event)
            return
        if kind == "decision_recorded":
            subject_kind = payload.get("subject_kind")
            subject_id = payload.get("subject_id")
            exists = {
                "run": "SELECT 1 FROM runs WHERE run_id=?",
                "run_step": "SELECT 1 FROM run_steps WHERE step_id=?",
                "artifact": "SELECT 1 FROM artifacts WHERE artifact_id=?",
            }.get(subject_kind)
            if exists is None:
                raise _Quarantine("invalid_payload", f"人工判定对象类别 {subject_kind} 不受支持", event)
            if connection.execute(exists, (subject_id,)).fetchone() is None:
                raise _Quarantine("reference_missing",
                                  f"人工判定对象 {subject_kind}:{subject_id} 不存在", event)

    def _validate_ref(self, connection, event, ref: Any, index: int) -> None:
        if not isinstance(ref, dict) or "kind" not in ref:
            raise _Quarantine("invalid_payload", f"步骤 {index} 的输入引用格式错误", event)
        if ref["kind"] == "artifact":
            if connection.execute("SELECT 1 FROM artifacts WHERE artifact_id=?",
                                  (ref.get("artifact_id"),)).fetchone() is None:
                raise _Quarantine("reference_missing",
                                  f"步骤 {index} 引用的制品 {ref.get('artifact_id')} 不存在", event)
        elif ref["kind"] == "dataset":
            if connection.execute(
                    "SELECT 1 FROM dataset_versions WHERE dataset_id=? AND version=?",
                    (ref.get("dataset_id"), ref.get("version"))).fetchone() is None:
                raise _Quarantine("reference_missing",
                                  f"步骤 {index} 引用的数据集 {ref.get('dataset_id')}@{ref.get('version')} 不存在",
                                  event)
        else:
            raise _Quarantine("invalid_payload", f"步骤 {index} 的引用类型 {ref['kind']} 不受支持", event)

    def _apply_event(self, connection, event: dict[str, Any], *, forced: bool = False) -> None:
        kind = event["event_type"]
        payload = event["payload"]
        node_id = event["node_id"]
        occurred_at = _utc_text(event["_occurred"])
        if kind == "artifact_put":
            content = base64.b64decode(payload["content_base64"], validate=True)
            if connection.execute("SELECT 1 FROM artifacts WHERE artifact_id=?",
                                  (payload["artifact_id"],)).fetchone() is None:
                connection.execute(
                    "INSERT INTO artifacts(artifact_id,media_type,size_bytes,content,created_by,created_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (payload["artifact_id"], payload["media_type"], len(content), content,
                     node_id, occurred_at),
                )
        elif kind == "dataset_registered":
            existing = connection.execute(
                "SELECT * FROM dataset_versions WHERE dataset_id=? AND version=?",
                (payload["dataset_id"], payload["version"])).fetchone()
            if existing is None:
                connection.execute(
                    "INSERT INTO dataset_versions(dataset_id,version,artifact_id,license_json,calibration_json,"
                    "created_by,created_at) VALUES(?,?,?,?,?,?,?)",
                    (payload["dataset_id"], payload["version"], payload["artifact_id"],
                     canonical_json(payload["license"]),
                     canonical_json(payload["calibration"]) if payload.get("calibration") is not None else None,
                     node_id, occurred_at),
                )
            elif existing["artifact_id"] != payload["artifact_id"]:
                raise ConflictError("同一数据集版本已绑定不同内容制品")
        elif kind == "model_registered":
            existing = connection.execute(
                "SELECT * FROM model_configs WHERE model_config_id=?",
                (payload["model_config_id"],)).fetchone()
            if existing is None:
                connection.execute(
                    "INSERT INTO model_configs(model_config_id,params_json,weights_artifact_id,"
                    "calibration_status,created_by,created_at) VALUES(?,?,?,?,?,?)",
                    (payload["model_config_id"], canonical_json(payload["params"]),
                     payload.get("weights_artifact_id"),
                     payload.get("calibration_status", "valid"), node_id, occurred_at),
                )
            elif existing["params_json"] != canonical_json(payload["params"]):
                raise ConflictError("同一模型配置编号已登记不同参数")
        elif kind == "environment_registered":
            existing = connection.execute(
                "SELECT fingerprint_json FROM environments WHERE environment_id=?",
                (payload["environment_id"],)).fetchone()
            if existing is None:
                connection.execute(
                    "INSERT INTO environments(environment_id,fingerprint_json,created_by,created_at) "
                    "VALUES(?,?,?,?)",
                    (payload["environment_id"], canonical_json(payload["fingerprint"]), node_id, occurred_at),
                )
            elif existing["fingerprint_json"] != canonical_json(payload["fingerprint"]):
                raise ConflictError("同一环境编号已登记不同指纹")
        elif kind == "workflow_registered":
            existing = connection.execute(
                "SELECT definition_json FROM workflows WHERE workflow_id=?",
                (payload["workflow_id"],)).fetchone()
            if existing is None:
                connection.execute(
                    "INSERT INTO workflows(workflow_id,definition_json,created_by,created_at) VALUES(?,?,?,?)",
                    (payload["workflow_id"], canonical_json(payload["definition"]), node_id, occurred_at),
                )
            elif existing["definition_json"] != canonical_json(payload["definition"]):
                raise ConflictError("同一工作流编号已登记不同定义")
        elif kind == "run_recorded":
            run_id = payload["run_id"]
            if connection.execute("SELECT 1 FROM runs WHERE run_id=?", (run_id,)).fetchone() is None:
                connection.execute(
                    "INSERT INTO runs(run_id,workflow_id,environment_id,seed,created_by,occurred_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (run_id, payload["workflow_id"], payload["environment_id"], str(payload["seed"]),
                     node_id, occurred_at),
                )
                for step in payload["steps"]:
                    step_id = f"{run_id}:step-{step['step_order']}"
                    connection.execute(
                        "INSERT INTO run_steps(step_id,run_id,step_order,action,model_config_id) "
                        "VALUES(?,?,?,?,?)",
                        (step_id, run_id, step["step_order"], step["action"], step.get("model_config_id")),
                    )
                    for ref in step.get("inputs", []):
                        connection.execute(
                            "INSERT INTO run_step_inputs(step_id,ref_json) VALUES(?,?)",
                            (step_id, canonical_json(ref)),
                        )
                    for output in step.get("outputs", []):
                        connection.execute(
                            "INSERT OR IGNORE INTO run_step_outputs(step_id,artifact_id) VALUES(?,?)",
                            (step_id, output),
                        )
        elif kind == "decision_recorded":
            connection.execute(
                "INSERT OR IGNORE INTO human_decisions(decision_id,subject_kind,subject_id,verdict,"
                "rationale,decided_by,created_at) VALUES(?,?,?,?,?,?,?)",
                (payload["decision_id"], payload["subject_kind"], payload["subject_id"],
                 payload["verdict"], payload["rationale"], node_id, occurred_at),
            )
        connection.execute(
            "INSERT INTO lineage_events(event_id,node_id,seq,occurred_at,event_type,payload_json,"
            "previous_hash,event_hash,admitted_by,admitted_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (event["event_id"], node_id, event["seq"], occurred_at, kind,
             canonical_json(payload), event["previous_hash"], event["event_hash"],
             event.get("_admitted_by", "node"), self._now()),
        )
        connection.execute(
            "UPDATE compute_nodes SET last_seq=?,last_event_hash=?,last_occurred_at=? WHERE node_id=?",
            (event["seq"], event["event_hash"], occurred_at, node_id),
        )

    def ingest_event(self, envelope: Any, *, submitted_by: str = "anonymous") -> dict[str, Any]:
        """准入一个节点事件；失败则隔离，重复上传保持幂等。"""

        raw = canonical_json(envelope) if isinstance(envelope, dict) else json.dumps(envelope, ensure_ascii=False)
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, submitted_by)
            self._require(actor, *WRITE_ROLES)
            event_id = envelope.get("event_id") if isinstance(envelope, dict) else None
            if event_id:
                admitted = connection.execute(
                    "SELECT * FROM lineage_events WHERE event_id=?", (event_id,)).fetchone()
                if admitted is not None:
                    if all(f in envelope for f in self.HASH_FIELDS):
                        material = {f: envelope[f] for f in self.HASH_FIELDS}
                        if digest(material) != admitted["event_hash"]:
                            raise _Quarantine("sequence_conflict",
                                              "同一 event_id 已准入但内容不同，拒绝覆盖",
                                              {"event_id": event_id})
                    return {"status": "admitted", "replayed": True, "event_id": event_id,
                            "node_id": admitted["node_id"], "seq": admitted["seq"]}
                pending = connection.execute(
                    "SELECT * FROM quarantine_events WHERE event_id=? AND status='pending' ORDER BY qid DESC LIMIT 1",
                    (event_id,)).fetchone()
                if pending is not None:
                    if pending["raw_json"] == raw:
                        return {"status": "quarantined", "replayed": True, "qid": pending["qid"],
                                "reason": pending["reason"]}
                    raise _Quarantine("sequence_conflict",
                                      "同一 event_id 在隔离区中已有不同内容",
                                      {"event_id": event_id})
            try:
                parsed = self._validate_envelope(connection, envelope)
                parsed["_admitted_by"] = actor["actor_id"]
                self._apply_event(connection, parsed)
            except _Quarantine:
                raise
            except (sqlite3.Error, ConflictError, ValueError, KeyError, TypeError) as exc:
                raise _Quarantine("invalid_payload", f"事件应用失败: {exc}",
                                  envelope if isinstance(envelope, dict) else None) from exc
            append_event(connection, actor_id=actor["actor_id"], action="lineage.admitted",
                         resource_type="lineage_event", resource_id=parsed["event_id"],
                         detail={"node_id": parsed["node_id"], "seq": parsed["seq"],
                                 "event_type": parsed["event_type"]}, occurred_at=self._now())
            return {"status": "admitted", "replayed": False, "event_id": parsed["event_id"],
                    "node_id": parsed["node_id"], "seq": parsed["seq"]}

    def _quarantine(self, failure: _Quarantine, raw: str, submitted_by: str) -> dict[str, Any]:
        parsed = failure.parsed or {}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, submitted_by)
            cursor = connection.execute(
                "INSERT INTO quarantine_events(event_id,node_id,seq,event_hash,reason,reason_detail,"
                "raw_json,submitted_by,received_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (parsed.get("event_id"), parsed.get("node_id"), parsed.get("seq"),
                 parsed.get("event_hash"), failure.reason, failure.detail, raw,
                 actor["actor_id"], self._now()),
            )
            qid = cursor.lastrowid
            append_event(connection, actor_id=actor["actor_id"], action="lineage.quarantined",
                         resource_type="quarantine_event", resource_id=str(qid),
                         detail={"event_id": parsed.get("event_id"), "node_id": parsed.get("node_id"),
                                 "seq": parsed.get("seq"), "reason": failure.reason,
                                 "reason_detail": failure.detail}, occurred_at=self._now())
        return {"status": "quarantined", "replayed": False, "qid": qid, "reason": failure.reason,
                "detail": failure.detail}

    def ingest(self, envelope: Any, *, submitted_by: str = "anonymous") -> dict[str, Any]:
        """与存储无关的入口，把准入异常转换为隔离记录。"""

        try:
            return self.ingest_event(envelope, submitted_by=submitted_by)
        except _Quarantine as failure:
            raw = canonical_json(envelope) if isinstance(envelope, dict) else json.dumps(envelope, ensure_ascii=False)
            return self._quarantine(failure, raw, submitted_by)

    def ingest_batch(self, envelopes: list[Any], *, submitted_by: str = "anonymous") -> list[dict[str, Any]]:
        return [self.ingest(envelope, submitted_by=submitted_by) for envelope in envelopes]

    # ── 隔离区裁定与重扫 ───────────────────────────────────────

    def list_quarantine(self, actor_id: str, status: str = "pending") -> list[dict[str, Any]]:
        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *GOVERNANCE_ROLES)
            rows = connection.execute(
                "SELECT * FROM quarantine_events WHERE status=? ORDER BY qid", (status,)).fetchall()
        return [self._quarantine_row(row) for row in rows]

    def _quarantine_row(self, row) -> dict[str, Any]:
        return {"qid": row["qid"], "event_id": row["event_id"], "node_id": row["node_id"],
                "seq": row["seq"], "event_hash": row["event_hash"], "reason": row["reason"],
                "reason_detail": row["reason_detail"], "status": row["status"],
                "submitted_by": row["submitted_by"], "received_at": row["received_at"],
                "adjudicated_by": row["adjudicated_by"], "rationale": row["rationale"],
                "adjudicated_at": row["adjudicated_at"]}

    def adjudicate_quarantine(self, *, actor_id: str, qid: int,
                              decision: str, rationale: str) -> dict[str, Any]:
        if decision not in ("accept", "dismiss"):
            raise ValidationError("decision 必须是 accept 或 dismiss")
        rationale = str(rationale or "").strip()
        if not rationale:
            raise ValidationError("裁定必须填写理由")
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *GOVERNANCE_ROLES)
            row = connection.execute("SELECT * FROM quarantine_events WHERE qid=?", (qid,)).fetchone()
            if row is None:
                raise NotFoundError("隔离记录不存在")
            if row["status"] != "pending":
                raise ConflictError("该隔离记录已经裁定")
            if decision == "accept":
                try:
                    envelope = json.loads(row["raw_json"])
                    event_id = envelope.get("event_id")
                    if event_id and connection.execute(
                            "SELECT 1 FROM lineage_events WHERE event_id=?", (event_id,)).fetchone():
                        raise ConflictError("事件已在谱系日志中，无需接受")
                    node = self._node(connection, row["node_id"])
                    parsed = self._validate_envelope(connection, envelope)
                except _Quarantine as failure:
                    if failure.reason not in ("predecessor_missing", "chain_break", "clock_regression"):
                        raise ConflictError(f"仅可强制接受排序/时钟类异常，当前为 {failure.reason}") from failure
                    parsed = failure.parsed
                    if not parsed.get("event_hash"):
                        raise ConflictError("隔离事件缺少完整信封，无法强制接受") from failure
                parsed["_admitted_by"] = actor["actor_id"]
                parsed["_forced"] = True
                self._apply_event(connection, parsed)
            connection.execute(
                "UPDATE quarantine_events SET status=?,adjudicated_by=?,rationale=?,adjudicated_at=? "
                "WHERE qid=?",
                ("admitted" if decision == "accept" else "dismissed", actor["actor_id"],
                 rationale, self._now(), qid),
            )
            append_event(connection, actor_id=actor["actor_id"], action="quarantine.adjudicated",
                         resource_type="quarantine_event", resource_id=str(qid),
                         detail={"decision": decision, "rationale": rationale,
                                 "node_id": row["node_id"], "seq": row["seq"]},
                         occurred_at=self._now())
            return {"qid": qid, "decision": decision, "rationale": rationale}

    def rescan_pending(self, actor_id: str = "system") -> dict[str, Any]:
        """节点补交缺口事件后，自动重扫隔离区，按节点序列顺序放行。"""

        admitted: list[int] = []
        progressed = True
        while progressed:
            progressed = False
            with self.database.transaction(immediate=True) as connection:
                if actor_id != "system":
                    actor = self._actor(connection, actor_id)
                    self._require(actor, *GOVERNANCE_ROLES)
                rows = connection.execute(
                    "SELECT * FROM quarantine_events WHERE status='pending' ORDER BY node_id, seq, qid"
                ).fetchall()
                for row in rows:
                    try:
                        envelope = json.loads(row["raw_json"])
                        parsed = self._validate_envelope(connection, envelope)
                    except _Quarantine:
                        continue
                    parsed["_admitted_by"] = actor_id
                    self._apply_event(connection, parsed)
                    connection.execute(
                        "UPDATE quarantine_events SET status='admitted',adjudicated_by=?,rationale=?,"
                        "adjudicated_at=? WHERE qid=?",
                        (actor_id, "缺口补齐后自动重扫放行", self._now(), row["qid"]),
                    )
                    append_event(connection, actor_id=actor_id, action="quarantine.auto_admitted",
                                 resource_type="quarantine_event", resource_id=str(row["qid"]),
                                 detail={"node_id": row["node_id"], "seq": row["seq"]},
                                 occurred_at=self._now())
                    admitted.append(row["qid"])
                    progressed = True
                    break
        return {"admitted_qids": admitted, "count": len(admitted)}

    # ── 谱系图与闭包 ───────────────────────────────────────────

    def _load_graph(self, connection) -> LineageGraph:
        runs = {r["run_id"]: r for r in connection.execute("SELECT * FROM runs").fetchall()}
        steps = {s["step_id"]: s for s in connection.execute("SELECT * FROM run_steps").fetchall()}
        inputs: dict[str, list[dict[str, Any]]] = {}
        for row in connection.execute("SELECT * FROM run_step_inputs"):
            inputs.setdefault(row["step_id"], []).append(json.loads(row["ref_json"]))
        outputs: dict[str, list[str]] = {}
        output_to_steps: dict[str, list[str]] = {}
        for row in connection.execute("SELECT * FROM run_step_outputs"):
            outputs.setdefault(row["step_id"], []).append(row["artifact_id"])
            output_to_steps.setdefault(row["artifact_id"], []).append(row["step_id"])
        return LineageGraph(runs=runs, steps=steps, inputs=inputs, outputs=outputs,
                            output_to_steps=output_to_steps)

    def _backward_closure(self, connection, graph: LineageGraph, seeds: Iterable[str]) -> dict[str, Any]:
        visited_artifacts: set[str] = set()
        visited_runs: list[str] = []
        dataset_refs: set[tuple[str, str]] = set()
        stack = list(seeds)
        while stack:
            artifact_id = stack.pop()
            if artifact_id in visited_artifacts:
                continue
            visited_artifacts.add(artifact_id)
            for step_id in graph.output_to_steps.get(artifact_id, []):
                run_id = graph.steps[step_id]["run_id"]
                if run_id in visited_runs:
                    continue
                visited_runs.append(run_id)
                for sid, step in graph.steps.items():
                    if step["run_id"] != run_id:
                        continue
                    if step["model_config_id"]:
                        model = connection.execute(
                            "SELECT weights_artifact_id FROM model_configs WHERE model_config_id=?",
                            (step["model_config_id"],)).fetchone()
                        if model is not None and model["weights_artifact_id"]:
                            stack.append(model["weights_artifact_id"])
                    for ref in graph.inputs.get(sid, []):
                        if ref["kind"] == "artifact":
                            stack.append(ref["artifact_id"])
                        elif ref["kind"] == "dataset":
                            dataset_refs.add((ref["dataset_id"], ref["version"]))
                            data_row = self._dataset_row(connection, ref["dataset_id"], ref["version"])
                            if data_row is not None:
                                stack.append(data_row["artifact_id"])
        return {"artifacts": visited_artifacts, "runs": visited_runs, "datasets": dataset_refs}

    def _forward_closure(self, connection, graph: LineageGraph,
                         seed_artifacts: Iterable[str],
                         seed_datasets: Iterable[tuple[str, str]] = ()) -> dict[str, Any]:
        visited_artifacts = set(seed_artifacts)
        visited_runs: list[str] = []
        stack_artifacts = list(seed_artifacts)
        stack_datasets = list(seed_datasets)
        expanded: set[str] = set()

        def expand_run(run_id: str) -> None:
            if run_id in visited_runs:
                return
            visited_runs.append(run_id)
            for sid, step in graph.steps.items():
                if step["run_id"] != run_id:
                    continue
                for output in graph.outputs.get(sid, []):
                    if output not in visited_artifacts:
                        visited_artifacts.add(output)
                        stack_artifacts.append(output)

        while stack_artifacts or stack_datasets:
            while stack_artifacts:
                artifact_id = stack_artifacts.pop()
                if artifact_id in expanded:
                    continue
                expanded.add(artifact_id)
                for sid, refs in graph.inputs.items():
                    if {"kind": "artifact", "artifact_id": artifact_id} in refs:
                        expand_run(graph.steps[sid]["run_id"])
            while stack_datasets:
                key = stack_datasets.pop()
                marker = "dataset:" + canonical_json(key)
                if marker in expanded:
                    continue
                expanded.add(marker)
                dataset_id, version = key
                target = {"kind": "dataset", "dataset_id": dataset_id, "version": version}
                for sid, refs in graph.inputs.items():
                    if target in refs:
                        expand_run(graph.steps[sid]["run_id"])
        return {"artifacts": visited_artifacts, "runs": visited_runs}

    def _dataset_row(self, connection, dataset_id: str, version: str):
        return connection.execute(
            "SELECT * FROM dataset_versions WHERE dataset_id=? AND version=?",
            (dataset_id, version)).fetchone()

    def _serialize_run(self, connection, graph: LineageGraph, run_id: str,
                       artifact_visibility: set[str] | None = None) -> dict[str, Any]:
        run = graph.runs[run_id]
        steps_out = []
        model_ids: set[str] = set()
        for step_id in sorted((s for s in graph.steps if graph.steps[s]["run_id"] == run_id),
                              key=lambda s: graph.steps[s]["step_order"]):
            step = graph.steps[step_id]
            if step["model_config_id"]:
                model_ids.add(step["model_config_id"])
            inputs = []
            for ref in graph.inputs.get(step_id, []):
                item = dict(ref)
                if ref["kind"] == "dataset":
                    row = self._dataset_row(connection, ref["dataset_id"], ref["version"])
                    data_artifact = row["artifact_id"] if row else None
                    if artifact_visibility is not None and (
                            data_artifact is None or data_artifact not in artifact_visibility):
                        item["artifact_id"] = None
                        item["visible"] = False
                    else:
                        item["artifact_id"] = data_artifact
                        item["visible"] = True
                else:
                    item["visible"] = artifact_visibility is None or ref["artifact_id"] in artifact_visibility
                inputs.append(item)
            outputs = graph.outputs.get(step_id, [])
            if artifact_visibility is not None:
                inputs = [r for r in inputs
                          if r.get("kind") != "artifact" or r["artifact_id"] in artifact_visibility]
                outputs = [a for a in outputs if a in artifact_visibility]
            decisions = connection.execute(
                "SELECT * FROM human_decisions WHERE subject_kind='run_step' AND subject_id=? ORDER BY created_at",
                (step_id,)).fetchall()
            steps_out.append({"step_id": step_id, "step_order": step["step_order"],
                              "action": step["action"], "model_config_id": step["model_config_id"],
                              "inputs": inputs, "outputs": outputs,
                              "decisions": [self._decision_brief(d) for d in decisions]})
        models = {}
        for model_id in model_ids:
            row = connection.execute("SELECT * FROM model_configs WHERE model_config_id=?",
                                     (model_id,)).fetchone()
            models[model_id] = {"model_config_id": model_id, "params": json.loads(row["params_json"]),
                                "weights_artifact_id": row["weights_artifact_id"],
                                "calibration_status": row["calibration_status"]}
        run_decisions = connection.execute(
            "SELECT * FROM human_decisions WHERE subject_kind='run' AND subject_id=? ORDER BY created_at",
            (run_id,)).fetchall()
        workflow = connection.execute("SELECT * FROM workflows WHERE workflow_id=?",
                                      (run["workflow_id"],)).fetchone()
        environment = connection.execute("SELECT * FROM environments WHERE environment_id=?",
                                         (run["environment_id"],)).fetchone()
        return {"run_id": run_id, "node_id": run["created_by"], "occurred_at": run["occurred_at"],
                "seed": run["seed"],
                "workflow": {"workflow_id": run["workflow_id"],
                             "definition": json.loads(workflow["definition_json"])},
                "environment": {"environment_id": run["environment_id"],
                                "fingerprint": json.loads(environment["fingerprint_json"])},
                "steps": steps_out, "models": models,
                "decisions": [self._decision_brief(d) for d in run_decisions]}

    @staticmethod
    def _decision_brief(row) -> dict[str, Any]:
        return {"decision_id": row["decision_id"], "subject_kind": row["subject_kind"],
                "subject_id": row["subject_id"], "verdict": row["verdict"],
                "rationale": row["rationale"], "decided_by": row["decided_by"],
                "created_at": row["created_at"]}

    def _dataset_index(self, connection, keys: Iterable[tuple[str, str]],
                       include_artifact_ids: Iterable[str] = ()) -> dict[str, Any]:
        index: dict[str, Any] = {}
        keys = set(keys)
        for aid in include_artifact_ids:
            row = connection.execute(
                "SELECT * FROM dataset_versions WHERE artifact_id=?", (aid,)).fetchone()
            if row is not None:
                keys.add((row["dataset_id"], row["version"]))
        for dataset_id, version in keys:
            row = self._dataset_row(connection, dataset_id, version)
            if row is None:
                index[f"{dataset_id}@{version}"] = {"missing": True}
                continue
            advisories = connection.execute(
                "SELECT advisory_id,kind,reason FROM advisories WHERE dataset_id=? AND version=? ORDER BY created_at",
                (dataset_id, version)).fetchall()
            index[f"{dataset_id}@{version}"] = {
                "dataset_id": dataset_id, "version": version,
                "artifact_id": row["artifact_id"], "license": json.loads(row["license_json"]),
                "calibration": json.loads(row["calibration_json"]) if row["calibration_json"] else None,
                "status": row["status"], "withdrawn_reason": row["withdrawn_reason"],
                "advisories": [{"advisory_id": a["advisory_id"], "kind": a["kind"], "reason": a["reason"]}
                               for a in advisories]}
        return index

    # ── 研究人员：复原完整版本组合 ─────────────────────────────

    def reconstruct_result(self, *, actor_id: str, artifact_id: str) -> dict[str, Any]:
        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            if connection.execute("SELECT 1 FROM artifacts WHERE artifact_id=?",
                                  (artifact_id,)).fetchone() is None:
                raise NotFoundError("结果制品不存在")
            graph = self._load_graph(connection)
            closure = self._backward_closure(connection, graph, [artifact_id])
            visible = {a for a in closure["artifacts"]
                       if self._artifact_visible(connection, actor, a)}
            runs = [self._serialize_run(connection, graph, run_id, visible)
                    for run_id in closure["runs"]]
            datasets = self._dataset_index(connection, closure["datasets"], closure["artifacts"])
            compliance = self._compliance(connection, graph, [artifact_id])
            return {"result_artifact_id": artifact_id,
                    "artifacts": [{"artifact_id": a,
                                   "visible": a in visible,
                                   "media_type": connection.execute(
                                       "SELECT media_type FROM artifacts WHERE artifact_id=?", (a,)
                                   ).fetchone()["media_type"]}
                                  for a in sorted(closure["artifacts"])],
                    "runs": runs, "datasets": datasets, "compliance": compliance}

    def trace_backward(self, *, actor_id: str, artifact_id: str) -> dict[str, Any]:
        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            graph = self._load_graph(connection)
            closure = self._backward_closure(connection, graph, [artifact_id])
            return {"artifact_id": artifact_id,
                    "origin_runs": [self._serialize_run(connection, graph, r) for r in closure["runs"]],
                    "datasets": self._dataset_index(connection, closure["datasets"], closure["artifacts"])}

    def trace_forward(self, *, actor_id: str, artifact_id: str | None = None,
                      dataset_id: str | None = None, version: str | None = None) -> dict[str, Any]:
        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *GOVERNANCE_ROLES)
            graph = self._load_graph(connection)
            seed_artifacts: list[str] = []
            seed_datasets: list[tuple[str, str]] = []
            if artifact_id:
                seed_artifacts.append(artifact_id)
            if dataset_id:
                if version is None:
                    raise ValidationError("追踪数据集影响必须提供 version")
                seed_datasets.append((dataset_id, version))
                row = self._dataset_row(connection, dataset_id, version)
                if row is None:
                    raise NotFoundError("数据集版本不存在")
                seed_artifacts.append(row["artifact_id"])
            closure = self._forward_closure(connection, graph, seed_artifacts, seed_datasets)
            releases = connection.execute(
                "SELECT r.release_id FROM releases r JOIN release_results rr ON rr.release_id=r.release_id "
                "WHERE r.state='published' AND rr.artifact_id IN (%s) GROUP BY r.release_id"
                % ",".join("?" * len(closure["artifacts"] or [""])),
                list(closure["artifacts"] or [""])).fetchall()
            return {"seed_artifacts": sorted(seed_artifacts), "seed_datasets": seed_datasets,
                    "affected_artifacts": sorted(closure["artifacts"]),
                    "affected_runs": list(closure["runs"]),
                    "runs": [self._serialize_run(connection, graph, r) for r in closure["runs"]],
                    "affected_releases": [r["release_id"] for r in releases]}

    # ── 发布快照与合规 ─────────────────────────────────────────

    def _compliance(self, connection, graph: LineageGraph, result_artifacts: list[str]) -> dict[str, Any]:
        closure = self._backward_closure(connection, graph, result_artifacts)
        blockers: list[dict[str, Any]] = []
        for dataset_id, version in closure["datasets"]:
            row = self._dataset_row(connection, dataset_id, version)
            if row is None:
                blockers.append({"type": "dataset_missing", "dataset_id": dataset_id, "version": version})
                continue
            if row["status"] == "withdrawn":
                blockers.append({"type": "dataset_withdrawn", "dataset_id": dataset_id, "version": version,
                                 "reason": row["withdrawn_reason"]})
            license_scope = json.loads(row["license_json"])
            if not license_scope.get("publish_allowed", False):
                blockers.append({"type": "license_publish_denied", "dataset_id": dataset_id,
                                 "version": version, "license": license_scope.get("name")})
            for advisory in connection.execute(
                    "SELECT advisory_id,kind,reason FROM advisories WHERE dataset_id=? AND version=?",
                    (dataset_id, version)).fetchall():
                blockers.append({"type": advisory["kind"], "dataset_id": dataset_id, "version": version,
                                 "advisory_id": advisory["advisory_id"], "reason": advisory["reason"]})
        for aid in closure["artifacts"]:
            row = connection.execute(
                "SELECT * FROM dataset_versions WHERE artifact_id=?", (aid,)).fetchone()
            if row is not None and (row["dataset_id"], row["version"]) not in closure["datasets"]:
                if row["status"] == "withdrawn":
                    blockers.append({"type": "dataset_withdrawn", "dataset_id": row["dataset_id"],
                                     "version": row["version"], "reason": row["withdrawn_reason"]})
                for advisory in connection.execute(
                        "SELECT advisory_id,kind,reason FROM advisories WHERE dataset_id=? AND version=?",
                        (row["dataset_id"], row["version"])).fetchall():
                    blockers.append({"type": advisory["kind"], "dataset_id": row["dataset_id"],
                                     "version": row["version"], "advisory_id": advisory["advisory_id"],
                                     "reason": advisory["reason"]})
        for run_id in closure["runs"]:
            for step in graph.steps.values():
                if step["run_id"] != run_id or not step["model_config_id"]:
                    continue
                model = connection.execute("SELECT * FROM model_configs WHERE model_config_id=?",
                                           (step["model_config_id"],)).fetchone()
                if model["calibration_status"] == "invalid":
                    blockers.append({"type": "model_calibration_invalid",
                                     "model_config_id": step["model_config_id"], "run_id": run_id})
        deduped = [json.loads(item) for item in {canonical_json(b) for b in blockers}]
        return {"publishable": not deduped, "blockers": deduped,
                "dataset_count": len(closure["datasets"]), "run_count": len(closure["runs"])}

    def create_release(self, *, actor_id: str, release_id: str,
                       result_artifacts: list[str], scope: dict[str, Any] | None = None) -> dict[str, Any]:
        if not result_artifacts:
            raise ValidationError("result_artifacts 不能为空")
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *WRITE_ROLES)
            for artifact_id in result_artifacts:
                if connection.execute("SELECT 1 FROM artifacts WHERE artifact_id=?",
                                      (artifact_id,)).fetchone() is None:
                    raise NotFoundError(f"结果制品 {artifact_id} 不存在")
            try:
                connection.execute(
                    "INSERT INTO releases(release_id,state,scope_json,result_artifacts_json,snapshot_json,"
                    "snapshot_hash,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)",
                    (release_id, "draft", canonical_json(scope or {}),
                     canonical_json(result_artifacts), "null", "", actor_id, self._now()),
                )
            except Exception as exc:
                raise ConflictError("发布编号已经存在") from exc
            for artifact_id in result_artifacts:
                connection.execute("INSERT INTO release_results(release_id,artifact_id) VALUES(?,?)",
                                   (release_id, artifact_id))
            append_event(connection, actor_id=actor_id, action="release.created",
                         resource_type="release", resource_id=release_id,
                         detail={"result_artifacts": result_artifacts, "scope": scope or {}},
                         occurred_at=self._now())
            return {"release_id": release_id, "state": "draft",
                    "result_artifacts": result_artifacts, "scope": scope or {}}

    def _build_snapshot(self, connection, release) -> dict[str, Any]:
        graph = self._load_graph(connection)
        result_artifacts = json.loads(release["result_artifacts_json"])
        closure = self._backward_closure(connection, graph, result_artifacts)
        runs = {run_id: self._serialize_run(connection, graph, run_id) for run_id in closure["runs"]}
        artifacts_index = {}
        for aid in closure["artifacts"]:
            row = connection.execute("SELECT * FROM artifacts WHERE artifact_id=?", (aid,)).fetchone()
            artifacts_index[aid] = {"artifact_id": aid, "media_type": row["media_type"],
                                    "size_bytes": row["size_bytes"], "created_by": row["created_by"]}
        decisions = connection.execute(
            "SELECT * FROM human_decisions WHERE subject_kind='artifact' AND subject_id IN (%s)"
            % ",".join("?" * len(closure["artifacts"] or [""])),
            list(closure["artifacts"] or [""])).fetchall()
        snapshot = {
            "release_id": release["release_id"],
            "scope": json.loads(release["scope_json"]),
            "result_artifacts": result_artifacts,
            "runs": runs,
            "artifacts": artifacts_index,
            "datasets": self._dataset_index(connection, closure["datasets"], closure["artifacts"]),
            "artifact_decisions": [self._decision_brief(d) for d in decisions],
            "released_at": self._now(),
        }
        snapshot["snapshot_hash"] = digest(snapshot)
        return snapshot

    def publish_release(self, *, actor_id: str, release_id: str) -> dict[str, Any]:
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "reviewer", "admin")
            release = connection.execute("SELECT * FROM releases WHERE release_id=?",
                                         (release_id,)).fetchone()
            if release is None:
                raise NotFoundError("发布不存在")
            if release["state"] == "published":
                raise ConflictError("发布快照一经引用不得覆盖")
            graph = self._load_graph(connection)
            result_artifacts = json.loads(release["result_artifacts_json"])
            compliance = self._compliance(connection, graph, result_artifacts)
            if not compliance["publishable"]:
                raise ConflictError("存在不合规上游，发布已阻断", compliance["blockers"])
            snapshot = self._build_snapshot(connection, release)
            connection.execute(
                "UPDATE releases SET state='published',snapshot_json=?,snapshot_hash=?,"
                "published_by=?,published_at=? WHERE release_id=?",
                (canonical_json(snapshot), snapshot["snapshot_hash"], actor_id,
                 snapshot["released_at"], release_id),
            )
            append_event(connection, actor_id=actor_id, action="release.published",
                         resource_type="release", resource_id=release_id,
                         detail={"snapshot_hash": snapshot["snapshot_hash"]},
                         occurred_at=snapshot["released_at"])
            return {"release_id": release_id, "state": "published",
                    "snapshot_hash": snapshot["snapshot_hash"]}

    def get_release(self, actor_id: str, release_id: str) -> dict[str, Any]:
        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            release = connection.execute("SELECT * FROM releases WHERE release_id=?",
                                         (release_id,)).fetchone()
            if release is None:
                raise NotFoundError("发布不存在")
            marks = connection.execute(
                "SELECT advisory_id,status FROM release_status_marks WHERE release_id=?",
                (release_id,)).fetchall()
            return {"release_id": release_id, "state": release["state"],
                    "scope": json.loads(release["scope_json"]),
                    "result_artifacts": json.loads(release["result_artifacts_json"]),
                    "snapshot_hash": release["snapshot_hash"] or None,
                    "published_by": release["published_by"], "published_at": release["published_at"],
                    "created_by": release["created_by"], "created_at": release["created_at"],
                    "status_marks": [{"advisory_id": m["advisory_id"], "status": m["status"]} for m in marks]}

    def list_releases(self, actor_id: str) -> list[dict[str, Any]]:
        with self.database.transaction() as connection:
            self._actor(connection, actor_id)
            rows = connection.execute(
                "SELECT * FROM releases ORDER BY created_at, release_id").fetchall()
            results = []
            for release in rows:
                marks = connection.execute(
                    "SELECT advisory_id,status FROM release_status_marks WHERE release_id=?",
                    (release["release_id"],)).fetchall()
                results.append({
                    "release_id": release["release_id"], "state": release["state"],
                    "scope": json.loads(release["scope_json"]),
                    "result_artifacts": json.loads(release["result_artifacts_json"]),
                    "snapshot_hash": release["snapshot_hash"] or None,
                    "published_by": release["published_by"], "published_at": release["published_at"],
                    "created_by": release["created_by"], "created_at": release["created_at"],
                    "status_marks": [{"advisory_id": m["advisory_id"], "status": m["status"]}
                                     for m in marks]})
            return results

    def get_reference(self, *, actor_id: str, release_id: str) -> dict[str, Any]:
        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            release = connection.execute("SELECT * FROM releases WHERE release_id=?",
                                         (release_id,)).fetchone()
            if release is None:
                raise NotFoundError("发布不存在")
            if release["state"] != "published":
                raise ConflictError("仅已发布快照可以作为引用复原")
            snapshot = json.loads(release["snapshot_json"])
            if actor["role"] not in ("admin", "auditor"):
                visible_artifacts: set[str] = set()
                for aid in snapshot["artifacts"]:
                    try:
                        if self._artifact_visible(connection, actor, aid):
                            visible_artifacts.add(aid)
                    except NotFoundError:
                        pass
                snapshot["artifacts"] = {a: v for a, v in snapshot["artifacts"].items()
                                         if a in visible_artifacts}
                for run in snapshot["runs"].values():
                    for step in run["steps"]:
                        step["inputs"] = [r for r in step["inputs"]
                                          if r.get("kind") != "artifact"
                                          or r["artifact_id"] in visible_artifacts]
                        step["outputs"] = [a for a in step["outputs"] if a in visible_artifacts]
            return snapshot

    def find_release_for_result(self, *, actor_id: str, artifact_id: str) -> dict[str, Any]:
        with self.database.transaction() as connection:
            self._actor(connection, actor_id)
            rows = connection.execute(
                "SELECT release_id FROM release_results WHERE artifact_id=? ORDER BY release_id",
                (artifact_id,)).fetchall()
        return {"artifact_id": artifact_id, "release_ids": [r["release_id"] for r in rows]}

    # ── 撤回 / 校准失效 → 影响分析 ─────────────────────────────

    def _raise_advisory(self, connection, *, kind: str, dataset_id: str, version: str,
                        reason: str, actor_id: str) -> str:
        row = self._dataset_row(connection, dataset_id, version)
        if row is None:
            raise NotFoundError("数据集版本不存在")
        advisory_id = uuid.uuid4().hex
        try:
            connection.execute(
                "INSERT INTO advisories(advisory_id,kind,dataset_id,version,reason,created_by,created_at) "
                "VALUES(?,?,?,?,?,?,?)",
                (advisory_id, kind, dataset_id, version, reason, actor_id, self._now()),
            )
        except Exception as exc:
            raise ConflictError("该数据集版本已有同类通告") from exc
        if kind == "dataset_withdrawn":
            connection.execute(
                "UPDATE dataset_versions SET status='withdrawn',withdrawn_reason=? WHERE dataset_id=? AND version=?",
                (reason, dataset_id, version),
            )
        return advisory_id

    def _create_impact_analysis(self, connection, *, advisory_id: str, kind: str,
                                dataset_id: str, version: str, actor_id: str) -> str:
        graph = self._load_graph(connection)
        dataset_row = self._dataset_row(connection, dataset_id, version)
        forward = self._forward_closure(connection, graph, [dataset_row["artifact_id"]],
                                        [(dataset_id, version)])
        affected_artifacts = sorted(forward["artifacts"])
        affected_runs = forward["runs"]
        placeholders = ",".join("?" * len(affected_artifacts or [""]))
        releases = connection.execute(
            f"SELECT r.release_id FROM releases r JOIN release_results rr ON rr.release_id=r.release_id "
            f"WHERE r.state='published' AND rr.artifact_id IN ({placeholders})",
            affected_artifacts or [""]).fetchall()
        affected_releases = [r["release_id"] for r in releases]
        for release_id in affected_releases:
            connection.execute(
                "INSERT OR IGNORE INTO release_status_marks(release_id,advisory_id,status) VALUES(?,?,?)",
                (release_id, advisory_id, f"flagged:{kind}"),
            )
        analysis_id = uuid.uuid4().hex
        connection.execute(
            "INSERT INTO impact_analyses(analysis_id,advisory_id,affected_artifacts_json,"
            "affected_runs_json,affected_releases_json,created_by,created_at) VALUES(?,?,?,?,?,?,?)",
            (analysis_id, advisory_id, canonical_json(affected_artifacts),
             canonical_json(affected_runs), canonical_json(affected_releases), actor_id, self._now()),
        )
        append_event(connection, actor_id=actor_id, action="impact.analysis_created",
                     resource_type="impact_analysis", resource_id=analysis_id,
                     detail={"advisory_id": advisory_id, "kind": kind,
                             "dataset_id": dataset_id, "version": version,
                             "affected_artifacts": len(affected_artifacts),
                             "affected_runs": len(affected_runs),
                             "affected_releases": len(affected_releases)},
                     occurred_at=self._now())
        return analysis_id

    def withdraw_dataset(self, *, actor_id: str, dataset_id: str, version: str, reason: str) -> dict[str, Any]:
        reason = str(reason or "").strip()
        if not reason:
            raise ValidationError("撤回必须填写原因")
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin")
            advisory_id = self._raise_advisory(connection, kind="dataset_withdrawn",
                                               dataset_id=dataset_id, version=version,
                                               reason=reason, actor_id=actor_id)
            analysis_id = self._create_impact_analysis(
                connection, advisory_id=advisory_id, kind="dataset_withdrawn",
                dataset_id=dataset_id, version=version, actor_id=actor_id)
            return {"advisory_id": advisory_id, "impact_analysis_id": analysis_id,
                    "kind": "dataset_withdrawn"}

    def invalidate_calibration(self, *, actor_id: str, dataset_id: str, version: str,
                               reason: str) -> dict[str, Any]:
        reason = str(reason or "").strip()
        if not reason:
            raise ValidationError("失效声明必须填写原因")
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin")
            advisory_id = self._raise_advisory(connection, kind="calibration_invalid",
                                               dataset_id=dataset_id, version=version,
                                               reason=reason, actor_id=actor_id)
            analysis_id = self._create_impact_analysis(
                connection, advisory_id=advisory_id, kind="calibration_invalid",
                dataset_id=dataset_id, version=version, actor_id=actor_id)
            return {"advisory_id": advisory_id, "impact_analysis_id": analysis_id,
                    "kind": "calibration_invalid"}

    def list_impact_analyses(self, actor_id: str) -> list[dict[str, Any]]:
        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *GOVERNANCE_ROLES)
            rows = connection.execute(
                "SELECT * FROM impact_analyses ORDER BY created_at").fetchall()
        return [self._impact_brief(r) for r in rows]

    def get_impact_analysis(self, *, actor_id: str, analysis_id: str) -> dict[str, Any]:
        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *GOVERNANCE_ROLES)
            row = connection.execute("SELECT * FROM impact_analyses WHERE analysis_id=?",
                                     (analysis_id,)).fetchone()
            if row is None:
                raise NotFoundError("影响分析不存在")
            result = self._impact_brief(row)
            advisory = connection.execute("SELECT * FROM advisories WHERE advisory_id=?",
                                          (row["advisory_id"],)).fetchone()
            result["advisory"] = {"advisory_id": advisory["advisory_id"], "kind": advisory["kind"],
                                  "dataset_id": advisory["dataset_id"], "version": advisory["version"],
                                  "reason": advisory["reason"], "created_at": advisory["created_at"]}
            return result

    @staticmethod
    def _impact_brief(row) -> dict[str, Any]:
        return {"analysis_id": row["analysis_id"], "advisory_id": row["advisory_id"],
                "affected_artifacts": json.loads(row["affected_artifacts_json"]),
                "affected_runs": json.loads(row["affected_runs_json"]),
                "affected_releases": json.loads(row["affected_releases_json"]),
                "created_by": row["created_by"], "created_at": row["created_at"]}

    # ── 事件链验证（科研诚信） ─────────────────────────────────

    def verify_lineage_chain(self, actor_id: str, node_id: str | None = None) -> dict[str, Any]:
        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *GOVERNANCE_ROLES)
            query = "SELECT * FROM lineage_events"
            parameters: list[Any] = []
            if node_id:
                query += " WHERE node_id=?"
                parameters.append(node_id)
            query += " ORDER BY node_id, seq"
            per_node: dict[str, dict[str, Any]] = {}
            for row in connection.execute(query, parameters):
                state = per_node.setdefault(row["node_id"], {"previous": GENESIS_HASH, "seq": 0, "ok": True})
                material = {"event_id": row["event_id"], "node_id": row["node_id"], "seq": row["seq"],
                            "occurred_at": row["occurred_at"], "event_type": row["event_type"],
                            "payload": json.loads(row["payload_json"]),
                            "previous_hash": row["previous_hash"]}
                if (row["previous_hash"] != state["previous"] or row["seq"] != state["seq"] + 1
                        or digest(material) != row["event_hash"]):
                    state["ok"] = False
                state["previous"] = row["event_hash"]
                state["seq"] = row["seq"]
            return {"valid": all(s["ok"] for s in per_node.values()), "nodes": per_node and {
                node: {"valid": s["ok"], "last_seq": s["seq"], "last_event_hash": s["previous"]}
                for node, s in per_node.items()}}

    def list_lineage_events(self, actor_id: str, node_id: str | None = None,
                            after_seq: int = 0) -> list[dict[str, Any]]:
        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            query = "SELECT * FROM lineage_events WHERE seq>?"
            parameters: list[Any] = [after_seq]
            if node_id:
                query += " AND node_id=?"
                parameters.append(node_id)
            query += " ORDER BY node_id, seq"
            rows = connection.execute(query, parameters).fetchall()
        return [{"event_id": r["event_id"], "node_id": r["node_id"], "seq": r["seq"],
                 "occurred_at": r["occurred_at"], "event_type": r["event_type"],
                 "payload": json.loads(r["payload_json"]), "previous_hash": r["previous_hash"],
                 "event_hash": r["event_hash"]} for r in rows]
