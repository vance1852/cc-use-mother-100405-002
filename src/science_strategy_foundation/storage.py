"""封装 SQLite 连接、建表和事务边界。"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS organizations (
    organization_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS actors (
    actor_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    active INTEGER NOT NULL CHECK(active IN (0, 1)),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sites (
    site_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    name TEXT NOT NULL,
    timezone_name TEXT NOT NULL,
    version INTEGER NOT NULL CHECK(version >= 1),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS domain_records (
    record_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    category TEXT NOT NULL,
    external_key TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    created_at TEXT NOT NULL,
    UNIQUE(site_id, category, external_key)
);
CREATE TABLE IF NOT EXISTS request_receipts (
    request_id TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE,
    occurred_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS compute_nodes (
    node_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    name TEXT NOT NULL,
    last_seq INTEGER NOT NULL DEFAULT 0 CHECK(last_seq >= 0),
    last_event_hash TEXT NOT NULL,
    last_occurred_at TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id TEXT PRIMARY KEY,
    media_type TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
    content BLOB NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dataset_versions (
    dataset_id TEXT NOT NULL,
    version TEXT NOT NULL,
    artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id),
    license_json TEXT NOT NULL,
    calibration_json TEXT,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'withdrawn')),
    withdrawn_reason TEXT,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(dataset_id, version)
);
CREATE TABLE IF NOT EXISTS license_grants (
    grant_id TEXT PRIMARY KEY,
    grantee_actor_id TEXT NOT NULL REFERENCES actors(actor_id),
    dataset_id TEXT NOT NULL,
    version TEXT,
    scope_json TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(grantee_actor_id, dataset_id, version)
);
CREATE TABLE IF NOT EXISTS model_configs (
    model_config_id TEXT PRIMARY KEY,
    params_json TEXT NOT NULL,
    weights_artifact_id TEXT REFERENCES artifacts(artifact_id),
    calibration_status TEXT NOT NULL DEFAULT 'valid'
        CHECK(calibration_status IN ('valid', 'invalid')),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS environments (
    environment_id TEXT PRIMARY KEY,
    fingerprint_json TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS workflows (
    workflow_id TEXT PRIMARY KEY,
    definition_json TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    workflow_id TEXT NOT NULL REFERENCES workflows(workflow_id),
    environment_id TEXT NOT NULL REFERENCES environments(environment_id),
    seed TEXT NOT NULL,
    created_by TEXT NOT NULL,
    occurred_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS run_steps (
    step_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    step_order INTEGER NOT NULL CHECK(step_order >= 1),
    action TEXT NOT NULL,
    model_config_id TEXT REFERENCES model_configs(model_config_id),
    UNIQUE(run_id, step_order)
);
CREATE TABLE IF NOT EXISTS run_step_inputs (
    step_id TEXT NOT NULL REFERENCES run_steps(step_id),
    ref_json TEXT NOT NULL,
    PRIMARY KEY(step_id, ref_json)
);
CREATE TABLE IF NOT EXISTS run_step_outputs (
    step_id TEXT NOT NULL REFERENCES run_steps(step_id),
    artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id),
    PRIMARY KEY(step_id, artifact_id)
);
CREATE TABLE IF NOT EXISTS human_decisions (
    decision_id TEXT PRIMARY KEY,
    subject_kind TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    verdict TEXT NOT NULL,
    rationale TEXT NOT NULL,
    decided_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS lineage_events (
    event_id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL REFERENCES compute_nodes(node_id),
    seq INTEGER NOT NULL CHECK(seq >= 1),
    occurred_at TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE,
    admitted_by TEXT NOT NULL,
    admitted_at TEXT NOT NULL,
    UNIQUE(node_id, seq)
);
CREATE TABLE IF NOT EXISTS quarantine_events (
    qid INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT,
    node_id TEXT,
    seq INTEGER,
    event_hash TEXT,
    reason TEXT NOT NULL,
    reason_detail TEXT NOT NULL DEFAULT '',
    raw_json TEXT NOT NULL,
    submitted_by TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK(status IN ('pending', 'admitted', 'dismissed')),
    adjudicated_by TEXT,
    rationale TEXT,
    adjudicated_at TEXT,
    received_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS advisories (
    advisory_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK(kind IN ('dataset_withdrawn', 'calibration_invalid')),
    dataset_id TEXT NOT NULL,
    version TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(kind, dataset_id, version)
);
CREATE TABLE IF NOT EXISTS impact_analyses (
    analysis_id TEXT PRIMARY KEY,
    advisory_id TEXT NOT NULL REFERENCES advisories(advisory_id),
    affected_artifacts_json TEXT NOT NULL,
    affected_runs_json TEXT NOT NULL,
    affected_releases_json TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS releases (
    release_id TEXT PRIMARY KEY,
    state TEXT NOT NULL CHECK(state IN ('draft', 'published')),
    scope_json TEXT NOT NULL,
    result_artifacts_json TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    snapshot_hash TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    published_by TEXT,
    published_at TEXT
);
CREATE TABLE IF NOT EXISTS release_results (
    release_id TEXT NOT NULL REFERENCES releases(release_id),
    artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id),
    PRIMARY KEY(release_id, artifact_id)
);
CREATE TABLE IF NOT EXISTS release_status_marks (
    release_id TEXT NOT NULL REFERENCES releases(release_id),
    advisory_id TEXT NOT NULL REFERENCES advisories(advisory_id),
    status TEXT NOT NULL,
    PRIMARY KEY(release_id, advisory_id)
);
"""


class Database:
    """管理 SQLite 数据库并为服务提供短事务。"""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        self.connection = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA busy_timeout = 5000")
        self.connection.executescript(SCHEMA)

    @contextmanager
    def transaction(self, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        """在异常时回滚，在成功时提交。"""

        self.connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
        try:
            yield self.connection
        except Exception:
            self.connection.rollback()
            raise
        else:
            self.connection.commit()

    def close(self) -> None:
        """关闭底层连接。"""

        self.connection.close()
