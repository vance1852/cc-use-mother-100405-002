"""离线算力节点使用的事件构造器：本地维护序列与哈希链。

节点在断网期间持续运行，事件按本地单调序列写入本地日志；
恢复连接后把日志按序补交，服务端按同样的哈希材料校验。
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .audit import GENESIS_HASH, canonical_json, digest

HASH_FIELDS = ("event_id", "node_id", "seq", "occurred_at", "event_type", "payload", "previous_hash")


def utc_now_text() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class LocalEventLog:
    """节点本地的只追加事件日志，可持久化为 JSONL。"""

    def __init__(self, node_id: str, *, last_seq: int = 0,
                 last_hash: str = GENESIS_HASH, last_occurred_at: str | None = None) -> None:
        self.node_id = node_id
        self.last_seq = last_seq
        self.last_hash = last_hash
        self.last_occurred_at = last_occurred_at
        self.events: list[dict[str, Any]] = []
        self._persisted = 0

    @classmethod
    def from_file(cls, path: str | Path) -> "LocalEventLog":
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(path)
        events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if not events:
            raise ValueError("本地日志为空，缺少节点标识")
        log = cls(events[0]["node_id"])
        for envelope in events:
            log.ingest_prepared(envelope)
        log._persisted = len(events)
        return log

    def build(self, event_type: str, payload: dict[str, Any], *,
              occurred_at: str | None = None, event_id: str | None = None,
              clock_fn=utc_now_text) -> dict[str, Any]:
        """构造下一个事件信封，校验本地时钟不倒退。"""

        occurred_at = occurred_at or clock_fn()
        if self.last_occurred_at is not None and occurred_at < self.last_occurred_at:
            raise ValueError(f"本地时钟倒退：{occurred_at} 早于 {self.last_occurred_at}")
        seq = self.last_seq + 1
        material = {
            "event_id": event_id or f"{self.node_id}-{seq}",
            "node_id": self.node_id,
            "seq": seq,
            "occurred_at": occurred_at,
            "event_type": event_type,
            "payload": payload,
            "previous_hash": self.last_hash,
        }
        envelope = {**material, "event_hash": digest(material)}
        self.events.append(envelope)
        self.last_seq = seq
        self.last_hash = envelope["event_hash"]
        self.last_occurred_at = occurred_at
        return envelope

    def ingest_prepared(self, envelope: dict[str, Any]) -> dict[str, Any]:
        """从持久化日志载入既有事件并推进本地链状态。"""

        material = {f: envelope[f] for f in HASH_FIELDS}
        if digest(material) != envelope["event_hash"]:
            raise ValueError(f"本地事件 {envelope.get('event_id')} 哈希不符")
        if envelope["node_id"] != self.node_id:
            raise ValueError("本地日志混入了其他节点的事件")
        if envelope["seq"] != self.last_seq + 1 or envelope["previous_hash"] != self.last_hash:
            raise ValueError(f"本地事件序列断档于 seq={envelope['seq']}")
        self.events.append(envelope)
        self.last_seq = envelope["seq"]
        self.last_hash = envelope["event_hash"]
        self.last_occurred_at = envelope["occurred_at"]
        return envelope

    def append_to_file(self, path: str | Path) -> None:
        """仅把尚未持久化的新事件追加到 JSONL。"""

        path = Path(path)
        fresh = self.events[self._persisted:]
        with path.open("a", encoding="utf-8") as handle:
            for envelope in fresh:
                handle.write(canonical_json(envelope) + "\n")
        self._persisted = len(self.events)

    def pending(self) -> list[dict[str, Any]]:
        return list(self.events)
