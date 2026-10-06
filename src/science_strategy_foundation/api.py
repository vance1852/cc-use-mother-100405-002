"""提供不依赖第三方框架的 HTTP/JSON 边界。"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from .errors import DomainError, ValidationError
from .provenance import ProvenanceService
from .service import DomainService
from .storage import Database


def route(service: DomainService, method: str, path: str, body: dict[str, Any] | None,
          headers: dict[str, str] | None = None,
          provenance: ProvenanceService | None = None) -> tuple[int, dict[str, Any]]:
    """把一个 HTTP 语义请求分派到领域服务。"""

    headers = headers or {}
    body = body or {}
    provenance = provenance or ProvenanceService(service.database, service.clock)
    parsed = urlparse(path)
    query = parse_qs(parsed.query)
    segments = [segment for segment in parsed.path.split("/") if segment]
    actor_id = headers.get("X-Actor-Id", "")

    def q(name: str, default: Any = None) -> Any:
        return query.get(name, [default])[0]

    try:
        if method == "GET" and parsed.path == "/health":
            valid, count = service.verify_audit()
            return 200, {"status": "ok", "audit_valid": valid, "audit_events": count}
        if method == "POST" and parsed.path == "/organizations":
            receipt = service.register_organization(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/actors":
            receipt = service.register_actor(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/sites":
            receipt = service.register_site(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/domain-records":
            receipt = service.record_domain_data(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "GET" and parsed.path == "/domain-records":
            site_id = query.get("site_id", [""])[0]
            if not site_id:
                raise ValidationError("site_id 不能为空")
            category = query.get("category", [None])[0]
            return 200, {"items": [item.__dict__ for item in service.list_domain_data(site_id, category)]}
        if method == "GET" and parsed.path == "/audit-events":
            after = int(query.get("after_sequence", ["0"])[0])
            return 200, {"items": service.audit_events(after)}

        status, payload = _route_provenance(provenance, method, segments, body, query, actor_id)
        if status is not None:
            return status, payload
        return 404, {"error": "route_not_found", "message": "接口不存在"}
    except DomainError as exc:
        payload: dict[str, Any] = {"error": exc.code, "message": str(exc)}
        if exc.detail is not None:
            payload["detail"] = exc.detail
        return exc.status, payload
    except (TypeError, ValueError) as exc:
        return 400, {"error": "invalid_request", "message": str(exc)}


def _route_provenance(provenance: ProvenanceService, method: str, segments: list[str],
                      body: dict[str, Any], query: dict[str, Any], actor_id: str
                      ) -> tuple[int | None, dict[str, Any]]:
    """处理科研溯源相关路由，未命中返回 (None, {})。"""

    def q(name: str, default: Any = None) -> Any:
        return query.get(name, [default])[0]

    if method == "POST" and segments == ["nodes"]:
        return 201, provenance.register_node(actor_id=actor_id, **body)
    if method == "GET" and segments == ["nodes"]:
        return 200, {"items": provenance.list_nodes(actor_id)}
    if method == "POST" and segments == ["license-grants"]:
        return 201, provenance.grant_license(actor_id=actor_id, **body)

    if method == "POST" and segments == ["ingest"]:
        result = provenance.ingest(body, submitted_by=actor_id)
        return (200 if result["status"] == "admitted" else 422), result
    if method == "POST" and segments == ["ingest-batch"]:
        results = provenance.ingest_batch(body.get("events", []), submitted_by=actor_id)
        status = 200 if all(r["status"] == "admitted" for r in results) else 207
        return status, {"items": results}

    if method == "GET" and segments == ["quarantine"]:
        return 200, {"items": provenance.list_quarantine(actor_id, q("status", "pending"))}
    if method == "POST" and segments == ["quarantine", "adjudicate"]:
        return 200, provenance.adjudicate_quarantine(
            actor_id=actor_id, qid=body["qid"], decision=body["decision"],
            rationale=body.get("rationale", ""))
    if method == "POST" and segments == ["quarantine", "rescan"]:
        return 200, provenance.rescan_pending(actor_id)

    if method == "GET" and len(segments) == 2 and segments[0] == "artifacts":
        return 200, provenance.get_artifact(
            actor_id=actor_id, artifact_id=segments[1],
            include_content=q("content") in ("1", "true", "yes"))

    if method == "GET" and len(segments) == 2 and segments[0] == "results":
        return 200, provenance.reconstruct_result(actor_id=actor_id, artifact_id=segments[1])
    if method == "GET" and segments == ["trace", "backward"]:
        artifact_id = q("artifact_id")
        if not artifact_id:
            raise ValidationError("artifact_id 不能为空")
        return 200, provenance.trace_backward(actor_id=actor_id, artifact_id=artifact_id)
    if method == "GET" and segments == ["trace", "forward"]:
        return 200, provenance.trace_forward(
            actor_id=actor_id, artifact_id=q("artifact_id"),
            dataset_id=q("dataset_id"), version=q("version"))

    if method == "POST" and segments == ["releases"]:
        return 201, provenance.create_release(actor_id=actor_id, **body)
    if method == "GET" and segments == ["releases"]:
        return 200, {"items": provenance.list_releases(actor_id)}
    if method == "GET" and len(segments) == 2 and segments[0] == "releases":
        return 200, provenance.get_release(actor_id, segments[1])
    if method == "POST" and len(segments) == 3 and segments[0] == "releases" and segments[2] == "publish":
        return 200, provenance.publish_release(actor_id=actor_id, release_id=segments[1])
    if method == "GET" and len(segments) == 2 and segments[0] == "references":
        return 200, provenance.get_reference(actor_id=actor_id, release_id=segments[1])

    if method == "POST" and segments == ["datasets", "withdraw"]:
        return 200, provenance.withdraw_dataset(actor_id=actor_id, **body)
    if method == "POST" and segments == ["datasets", "invalidate-calibration"]:
        return 200, provenance.invalidate_calibration(actor_id=actor_id, **body)
    if method == "GET" and segments == ["impact-analyses"]:
        return 200, {"items": provenance.list_impact_analyses(actor_id)}
    if method == "GET" and len(segments) == 2 and segments[0] == "impact-analyses":
        return 200, provenance.get_impact_analysis(actor_id=actor_id, analysis_id=segments[1])

    if method == "GET" and segments == ["lineage", "verify"]:
        return 200, provenance.verify_lineage_chain(actor_id, q("node_id"))
    if method == "GET" and segments == ["lineage", "events"]:
        return 200, {"items": provenance.list_lineage_events(
            actor_id, q("node_id"), int(q("after_seq", "0")))}
    return None, {}


class Handler(BaseHTTPRequestHandler):
    """把标准库 HTTP 请求转换为路由调用。"""

    service: DomainService
    provenance: ProvenanceService

    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._write(400, {"error": "invalid_json", "message": "请求体必须是 UTF-8 JSON"})
            return
        status, payload = route(self.service, self.command, self.path, body,
                                {"X-Actor-Id": self.headers.get("X-Actor-Id", "")},
                                self.provenance)
        self._write(status, payload)

    def _write(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle()

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> int:
    """启动本地 HTTP 服务。"""

    parser = argparse.ArgumentParser(description="启动科研计算溯源与发布服务")
    parser.add_argument("--database", default="service.sqlite3")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    database = Database(args.database)
    Handler.service = DomainService(database)
    Handler.provenance = ProvenanceService(database)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        database.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
