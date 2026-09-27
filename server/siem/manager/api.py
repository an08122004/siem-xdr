"""Manager API — điểm tiếp nhận của agent và giao diện cho analyst.

Agent:
  POST /api/v1/agents/enroll          (header X-Enrollment-Key) -> token riêng của agent
  POST /api/v1/agents/heartbeat       (Bearer token)
  POST /api/v1/events                 (Bearer token) batch event -> Kafka siem.raw
  GET  /api/v1/agents/actions         (Bearer token) lấy lệnh phản ứng đang chờ
  POST /api/v1/actions/{id}/result    (Bearer token) báo kết quả thực thi

Analyst (header X-API-Key):
  GET  /api/v1/agents | /alerts | /actions | /cases | /stats
  PATCH /api/v1/alerts/{id}           đổi trạng thái alert (ack/closed/false_positive)
  POST /api/v1/actions                ra lệnh phản ứng thủ công (block IP, kill, isolate)
  GET  /                              SOC console (HTML)

Chạy: uvicorn siem.manager.api:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import hashlib
import hmac
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .. import bus, settings, store

log = logging.getLogger("manager")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

STATIC = Path(__file__).parent / "static"
MAX_BATCH = 5000

_state: dict[str, Any] = {}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    _state["es"] = store.connect()
    bus.wait_for_kafka()
    _state["producer"] = bus.producer()
    log.info("manager sẵn sàng")
    yield
    _state["producer"].flush(10)


app = FastAPI(title="SIEM/XDR Manager", version="1.0.0", lifespan=lifespan)


def es():
    return _state["es"]


# ---------------------------------------------------------------------------
# Xác thực
# ---------------------------------------------------------------------------

def agent_token(agent_id: str) -> str:
    return hmac.new(settings.SERVER_SECRET.encode(), agent_id.encode(), hashlib.sha256).hexdigest()


def require_agent(x_agent_id: str = Header(...), authorization: str = Header("")) -> str:
    token = authorization.removeprefix("Bearer ").strip()
    if not token or not hmac.compare_digest(token, agent_token(x_agent_id)):
        raise HTTPException(401, "token agent không hợp lệ")
    return x_agent_id


def require_analyst(x_api_key: str = Header("")) -> None:
    if not hmac.compare_digest(x_api_key, settings.API_KEY):
        raise HTTPException(401, "API key không hợp lệ")


# ---------------------------------------------------------------------------
# Agent endpoints
# ---------------------------------------------------------------------------

class AgentInfo(BaseModel):
    agent_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")
    hostname: str = ""
    os: str = ""
    version: str = ""


class ActionResult(BaseModel):
    status: str
    output: str = ""


@app.post("/api/v1/agents/enroll")
def enroll(info: AgentInfo, request: Request, x_enrollment_key: str = Header("")) -> dict[str, str]:
    if not hmac.compare_digest(x_enrollment_key, settings.ENROLLMENT_KEY):
        log.warning("enroll bị từ chối từ %s (agent_id=%s)", request.client.host, info.agent_id)
        raise HTTPException(403, "enrollment key sai")
    store.upsert_agent(es(), info.model_dump(), request.client.host)
    log.info("agent %s (%s/%s) đã enroll từ %s", info.agent_id, info.hostname, info.os, request.client.host)
    return {"token": agent_token(info.agent_id)}


@app.post("/api/v1/agents/heartbeat")
def heartbeat(info: AgentInfo, request: Request, agent_id: str = Depends(require_agent)) -> dict[str, bool]:
    data = info.model_dump() | {"agent_id": agent_id}
    store.upsert_agent(es(), data, request.client.host)
    return {"ok": True}


@app.post("/api/v1/events")
async def ingest(request: Request, agent_id: str = Depends(require_agent)) -> dict[str, int]:
    try:
        body = await request.json()
    except ValueError:
        raise HTTPException(400, "body không phải JSON")
    events = body if isinstance(body, list) else [body]
    if len(events) > MAX_BATCH:
        raise HTTPException(413, f"tối đa {MAX_BATCH} event/lần")
    p = _state["producer"]
    ip = request.client.host
    accepted = 0
    for e in events:
        if not isinstance(e, dict):
            continue
        e["agent_id"] = agent_id      # không tin agent_id trong payload -> chống giả mạo
        e["agent_ip"] = ip
        bus.send(p, settings.TOPIC_RAW, e, key=agent_id)
        accepted += 1
    p.poll(0)
    return {"accepted": accepted}


@app.get("/api/v1/agents/actions")
def poll_actions(agent_id: str = Depends(require_agent)) -> list[dict[str, Any]]:
    return store.claim_pending_actions(es(), agent_id)


@app.post("/api/v1/actions/{action_id}/result")
def action_result(action_id: str, res: ActionResult, agent_id: str = Depends(require_agent)) -> dict[str, bool]:
    if not store.finish_action(es(), action_id, agent_id, res.status, res.output):
        raise HTTPException(404, "không tìm thấy action")
    log.info("action %s trên %s: %s", action_id, agent_id, res.status)
    return {"ok": True}


# ---------------------------------------------------------------------------
# Analyst endpoints
# ---------------------------------------------------------------------------

class NewAction(BaseModel):
    agent_id: str
    type: str
    params: dict[str, Any] = {}
    alert_id: str | None = None


class AlertUpdate(BaseModel):
    status: str = Field(pattern=r"^(open|acknowledged|in_progress|closed|false_positive)$")
    note: str = ""


@app.get("/api/v1/agents", dependencies=[Depends(require_analyst)])
def agents() -> list[dict[str, Any]]:
    return store.list_agents(es())


@app.get("/api/v1/alerts", dependencies=[Depends(require_analyst)])
def alerts(status: str | None = None, severity: str | None = None, size: int = 100) -> list[dict[str, Any]]:
    filters: list[dict] = []
    if status:
        filters.append({"term": {"alert.status": status}})
    if severity:
        filters.append({"term": {"severity": severity}})
    return store.search(es(), settings.IDX_ALERTS, {"bool": {"filter": filters}}, size=min(size, 1000))


@app.patch("/api/v1/alerts/{alert_id}", dependencies=[Depends(require_analyst)])
def update_alert(alert_id: str, body: AlertUpdate) -> dict[str, bool]:
    es().update(index=settings.IDX_ALERTS, id=alert_id, refresh="wait_for",
                doc={"alert": {"status": body.status, "note": body.note, "updated_at": store.now_iso()}})
    return {"ok": True}


@app.get("/api/v1/actions", dependencies=[Depends(require_analyst)])
def actions(size: int = 100) -> list[dict[str, Any]]:
    return store.search(es(), settings.IDX_ACTIONS, size=min(size, 1000), sort=[{"created_at": "desc"}])


@app.post("/api/v1/actions", dependencies=[Depends(require_analyst)])
def create_action(body: NewAction) -> dict[str, Any]:
    try:
        return store.create_action(es(), body.agent_id, body.type, body.params, alert_id=body.alert_id, source="manual")
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.get("/api/v1/cases", dependencies=[Depends(require_analyst)])
def cases(size: int = 100) -> list[dict[str, Any]]:
    return store.search(es(), settings.IDX_CASES, size=min(size, 1000), sort=[{"created_at": "desc"}])


CASE_STATUSES = r"^(open|in_progress|contained|closed|false_positive)$"


class CaseUpdate(BaseModel):
    analyst: str = Field(min_length=1, max_length=64)   # ai thực hiện (ghi vào lịch sử case)
    status: str | None = Field(None, pattern=CASE_STATUSES)
    assignee: str | None = Field(None, max_length=64)
    note: str = Field("", max_length=4000)
    task_index: int | None = Field(None, ge=0)
    task_done: bool | None = None


@app.get("/api/v1/cases/{case_id}", dependencies=[Depends(require_analyst)])
def get_case(case_id: str) -> dict[str, Any]:
    try:
        return es().get(index=settings.IDX_CASES, id=case_id)["_source"]
    except Exception:  # noqa: BLE001
        raise HTTPException(404, "không tìm thấy case")


@app.patch("/api/v1/cases/{case_id}", dependencies=[Depends(require_analyst)])
def update_case(case_id: str, body: CaseUpdate) -> dict[str, Any]:
    """Cập nhật case: trạng thái, người xử lý, đánh dấu task playbook, ghi chú.
    Mọi thay đổi được ghi vào `notes` (lịch sử) kèm tên analyst và thời điểm."""
    try:
        cur = es().get(index=settings.IDX_CASES, id=case_id)
    except Exception:  # noqa: BLE001
        raise HTTPException(404, "không tìm thấy case")
    case, now = cur["_source"], store.now_iso()
    changes: dict[str, Any] = {"updated_at": now}
    history: list[str] = []
    if body.status and body.status != case.get("status"):
        if body.status in ("closed", "false_positive") and not body.note.strip():
            raise HTTPException(400, "đóng case phải ghi lý do / kết luận vào note")
        changes["status"] = body.status
        if body.status in ("closed", "false_positive"):
            changes["closed_at"] = now
        history.append(f"trạng thái: {case.get('status')} -> {body.status}")
    if body.assignee is not None and body.assignee != case.get("assignee"):
        changes["assignee"] = body.assignee or None
        history.append(f"giao cho: {body.assignee or '(bỏ giao)'}")
    if body.task_index is not None and body.task_done is not None:
        tasks = case.get("tasks") or []
        if body.task_index >= len(tasks):
            raise HTTPException(400, "task_index vượt quá số task")
        t = tasks[body.task_index]
        t.update(done=body.task_done, done_by=body.analyst if body.task_done else None,
                 done_at=now if body.task_done else None)
        changes["tasks"] = tasks
        history.append(f"{'hoàn thành' if body.task_done else 'bỏ đánh dấu'} task [{t['phase']}] {t['title']}")
    if body.note.strip():
        history.append(f"ghi chú: {body.note.strip()}")
    if not history:
        return case
    changes["notes"] = (case.get("notes") or []) + [{"at": now, "by": body.analyst, "text": h} for h in history]
    try:
        es().update(index=settings.IDX_CASES, id=case_id, doc=changes, refresh="wait_for",
                    if_seq_no=cur["_seq_no"], if_primary_term=cur["_primary_term"])
    except Exception:  # noqa: BLE001 - người khác vừa sửa case
        raise HTTPException(409, "case vừa được người khác cập nhật, hãy tải lại")
    log.info("case %s cập nhật bởi %s: %s", case_id, body.analyst, "; ".join(history))
    return case | changes


@app.get("/api/v1/stats", dependencies=[Depends(require_analyst)])
def stats() -> dict[str, Any]:
    def count(index: str, query: dict | None = None) -> int:
        try:
            return es().count(index=index, query=query or {"match_all": {}})["count"]
        except Exception:  # noqa: BLE001
            return 0
    last24 = {"range": {"@timestamp": {"gte": "now-24h"}}}
    ag = store.list_agents(es())
    return {
        "events_24h": count(f"{settings.IDX_EVENTS}-*", last24),
        "alerts_24h": count(settings.IDX_ALERTS, last24),
        "alerts_open": count(settings.IDX_ALERTS, {"terms": {"alert.status": ["open", "in_progress"]}}),
        "agents_total": len(ag),
        "agents_online": sum(a["status"] == "online" for a in ag),
        "actions_pending": count(settings.IDX_ACTIONS, {"terms": {"status": ["pending", "sent"]}}),
        "cases_open": count(settings.IDX_CASES, {"terms": {"status": ["open", "in_progress", "contained"]}}),
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/")
def console() -> FileResponse:
    return FileResponse(STATIC / "console.html")


# ---------------------------------------------------------------------------
# AI hỗ trợ viết rule — analyst duyệt / từ chối / gỡ đề xuất
# ---------------------------------------------------------------------------

from ..ai import deploy as ai_deploy  # noqa: E402


class AIDecision(BaseModel):
    analyst: str = Field(min_length=1, max_length=64)
    reason: str = Field("", max_length=2000)


def _ai(fn, *args, **kw):
    try:
        return fn(*args, **kw)
    except ai_deploy.DeployError as e:
        raise HTTPException(e.code, str(e))


@app.get("/api/v1/ai/proposals", dependencies=[Depends(require_analyst)])
def ai_proposals(status: str | None = None, size: int = 100) -> list[dict[str, Any]]:
    q = {"bool": {"filter": [{"term": {"status": status}}]}} if status else None
    return store.search(es(), settings.IDX_AI_PROPOSALS, q, size=min(size, 500), sort=[{"created_at": "desc"}])


@app.post("/api/v1/ai/proposals/{pid}/approve", dependencies=[Depends(require_analyst)])
def ai_approve(pid: str, body: AIDecision) -> dict[str, Any]:
    return _ai(ai_deploy.approve, es(), pid, body.analyst, settings.RULES_DIR, now=store.now_iso())


@app.post("/api/v1/ai/proposals/{pid}/reject", dependencies=[Depends(require_analyst)])
def ai_reject(pid: str, body: AIDecision) -> dict[str, Any]:
    if len(body.reason.strip()) < 3:
        raise HTTPException(400, "từ chối phải ghi lý do (AI dùng lý do này để không lặp lại lỗi)")
    return _ai(ai_deploy.reject, es(), pid, body.analyst, body.reason.strip(), now=store.now_iso())


@app.post("/api/v1/ai/proposals/{pid}/rollback", dependencies=[Depends(require_analyst)])
def ai_rollback(pid: str, body: AIDecision) -> dict[str, Any]:
    if len(body.reason.strip()) < 3:
        raise HTTPException(400, "gỡ phải ghi lý do")
    return _ai(ai_deploy.rollback, es(), pid, body.analyst, body.reason.strip(), settings.RULES_DIR, now=store.now_iso())


@app.post("/api/v1/ai/run", dependencies=[Depends(require_analyst)])
def ai_run(body: AIDecision) -> dict[str, Any]:
    job = {"kind": "job", "status": "pending", "requested_by": body.analyst, "created_at": store.now_iso()}
    r = es().index(index=settings.IDX_AI_JOBS, document=job, refresh="wait_for")
    return job | {"id": r["_id"]}


@app.get("/api/v1/ai/status", dependencies=[Depends(require_analyst)])
def ai_status() -> dict[str, Any]:
    try:
        worker = es().get(index=settings.IDX_AI_JOBS, id="worker")["_source"]
    except Exception:  # noqa: BLE001
        worker = None
    jobs = store.search(es(), settings.IDX_AI_JOBS, {"term": {"kind": "job"}}, size=5, sort=[{"created_at": "desc"}])
    return {"worker": worker, "jobs": jobs}
