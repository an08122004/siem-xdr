"""Manager API — điểm tiếp nhận của agent và giao diện cho analyst.

Agent:
  POST /api/v1/agents/enroll          (header X-Enrollment-Key [+ Bearer token hiện tại]) -> token ngẫu nhiên
                                      riêng của agent; agent_id đã tồn tại -> 409 trừ khi chứng minh được danh tính
  POST /api/v1/agents/heartbeat       (Bearer token)
  POST /api/v1/events                 (Bearer token) batch event -> Kafka siem.raw
  GET  /api/v1/agents/actions         (Bearer token) lấy lệnh phản ứng đang chờ
  POST /api/v1/actions/{id}/result    (Bearer token) báo kết quả thực thi

Analyst (header X-API-Key):
  GET  /api/v1/agents | /alerts | /actions | /cases | /stats
  PATCH /api/v1/alerts/{id}           đổi trạng thái alert (ack/closed/false_positive)
  POST /api/v1/actions                ra lệnh phản ứng thủ công (block IP, kill, isolate)
  POST /api/v1/agents/{id}/revoke     thu hồi token của agent
  POST /api/v1/agents/{id}/allow-reenroll  cho phép agent enroll lại (có hạn, có thể giới hạn IP)
  GET  /                              SOC console (HTML)

Chạy: uvicorn siem.manager.api:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
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

def legacy_token(agent_id: str) -> str:
    """Token kiểu cũ (HMAC theo agent_id). Không còn dùng để gọi API, chỉ để agent
    cũ chứng minh danh tính một lần khi đổi sang token ngẫu nhiên."""
    return hmac.new(settings.SERVER_SECRET.encode(), agent_id.encode(), hashlib.sha256).hexdigest()


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _matches(token: str, digest: str | None) -> bool:
    return bool(token and digest) and hmac.compare_digest(_hash(token), digest)


def _bearer(authorization: str) -> str:
    return authorization.removeprefix("Bearer ").strip()


# Cache ngắn hạn thông tin xác thực agent để không phải hỏi ES ở mọi request.
# Thu hồi / enroll trong manager này xóa cache ngay.
_CRED_TTL = 10.0
_cred_cache: dict[str, tuple[float, dict[str, Any] | None]] = {}


def _agent_doc(agent_id: str) -> dict[str, Any] | None:
    now = time.monotonic()
    hit = _cred_cache.get(agent_id)
    if hit and now - hit[0] < _CRED_TTL:
        return hit[1]
    doc = store.get_agent(es(), agent_id)
    _cred_cache[agent_id] = (now, doc)
    return doc


def require_agent(x_agent_id: str = Header(...), authorization: str = Header("")) -> str:
    token = _bearer(authorization)
    doc = _agent_doc(x_agent_id) if token else None
    if not doc or doc.get("revoked") or not _matches(token, doc.get("token_hash")):
        raise HTTPException(401, "token agent không hợp lệ")
    if not doc.get("token_confirmed"):
        # Agent đã nhận và dùng được token mới -> token trước đó hết hiệu lực hẳn.
        store.update_agent(es(), x_agent_id, {"token_confirmed": True, "prev_token_hash": None})
        doc.update(token_confirmed=True, prev_token_hash=None)
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


def audit(action: str, outcome: str, target_agent: str, ip: str | None, detail: str, analyst: str | None = None) -> None:
    """Ghi sự kiện quản trị agent vào pipeline như mọi event khác -> có rule phát hiện (AGENT-*)."""
    evt = {"timestamp": store.now_iso(), "agent_id": "siem-manager", "source": "manager", "event_type": "agent_audit",
           "data": {"action": action, "outcome": outcome, "target_agent": target_agent, "ip": ip,
                    "detail": detail, "analyst": analyst}}
    try:
        bus.send(_state["producer"], settings.TOPIC_RAW, evt, key="siem-manager")
        _state["producer"].poll(0)
    except Exception:  # noqa: BLE001 - không để lỗi Kafka chặn thao tác quản trị
        log.exception("không gửi được audit event %s", action)


def _parse_iso(s: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(s) if s else None
    except ValueError:
        return None


def enroll_reason(doc: dict[str, Any] | None, presented: str, ip: str | None, agent_id: str) -> str | None:
    """Có cấp token mới cho agent_id này không. Trả về lý do nếu được, None nếu phải từ chối.

    Khóa enroll dùng chung nằm trên mọi endpoint, nên nó KHÔNG đủ để nhận danh tính của một
    agent đã tồn tại. Với agent đã có, người gọi phải chứng minh mình là agent đó."""
    if doc is None:
        return "new"
    if doc.get("reenroll_allowed"):
        until = _parse_iso(doc.get("reenroll_until"))
        if until and datetime.now(timezone.utc) > until:
            return None
        if doc.get("reenroll_ip") and doc["reenroll_ip"] != ip:
            return None
        return "reset"
    if doc.get("revoked"):
        return None
    if doc.get("token_hash"):
        if _matches(presented, doc["token_hash"]):
            return "rotate"
        if not doc.get("token_confirmed"):
            # Token vừa cấp chưa từng được dùng: có thể phản hồi enroll trước đó bị mất trên đường.
            if _matches(presented, doc.get("prev_token_hash")):
                return "retry"
            if not presented and not doc.get("prev_token_hash") and ip and ip == doc.get("enroll_ip"):
                return "retry"
        return None
    # Agent cũ chưa có token ngẫu nhiên: chứng minh danh tính bằng token HMAC cũ.
    if presented and hmac.compare_digest(presented, legacy_token(agent_id)):
        return "legacy"
    return None


@app.post("/api/v1/agents/enroll")
def enroll(info: AgentInfo, request: Request, x_enrollment_key: str = Header(""),
           authorization: str = Header("")) -> dict[str, str]:
    ip = request.client.host
    if not hmac.compare_digest(x_enrollment_key, settings.ENROLLMENT_KEY):
        log.warning("enroll bị từ chối từ %s (agent_id=%s): sai enrollment key", ip, info.agent_id)
        audit("agent_enroll_bad_key", "failure", info.agent_id, ip, "enrollment key sai")
        raise HTTPException(403, "enrollment key sai")
    presented = _bearer(authorization)
    doc = store.get_agent(es(), info.agent_id)
    reason = enroll_reason(doc, presented, ip, info.agent_id)
    if reason is None:
        log.warning("từ chối enroll agent_id=%s từ %s: agent_id đã được enroll", info.agent_id, ip)
        audit("agent_enroll_conflict", "failure", info.agent_id, ip,
              f"enroll trùng agent_id đang có (máy đăng ký trước: {(doc or {}).get('enroll_ip') or (doc or {}).get('ip')})")
        raise HTTPException(409, "agent_id đã được enroll. Nếu đây đúng là máy đó (cài lại, mất token), "
                                 "analyst cần bấm 'Cho enroll lại' trên console")
    token = secrets.token_urlsafe(32)
    keep_prev = reason in ("rotate", "legacy", "retry") and bool(presented)
    store.upsert_agent(es(), info.model_dump(), ip, extra={
        "token_hash": _hash(token), "token_confirmed": False,
        "prev_token_hash": _hash(presented) if keep_prev else None,
        "revoked": False, "reenroll_allowed": False, "reenroll_until": None, "reenroll_ip": None,
        "enrolled_at": store.now_iso(), "enroll_ip": ip, "enroll_reason": reason})
    _cred_cache.pop(info.agent_id, None)
    log.info("agent %s (%s/%s) đã enroll từ %s (%s)", info.agent_id, info.hostname, info.os, ip, reason)
    audit("agent_enrolled", "success", info.agent_id, ip, reason)
    return {"token": token}


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


class AgentDecision(BaseModel):
    analyst: str = Field(min_length=1, max_length=64)
    reason: str = Field("", max_length=500)
    ip: str | None = Field(None, max_length=64)   # chỉ cho enroll lại từ IP này (tùy chọn)
    minutes: int = Field(60, ge=5, le=1440)       # cửa sổ cho phép enroll lại


def _existing_agent(agent_id: str) -> dict[str, Any]:
    doc = store.get_agent(es(), agent_id)
    if doc is None:
        raise HTTPException(404, "không có agent này")
    return doc


@app.post("/api/v1/agents/{agent_id}/revoke", dependencies=[Depends(require_analyst)])
def revoke_agent(agent_id: str, body: AgentDecision) -> dict[str, Any]:
    """Thu hồi token: agent bị từ chối ngay (tối đa sau thời gian cache), không tự enroll lại được."""
    _existing_agent(agent_id)
    store.update_agent(es(), agent_id, {
        "revoked": True, "reenroll_allowed": False, "token_hash": None, "prev_token_hash": None,
        "revoked_at": store.now_iso(), "revoked_by": body.analyst, "revoke_reason": body.reason})
    _cred_cache.pop(agent_id, None)
    audit("agent_revoked", "success", agent_id, None, body.reason, analyst=body.analyst)
    log.info("agent %s bị thu hồi bởi %s", agent_id, body.analyst)
    return {"ok": True, "enrollment": "revoked"}


@app.post("/api/v1/agents/{agent_id}/allow-reenroll", dependencies=[Depends(require_analyst)])
def allow_reenroll(agent_id: str, body: AgentDecision) -> dict[str, Any]:
    """Cho phép enroll lại (máy cài lại / mất token). Token cũ hết hiệu lực ngay.
    Nên giới hạn theo IP của máy thật để kẻ khác không chen vào trước."""
    _existing_agent(agent_id)
    until = (datetime.now(timezone.utc) + timedelta(minutes=body.minutes)).isoformat()
    store.update_agent(es(), agent_id, {
        "revoked": False, "reenroll_allowed": True, "reenroll_until": until, "reenroll_ip": body.ip or None,
        "token_hash": None, "prev_token_hash": None,
        "reenroll_allowed_by": body.analyst, "reenroll_allowed_at": store.now_iso()})
    _cred_cache.pop(agent_id, None)
    audit("agent_reenroll_allowed", "success", agent_id, body.ip, f"tới {until}. {body.reason}".strip(), analyst=body.analyst)
    return {"ok": True, "enrollment": "reenroll_allowed", "until": until, "ip": body.ip}


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
