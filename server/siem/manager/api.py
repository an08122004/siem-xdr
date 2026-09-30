"""Manager API — SOC console và API cho analyst.

Agent là Wazuh agent: enroll, gửi event và nhận lệnh phản ứng qua wazuh-manager (không qua API này).
Danh sách agent do SOAR đồng bộ từ Wazuh API; lệnh tạo ở đây được SOAR gửi xuống agent (soar/wazuh.py).

Đăng nhập bằng tài khoản riêng (manager/auth.py): POST /api/v1/auth/login -> cookie phiên. Người thực hiện mọi
thao tác (case, lệnh, duyệt AI) lấy từ phiên, không tự khai.
  GET  /api/v1/agents | /alerts | /actions | /cases | /stats | /ai/...     mọi tài khoản
  PATCH /api/v1/alerts/{id}, /cases/{id}; POST /api/v1/actions; duyệt AI   analyst trở lên
  POST /api/v1/actions (isolate_host / unisolate_host)                     lead trở lên
  /api/v1/users                                                            admin
  GET  /                                                                   SOC console (HTML)

Chạy: uvicorn siem.manager.api:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse
from pydantic import BaseModel, Field

from .. import settings, store
from . import auth, grafana_proxy
from .auth import ROLES, Session, current_user, require_role

log = logging.getLogger("manager")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

STATIC = Path(__file__).parent / "static"

_state: dict[str, Any] = {}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    _state["es"] = store.connect()
    auth.setup(_state["es"])
    grafana_setup = asyncio.create_task(grafana_proxy.ensure_folder_permissions()) if settings.GRAFANA_URL else None
    log.info("manager sẵn sàng")
    yield
    if grafana_setup:
        grafana_setup.cancel()
    await grafana_proxy.close()


app = FastAPI(title="SIEM/XDR Manager", version="1.0.0", lifespan=lifespan)
app.include_router(auth.router)
app.include_router(grafana_proxy.router)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")                  # chống clickjacking console
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    if request.url.path.startswith("/api/"):
        resp.headers.setdefault("Cache-Control", "no-store")           # dữ liệu nhạy cảm không nằm trong cache
    return resp


def es():
    return _state["es"]


analyst = require_role("analyst")
lead = require_role("lead")


class NewAction(BaseModel):
    agent_id: str
    type: str
    params: dict[str, Any] = {}
    alert_id: str | None = None


class AlertUpdate(BaseModel):
    status: str = Field(pattern=r"^(open|acknowledged|in_progress|closed|false_positive)$")
    note: str = ""


@app.get("/api/v1/agents", dependencies=[Depends(current_user)])
def agents() -> list[dict[str, Any]]:
    return store.list_agents(es())


@app.get("/api/v1/alerts", dependencies=[Depends(current_user)])
def alerts(status: str | None = None, severity: str | None = None, size: int = 100) -> list[dict[str, Any]]:
    filters: list[dict] = []
    if status:
        filters.append({"term": {"alert.status": status}})
    if severity:
        filters.append({"term": {"severity": severity}})
    return store.search(es(), settings.IDX_ALERTS, {"bool": {"filter": filters}}, size=min(size, 1000))


@app.patch("/api/v1/alerts/{alert_id}")
def update_alert(alert_id: str, body: AlertUpdate, s: Session = Depends(analyst)) -> dict[str, bool]:
    es().update(index=settings.IDX_ALERTS, id=alert_id, refresh="wait_for",
                doc={"alert": {"status": body.status, "note": body.note, "updated_at": store.now_iso(),
                               "updated_by": s.username}})
    return {"ok": True}


@app.get("/api/v1/actions", dependencies=[Depends(current_user)])
def actions(size: int = 100) -> list[dict[str, Any]]:
    return store.search(es(), settings.IDX_ACTIONS, size=min(size, 1000), sort=[{"created_at": "desc"}])


@app.post("/api/v1/actions")
def create_action(body: NewAction, s: Session = Depends(analyst)) -> dict[str, Any]:
    if body.type in ("isolate_host", "unisolate_host") and ROLES[s.role] < ROLES["lead"]:
        raise HTTPException(403, "cô lập / bỏ cô lập máy cần quyền lead (Trưởng nhóm IR)")
    try:
        return store.create_action(es(), body.agent_id, body.type, body.params, alert_id=body.alert_id,
                                   source="manual", requested_by=s.username)
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.get("/api/v1/cases", dependencies=[Depends(current_user)])
def cases(size: int = 100) -> list[dict[str, Any]]:
    return store.search(es(), settings.IDX_CASES, size=min(size, 1000), sort=[{"created_at": "desc"}])


CASE_STATUSES = r"^(open|in_progress|contained|closed|false_positive)$"


class CaseUpdate(BaseModel):
    status: str | None = Field(None, pattern=CASE_STATUSES)
    assignee: str | None = Field(None, max_length=64)
    note: str = Field("", max_length=4000)
    task_index: int | None = Field(None, ge=0)
    task_done: bool | None = None


@app.get("/api/v1/cases/{case_id}", dependencies=[Depends(current_user)])
def get_case(case_id: str) -> dict[str, Any]:
    try:
        return es().get(index=settings.IDX_CASES, id=case_id)["_source"]
    except Exception:  # noqa: BLE001
        raise HTTPException(404, "không tìm thấy case")


@app.patch("/api/v1/cases/{case_id}")
def update_case(case_id: str, body: CaseUpdate, s: Session = Depends(analyst)) -> dict[str, Any]:
    """Cập nhật case: trạng thái, người xử lý, đánh dấu task playbook, ghi chú.
    Mọi thay đổi được ghi vào `notes` (lịch sử) kèm tài khoản thực hiện và thời điểm."""
    try:
        cur = es().get(index=settings.IDX_CASES, id=case_id)
    except Exception:  # noqa: BLE001
        raise HTTPException(404, "không tìm thấy case")
    case, now, who = cur["_source"], store.now_iso(), s.username
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
        t.update(done=body.task_done, done_by=who if body.task_done else None,
                 done_at=now if body.task_done else None)
        changes["tasks"] = tasks
        history.append(f"{'hoàn thành' if body.task_done else 'bỏ đánh dấu'} task [{t['phase']}] {t['title']}")
    if body.note.strip():
        history.append(f"ghi chú: {body.note.strip()}")
    if not history:
        return case
    changes["notes"] = (case.get("notes") or []) + [{"at": now, "by": who, "text": h} for h in history]
    try:
        es().update(index=settings.IDX_CASES, id=case_id, doc=changes, refresh="wait_for",
                    if_seq_no=cur["_seq_no"], if_primary_term=cur["_primary_term"])
    except Exception:  # noqa: BLE001 - người khác vừa sửa case
        raise HTTPException(409, "case vừa được người khác cập nhật, hãy tải lại")
    log.info("case %s cập nhật bởi %s: %s", case_id, who, "; ".join(history))
    return case | changes


@app.get("/api/v1/stats", dependencies=[Depends(current_user)])
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


@app.get("/", response_model=None)
def console(request: Request) -> FileResponse | RedirectResponse:
    """Chưa đăng nhập / hết phiên / phải đổi mật khẩu -> trang đăng nhập dùng chung (console + Grafana)."""
    token = request.cookies.get(auth.COOKIE)
    s = auth.sessions.get(token) if token else None
    if not s:
        return RedirectResponse("/login?" + ("reason=expired&" if token else "") + "next=%2F", status_code=303)
    if s.must_change:
        return RedirectResponse("/login?change=1&next=%2F", status_code=303)
    return FileResponse(STATIC / "console.html")


@app.get("/login", include_in_schema=False)
def login_page() -> FileResponse:
    return FileResponse(STATIC / "login.html")


# ---------------------------------------------------------------------------
# AI hỗ trợ viết rule — analyst duyệt / từ chối / gỡ đề xuất
# ---------------------------------------------------------------------------

from ..ai import deploy as ai_deploy  # noqa: E402


class AIDecision(BaseModel):
    reason: str = Field("", max_length=2000)


def _ai(fn, *args, **kw):
    try:
        return fn(*args, **kw)
    except ai_deploy.DeployError as e:
        raise HTTPException(e.code, str(e))


@app.get("/api/v1/ai/proposals", dependencies=[Depends(current_user)])
def ai_proposals(status: str | None = None, size: int = 100) -> list[dict[str, Any]]:
    q = {"bool": {"filter": [{"term": {"status": status}}]}} if status else None
    return store.search(es(), settings.IDX_AI_PROPOSALS, q, size=min(size, 500), sort=[{"created_at": "desc"}])


@app.post("/api/v1/ai/proposals/{pid}/approve")
def ai_approve(pid: str, s: Session = Depends(analyst)) -> dict[str, Any]:
    # ngoại lệ cần 2 người KHÁC NHAU duyệt: danh tính lấy từ phiên nên không giả được bằng cách đổi tên
    return _ai(ai_deploy.approve, es(), pid, s.username, settings.RULES_DIR, now=store.now_iso())


@app.post("/api/v1/ai/proposals/{pid}/reject")
def ai_reject(pid: str, body: AIDecision, s: Session = Depends(analyst)) -> dict[str, Any]:
    if len(body.reason.strip()) < 3:
        raise HTTPException(400, "từ chối phải ghi lý do (AI dùng lý do này để không lặp lại lỗi)")
    return _ai(ai_deploy.reject, es(), pid, s.username, body.reason.strip(), now=store.now_iso())


@app.post("/api/v1/ai/proposals/{pid}/rollback")
def ai_rollback(pid: str, body: AIDecision, s: Session = Depends(analyst)) -> dict[str, Any]:
    if len(body.reason.strip()) < 3:
        raise HTTPException(400, "gỡ phải ghi lý do")
    return _ai(ai_deploy.rollback, es(), pid, s.username, body.reason.strip(), settings.RULES_DIR, now=store.now_iso())


@app.post("/api/v1/ai/run")
def ai_run(s: Session = Depends(analyst)) -> dict[str, Any]:
    job = {"kind": "job", "status": "pending", "requested_by": s.username, "created_at": store.now_iso()}
    r = es().index(index=settings.IDX_AI_JOBS, document=job, refresh="wait_for")
    return job | {"id": r["_id"]}


@app.get("/api/v1/ai/status", dependencies=[Depends(current_user)])
def ai_status() -> dict[str, Any]:
    try:
        worker = es().get(index=settings.IDX_AI_JOBS, id="worker")["_source"]
    except Exception:  # noqa: BLE001
        worker = None
    jobs = store.search(es(), settings.IDX_AI_JOBS, {"term": {"kind": "job"}}, size=5, sort=[{"created_at": "desc"}])
    return {"worker": worker, "jobs": jobs}
