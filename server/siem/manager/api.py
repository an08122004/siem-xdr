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
import ipaddress
import logging
import re
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from elasticsearch import ConflictError, NotFoundError
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field

from .. import rules_catalog, settings, store
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
    catalog = asyncio.create_task(catalog_loop()) if settings.RULES_CATALOG_SECONDS > 0 else None
    log.info("manager sẵn sàng")
    yield
    for t in (grafana_setup, catalog):
        if t:
            t.cancel()
    await grafana_proxy.close()


async def catalog_loop() -> None:
    """Đồng bộ danh mục rule (Grafana "Thư viện rule") định kỳ; lỗi chỉ ghi log, lần sau thử lại."""
    while True:
        try:
            await asyncio.to_thread(rules_catalog.sync, es(), settings.RULES_DIR)
        except Exception as e:  # noqa: BLE001
            log.warning("đồng bộ danh mục rule lỗi: %s", e)
        await asyncio.sleep(settings.RULES_CATALOG_SECONDS)


def refresh_catalog() -> None:
    """Sau khi duyệt / từ chối / gỡ đề xuất: cập nhật danh mục ngay, không chờ chu kỳ."""
    try:
        rules_catalog.sync(es(), settings.RULES_DIR)
    except Exception as e:  # noqa: BLE001 - danh mục chỉ để tra cứu, không được làm hỏng thao tác duyệt
        log.warning("cập nhật danh mục rule lỗi: %s", e)


app = FastAPI(title="SIEM/XDR Manager", version="1.0.0", lifespan=lifespan)
app.include_router(auth.router)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    # chống clickjacking: chỉ cho nhúng trong chính hệ thống (console nhúng dashboard Grafana cùng origin)
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    resp.headers["Content-Security-Policy"] = "frame-ancestors 'self'"
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    if request.url.path.startswith("/api/"):
        resp.headers.setdefault("Cache-Control", "no-store")           # dữ liệu nhạy cảm không nằm trong cache
    return resp


def es():
    return _state["es"]


analyst = require_role("analyst")
lead = require_role("lead")


class NewAction(BaseModel):
    agent_id: str = Field(min_length=1, max_length=64)
    type: str
    params: dict[str, Any] = {}
    alert_id: str | None = Field(None, max_length=64)


ALERT_STATUSES = ("open", "acknowledged", "in_progress", "closed", "false_positive")


class AlertUpdate(BaseModel):
    status: str = Field(pattern=r"^(open|acknowledged|in_progress|closed|false_positive)$")
    note: str = Field("", max_length=4000)


SINCE = {"1h": "now-1h", "24h": "now-24h", "7d": "now-7d", "30d": "now-30d"}


def _csv(v: str | None) -> list[str]:
    return [x.strip() for x in (v or "").split(",") if x.strip()]


def _text_query(q: str, fields: list[str], ip_fields: list[str]) -> dict[str, Any]:
    """Ô tìm kiếm của console: IP -> so khớp trường IP; còn lại tìm theo từ trong các trường văn bản."""
    should: list[dict] = [{"simple_query_string": {"query": q, "fields": fields, "default_operator": "and",
                                                   "lenient": True}}]
    try:
        ipaddress.ip_address(q)
        should += [{"term": {f: q}} for f in ip_fields]
    except ValueError:
        should += [{"term": {f: q}} for f in ("rule.id", "host.name", "agent.id", "user.name", "entity", "id")]
    return {"bool": {"should": should, "minimum_should_match": 1}}


@app.get("/api/v1/agents", dependencies=[Depends(current_user)])
def agents() -> list[dict[str, Any]]:
    return store.list_agents(es())


@app.get("/api/v1/alerts", dependencies=[Depends(current_user)])
def alerts(status: str | None = None, severity: str | None = None, q: str | None = None, since: str | None = None,
           size: int = 100) -> list[dict[str, Any]]:
    """Lọc: status / severity (nhiều giá trị cách nhau bằng dấu phẩy), q (từ khóa hoặc IP), since (1h|24h|7d|30d)."""
    filters: list[dict] = []
    if st := _csv(status):
        filters.append({"terms": {"alert.status": st}})
    if sev := _csv(severity):
        filters.append({"terms": {"severity": sev}})
    if since in SINCE:
        filters.append({"range": {"@timestamp": {"gte": SINCE[since]}}})
    if q and q.strip():
        filters.append(_text_query(q.strip()[:200], ["message.text", "rule.name", "rule.id"], ["source.ip"]))
    return store.search(es(), settings.IDX_ALERTS, {"bool": {"filter": filters}}, size=min(max(size, 1), 1000))


def _get(index: str, doc_id: str, what: str) -> dict[str, Any]:
    try:
        return es().get(index=index, id=doc_id)
    except NotFoundError:
        raise HTTPException(404, f"không tìm thấy {what}")


@app.get("/api/v1/alerts/{alert_id}", dependencies=[Depends(current_user)])
def get_alert(alert_id: str) -> dict[str, Any]:
    """Một alert kèm case đang chứa nó và các lệnh phản ứng gắn với nó (trang chi tiết / liên kết từ Grafana)."""
    alert = _get(settings.IDX_ALERTS, alert_id, "alert")["_source"] | {"_id": alert_id}
    alert["cases"] = [{k: c.get(k) for k in ("_id", "id", "title", "status", "priority", "severity")}
                      for c in store.search(es(), settings.IDX_CASES, {"term": {"alert_ids": alert_id}}, size=5,
                                            sort=[{"created_at": "desc"}])]
    alert["actions"] = store.search(es(), settings.IDX_ACTIONS, {"term": {"alert_id": alert_id}}, size=20,
                                    sort=[{"created_at": "desc"}])
    return alert


@app.patch("/api/v1/alerts/{alert_id}")
def update_alert(alert_id: str, body: AlertUpdate, s: Session = Depends(analyst)) -> dict[str, Any]:
    """Đổi trạng thái alert; mọi lần đổi được ghi vào alert.history (ai, lúc nào, ghi chú)."""
    cur = _get(settings.IDX_ALERTS, alert_id, "alert")
    alert, now = cur["_source"], store.now_iso()
    old = (alert.get("alert") or {}).get("status")
    text = f"trạng thái: {old} -> {body.status}" + (f" — {body.note.strip()}" if body.note.strip() else "")
    history = ((alert.get("alert") or {}).get("history") or []) + [{"at": now, "by": s.username, "text": text}]
    try:
        es().update(index=settings.IDX_ALERTS, id=alert_id, refresh="wait_for",
                    if_seq_no=cur["_seq_no"], if_primary_term=cur["_primary_term"],
                    doc={"alert": {"status": body.status, "note": body.note.strip(), "updated_at": now,
                                   "updated_by": s.username, "history": history[-100:]}})
    except ConflictError:
        raise HTTPException(409, "alert vừa được cập nhật (bởi SOAR hoặc người khác), hãy thử lại")
    return {"ok": True, "status": body.status, "history": history[-100:]}


@app.get("/api/v1/actions", dependencies=[Depends(current_user)])
def actions(status: str | None = None, agent_id: str | None = None, size: int = 100) -> list[dict[str, Any]]:
    filters: list[dict] = []
    if st := _csv(status):
        filters.append({"terms": {"status": st}})
    if agent_id:
        filters.append({"term": {"agent_id": agent_id}})
    return store.search(es(), settings.IDX_ACTIONS, {"bool": {"filter": filters}}, size=min(max(size, 1), 1000),
                        sort=[{"created_at": "desc"}])


def validate_action(body: NewAction) -> None:
    """Kiểm tra lệnh thủ công trước khi tạo (script trên agent kiểm tra lại lần nữa)."""
    p = body.params
    if body.type in ("block_ip", "unblock_ip"):
        try:
            ip = ipaddress.ip_address(str(p.get("ip", "")).strip())
        except ValueError:
            raise HTTPException(400, f"IP không hợp lệ: {p.get('ip')!r}")
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
            raise HTTPException(400, f"không chặn địa chỉ đặc biệt {ip}")
        if body.type == "block_ip" and any(ip in ipaddress.ip_network(n, strict=False) for n in settings.SOAR_WHITELIST):
            raise HTTPException(400, f"{ip} nằm trong whitelist (SOAR_WHITELIST), không chặn")
        p["ip"] = str(ip)
    elif body.type == "kill_process":
        pid, name = p.get("pid"), p.get("name")
        if pid is not None:
            if not str(pid).isdigit() or int(pid) <= 1:
                raise HTTPException(400, f"PID không hợp lệ: {pid!r}")
            body.params = {"pid": int(pid)}
        elif not (isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9._-]{1,64}", name)):
            raise HTTPException(400, "cần PID hoặc tên tiến trình hợp lệ (chữ, số, . _ -)")
    if body.agent_id not in {a.get("agent_id") for a in store.list_agents(es())}:
        raise HTTPException(400, f"không có agent {body.agent_id}")


@app.post("/api/v1/actions")
def create_action(body: NewAction, s: Session = Depends(analyst)) -> dict[str, Any]:
    if body.type in ("isolate_host", "unisolate_host") and ROLES[s.role] < ROLES["lead"]:
        raise HTTPException(403, "cô lập / bỏ cô lập máy cần quyền lead (Trưởng nhóm IR)")
    if body.type not in store.ACTION_TYPES:
        raise HTTPException(400, f"loại lệnh không hỗ trợ: {body.type}")
    validate_action(body)
    return store.create_action(es(), body.agent_id, body.type, body.params, alert_id=body.alert_id,
                               source="manual", requested_by=s.username)


@app.get("/api/v1/cases", dependencies=[Depends(current_user)])
def cases(status: str | None = None, q: str | None = None, alert_id: str | None = None,
          size: int = 100) -> list[dict[str, Any]]:
    filters: list[dict] = []
    if st := _csv(status):
        filters.append({"terms": {"status": st}})
    if alert_id:
        filters.append({"term": {"alert_ids": alert_id}})
    if q and q.strip():
        filters.append(_text_query(q.strip()[:200], ["title", "entity", "rule_id"], ["entity"]))
    return store.search(es(), settings.IDX_CASES, {"bool": {"filter": filters}}, size=min(max(size, 1), 1000),
                        sort=[{"created_at": "desc"}])


CASE_STATUSES = r"^(open|in_progress|contained|closed|false_positive)$"


class CaseUpdate(BaseModel):
    status: str | None = Field(None, pattern=CASE_STATUSES)
    assignee: str | None = Field(None, max_length=64)
    note: str = Field("", max_length=4000)
    task_index: int | None = Field(None, ge=0)
    task_done: bool | None = None


@app.get("/api/v1/cases/{case_id}", dependencies=[Depends(current_user)])
def get_case(case_id: str) -> dict[str, Any]:
    """Case kèm tóm tắt các alert liên quan (tối đa 50 alert mới nhất) để mở từng alert."""
    case = _get(settings.IDX_CASES, case_id, "case")["_source"] | {"_id": case_id}
    ids = (case.get("alert_ids") or [])[-50:]
    case["alerts"] = [{"_id": a["_id"], "@timestamp": a.get("@timestamp"), "severity": a.get("severity"),
                       "rule": {k: (a.get("rule") or {}).get(k) for k in ("id", "name")},
                       "status": (a.get("alert") or {}).get("status")}
                      for a in store.search(es(), settings.IDX_ALERTS, {"terms": {"alert.id": ids}}, size=50)] if ids else []
    return case


@app.patch("/api/v1/cases/{case_id}")
def update_case(case_id: str, body: CaseUpdate, s: Session = Depends(analyst)) -> dict[str, Any]:
    """Cập nhật case: trạng thái, người xử lý, đánh dấu task playbook, ghi chú.
    Mọi thay đổi được ghi vào `notes` (lịch sử) kèm tài khoản thực hiện và thời điểm."""
    cur = _get(settings.IDX_CASES, case_id, "case")
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
        "ai_pending": count(settings.IDX_AI_PROPOSALS, {"term": {"status": "pending"}}),
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


GO_KINDS = {"alert": "alerts/{}", "case": "cases/{}", "proposal": "ai/{}",
            "rule": "alerts?set=all&since=30d&q={}"}       # rule -> danh sách cảnh báo của rule đó


@app.get("/go/{kind}/{doc_id}", include_in_schema=False)
@app.get("/grafana/go/{kind}/{doc_id}", include_in_schema=False)   # Grafana gắn tiền tố /grafana cho liên kết "/..."
def go(kind: str, doc_id: str) -> HTMLResponse:
    """Liên kết từ bảng Grafana sang chi tiết alert / case trên console. Grafana nằm trong khung (iframe) của console:
    trang này đưa CẢ CỬA SỔ (không phải riêng khung) tới /#/alerts/<id>; mở thẳng (tab mới) thì cũng chuyển như vậy."""
    if kind not in GO_KINDS or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", doc_id):
        raise HTTPException(404, "liên kết không hợp lệ")
    target = "/#/" + GO_KINDS[kind].format(doc_id)
    return HTMLResponse(f'<!doctype html><meta charset="utf-8"><title>Đang mở…</title>'
                        f'<script>(window.top === window ? location : window.top.location).replace("{target}")</script>'
                        f'<a href="{target}">Mở trên SOC console</a>')


# ---------------------------------------------------------------------------
# AI hỗ trợ viết rule — analyst duyệt / từ chối / gỡ đề xuất
# ---------------------------------------------------------------------------

from ..ai import deploy as ai_deploy  # noqa: E402


class AIDecision(BaseModel):
    reason: str = Field("", max_length=2000)


def _ai(fn, *args, **kw):
    try:
        res = fn(*args, **kw)
    except ai_deploy.DeployError as e:
        raise HTTPException(e.code, str(e))
    refresh_catalog()
    return res


@app.get("/api/v1/ai/proposals", dependencies=[Depends(current_user)])
def ai_proposals(status: str | None = None, size: int = 100) -> list[dict[str, Any]]:
    q = {"bool": {"filter": [{"term": {"status": status}}]}} if status else None
    rows = store.search(es(), settings.IDX_AI_PROPOSALS, q, size=min(size, 500), sort=[{"created_at": "desc"}])
    # nhãn để mở phần "So sánh với rule hiện có" của dashboard Thư viện rule đúng đề xuất này
    return [r | {"catalog_pick": rules_catalog.pick(r | {"id": r.get("id") or r["_id"]})} for r in rows]


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


# Route bắt-tất-cả /grafana/{path} phải đăng ký SAU mọi route của app (vd /grafana/go/...), FastAPI khớp theo thứ tự
app.include_router(grafana_proxy.router)
