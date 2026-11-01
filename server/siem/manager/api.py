"""Manager API — SOC console và API cho analyst.

Agent là Wazuh agent: enroll, gửi event và nhận lệnh phản ứng qua wazuh-manager (không qua API này).
Danh sách agent do SOAR đồng bộ từ Wazuh API; lệnh tạo ở đây được SOAR gửi xuống agent (soar/wazuh.py).

Đăng nhập bằng tài khoản riêng (manager/auth.py): POST /api/v1/auth/login -> cookie phiên. Người thực hiện mọi
thao tác (case, lệnh, duyệt AI) lấy từ phiên, không tự khai. Quyền theo năng lực của vai trò (auth.PERMISSIONS):
  GET  /api/v1/agents | /alerts | /actions | /cases | /stats | /ai/...     mọi tài khoản
  PATCH /api/v1/alerts/{id}, /cases/{id}; POST /api/v1/actions             triage (alert chạy bóng: cả rules)
  POST /api/v1/actions (isolate_host / unisolate_host), đổi ưu tiên case   contain
  POST /api/v1/alerts/{id}/soar/decline (từ chối bước SOAR chờ duyệt)      triage (cô lập: contain)
  PATCH /api/v1/cases/{id} với task cần duyệt                              theo nhãn approval của task
  POST /api/v1/cases/{id}/incident (tuyên bố sự cố lớn, đã thông báo)      declare
  duyệt / từ chối / gỡ đề xuất AI, bật chính thức rule chạy bóng           rules
  /api/v1/users                                                            users
  GET  /                                                                   SOC console (HTML)

Chạy: uvicorn siem.manager.api:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from elasticsearch import ConflictError, NotFoundError
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field

from .. import priority as prio
from .. import rules_catalog, settings, store
from . import auth, grafana_proxy, kpi, soc
from .auth import Session, current_user, has, require_perm

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
    kpis = asyncio.create_task(kpi_loop()) if settings.KPI_SECONDS > 0 else None
    log.info("manager sẵn sàng")
    yield
    for t in (grafana_setup, catalog, kpis):
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


def compute_kpi() -> dict[str, Any]:
    doc = kpi.compute(es(), settings.RULES_DIR, settings.CONFIG_DIR)
    kpi.save(es(), doc)
    return doc


async def kpi_loop() -> None:
    """KPI SOC (manager/kpi.py) tính định kỳ, lưu thành chuỗi thời gian cho dashboard SOC KPI."""
    await asyncio.sleep(20)                         # chờ SOAR / analyzer khởi động, index đã có
    while True:
        try:
            await asyncio.to_thread(compute_kpi)
        except Exception as e:  # noqa: BLE001
            log.warning("tính KPI lỗi: %s", e)
        await asyncio.sleep(settings.KPI_SECONDS)


def refresh_catalog() -> None:
    """Sau khi duyệt / từ chối / gỡ đề xuất: cập nhật danh mục ngay, không chờ chu kỳ."""
    try:
        rules_catalog.sync(es(), settings.RULES_DIR)
    except Exception as e:  # noqa: BLE001 - danh mục chỉ để tra cứu, không được làm hỏng thao tác duyệt
        log.warning("cập nhật danh mục rule lỗi: %s", e)


# tắt /docs, /redoc, /openapi.json: các trang này không qua đăng nhập, làm lộ sơ đồ API trên cổng 8000 mở ra ngoài
app = FastAPI(title="SIEM/XDR Manager", version="1.0.0", lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)
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


# Thao tác ghi dữ liệu trong console -> nhật ký hoạt động theo người dùng, cùng kênh với đăng nhập (auth.audit: file nhật ký ->
# wazuh-manager -> Kafka -> siem-events, event.module console). Đăng nhập / tài khoản / phiên tự ghi trong auth.py nên không có ở đây.
ACTIVITY = [(re.compile(p), op) for p, op in (
    (r"^/api/v1/alerts/[^/]+$", "alert_updated"), (r"^/api/v1/alerts/[^/]+/soar/decline$", "soar_declined"),
    (r"^/api/v1/actions$", "action_requested"), (r"^/api/v1/cases/[^/]+$", "case_updated"),
    (r"^/api/v1/ai/proposals/[^/]+/approve$", "ai_approved"), (r"^/api/v1/ai/proposals/[^/]+/reject$", "ai_rejected"),
    (r"^/api/v1/ai/proposals/[^/]+/rollback$", "ai_rolled_back"), (r"^/api/v1/ai/run$", "ai_run"),
    (r"^/api/v1/cases/[^/]+/incident$", "case_incident"), (r"^/api/v1/rules/[^/]+/promote$", "rule_promoted"),
    (r"^/api/v1/hunts$", "hunt_created"), (r"^/api/v1/hunts/[^/]+$", "hunt_updated"),
    (r"^/api/v1/handover$", "handover_saved"), (r"^/api/v1/ai/assist$", "ai_assist"),
    (r"^/api/v1/ai/assist/[^/]+/feedback$", "ai_assist_feedback"))]


def activity_detail(body: bytes) -> str | None:
    """Vài trường an toàn của body để nhật ký đọc được (vd "type=block_ip agent_id=001 ip=1.2.3.4"); không ghi ghi chú."""
    try:
        data = json.loads(body) if body and len(body) < 16384 else {}
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    params = data.get("params") if isinstance(data.get("params"), dict) else {}
    parts = [f"{k}={data[k]}" for k in ("status", "type", "agent_id", "assignee", "priority", "action", "task", "to")
             if data.get(k) not in (None, "")]
    parts += [f"{k}={params[k]}" for k in ("ip", "pid", "name") if params.get(k) not in (None, "")]
    return " ".join(str(p)[:80] for p in parts) or None


@app.middleware("http")
async def activity_log(request: Request, call_next):
    op = request.method in ("POST", "PATCH", "PUT", "DELETE") and \
        next((op for rx, op in ACTIVITY if rx.match(request.url.path)), None)
    if not op:
        return await call_next(request)
    body = await request.body()
    resp = await call_next(request)
    token = request.cookies.get(auth.COOKIE)
    s = auth.sessions.get(token, touch=False) if token else None
    if s:
        await asyncio.to_thread(auth.audit, "activity", "success" if resp.status_code < 400 else "failure", s.username,
                                auth.client_ip(request), role=s.role, op=op, method=request.method,
                                path=request.url.path, status=resp.status_code, change=activity_detail(body))
    return resp


def es():
    return _state["es"]


soc.setup(es)


triage = require_perm("triage")
contain = require_perm("contain")
rules_perm = require_perm("rules")
declare = require_perm("declare")


class NewAction(BaseModel):
    agent_id: str = Field(min_length=1, max_length=64)
    type: str
    params: dict[str, Any] = {}
    alert_id: str | None = Field(None, max_length=64)


ALERT_STATUSES = ("open", "acknowledged", "in_progress", "closed", "false_positive")
ACTIVE_ALERT_STATUSES = ALERT_STATUSES[:3]              # chưa đóng
CLOSED_STATUSES = ("closed", "false_positive")
# Kết luận bắt buộc khi đóng alert / case (đo tỉ lệ báo nhầm, SOC-OPERATIONS.md mục 3). "false_positive" luôn đi cùng
# trạng thái false_positive (AI worker lấy nhãn báo nhầm theo trạng thái này, ai/dataset.py).
VERDICTS = {"true_positive": "Đúng - độc hại", "benign_true_positive": "Đúng - hoạt động hợp lệ (pentest, quản trị)",
            "false_positive": "Báo nhầm", "duplicate": "Trùng lặp"}
VERDICT_PATTERN = "^(" + "|".join(VERDICTS) + ")$"


class AlertUpdate(BaseModel):
    status: str = Field(pattern=r"^(open|acknowledged|in_progress|closed|false_positive)$")
    note: str = Field("", max_length=4000)
    verdict: str | None = Field(None, pattern=VERDICT_PATTERN)


def closing(status: str, verdict: str | None, what: str) -> tuple[str, str | None]:
    """(trạng thái, kết luận) sau khi chuẩn hóa: đóng phải có kết luận; kết luận báo nhầm -> trạng thái false_positive."""
    if status == "false_positive":
        return status, "false_positive"
    if status == "closed":
        if not verdict:
            raise HTTPException(400, f"đóng {what} phải chọn kết luận: " + ", ".join(VERDICTS.values()))
        return ("false_positive" if verdict == "false_positive" else "closed"), verdict
    return status, None


SINCE = {"1h": "now-1h", "24h": "now-24h", "7d": "now-7d", "30d": "now-30d"}


def _csv(v: str | None) -> list[str]:
    return [x.strip() for x in (v or "").split(",") if x.strip()]


def _text_query(q: str, fields: list[str], ip_fields: list[str], contains: tuple[str, ...] = ()) -> dict[str, Any]:
    """Ô tìm kiếm của console: IP -> so khớp trường IP; còn lại tìm theo từ trong các trường văn bản.
    `contains`: trường keyword (không có bản .text) tìm theo chuỗi con, không phân biệt hoa thường — vd tiêu đề case:
    simple_query_string trên keyword chỉ khớp khi gõ nguyên văn cả tiêu đề, gõ "brute" không ra case nào."""
    should: list[dict] = [{"simple_query_string": {"query": q, "fields": fields, "default_operator": "and",
                                                   "lenient": True}}]
    pattern = "*" + re.sub(r"([\\*?])", r"\\\1", q) + "*"
    should += [{"wildcard": {f: {"value": pattern, "case_insensitive": True}}} for f in contains]
    try:
        ipaddress.ip_address(q)
        should += [{"term": {f: q}} for f in ip_fields]
    except ValueError:
        should += [{"term": {f: q}} for f in ("rule.id", "host.name", "agent.id", "user.name", "entity", "id")]
    return {"bool": {"should": should, "minimum_should_match": 1}}


@app.get("/api/v1/agents", dependencies=[Depends(current_user)])
def agents() -> list[dict[str, Any]]:
    return store.list_agents(es())


NOT_SHADOW = {"term": {"alert.shadow": True}}         # dùng trong must_not: alert của rule chạy bóng


@app.get("/api/v1/alerts", dependencies=[Depends(current_user)])
def alerts(status: str | None = None, severity: str | None = None, priority: str | None = None, q: str | None = None,
           since: str | None = None, shadow: str = "exclude", size: int = 100) -> list[dict[str, Any]]:
    """Lọc: status / severity / priority (nhiều giá trị cách nhau bằng dấu phẩy), q (từ khóa hoặc IP), since
    (1h|24h|7d|30d), shadow: exclude (mặc định, ẩn alert của rule chạy bóng) | only | all."""
    filters: list[dict] = []
    if st := _csv(status):
        filters.append({"terms": {"alert.status": st}})
    if sev := _csv(severity):
        filters.append({"terms": {"severity": sev}})
    if pr := _csv(priority):
        filters.append({"terms": {"priority": pr}})
    if since in SINCE:
        filters.append({"range": {"@timestamp": {"gte": SINCE[since]}}})
    if q and q.strip():
        filters.append(_text_query(q.strip()[:200], ["message.text", "rule.name", "rule.id"], ["source.ip"]))
    if shadow == "only":
        filters.append(NOT_SHADOW)
    query: dict[str, Any] = {"bool": {"filter": filters}}
    if shadow not in ("only", "all"):
        query["bool"]["must_not"] = [NOT_SHADOW]
    return store.search(es(), settings.IDX_ALERTS, query, size=min(max(size, 1), 1000))


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
def update_alert(alert_id: str, body: AlertUpdate, s: Session = Depends(current_user)) -> dict[str, Any]:
    """Đổi trạng thái alert; mọi lần đổi được ghi vào alert.history (ai, lúc nào, ghi chú). Đóng phải có kết luận.
    Lần đầu analyst đổi trạng thái = xác nhận (acknowledged_at, metrics.tta_seconds cho KPI MTTA). Alert chạy bóng:
    Detection Engineer (quyền rules) cũng ghi kết luận được, để đo tỉ lệ báo nhầm trước khi bật rule chính thức."""
    cur = _get(settings.IDX_ALERTS, alert_id, "alert")
    alert, now = cur["_source"], store.now_iso()
    meta = alert.get("alert") or {}
    if not (has(s.role, "triage") or (meta.get("shadow") and has(s.role, "rules"))):
        raise HTTPException(403, "cần quyền xử lý cảnh báo")
    status, verdict = closing(body.status, body.verdict, "cảnh báo")
    old = meta.get("status")
    text = f"trạng thái: {old} -> {status}" + (f" ({VERDICTS[verdict]})" if verdict else "") + \
        (f" — {body.note.strip()}" if body.note.strip() else "")
    history = (meta.get("history") or []) + [{"at": now, "by": s.username, "text": text}]
    change: dict[str, Any] = {"status": status, "note": body.note.strip(), "updated_at": now, "updated_by": s.username,
                              "history": history[-100:], "verdict": verdict,
                              "closed_at": now if status in CLOSED_STATUSES else None,
                              "closed_by": s.username if status in CLOSED_STATUSES else None}
    doc: dict[str, Any] = {"alert": change}
    if not meta.get("acknowledged_at") and status != "open":
        change.update(acknowledged_at=now, acknowledged_by=s.username)
        doc["metrics"] = {"tta_seconds": prio.seconds_between(alert.get("@timestamp"), now)}
    try:
        es().update(index=settings.IDX_ALERTS, id=alert_id, refresh="wait_for",
                    if_seq_no=cur["_seq_no"], if_primary_term=cur["_primary_term"], doc=doc)
    except ConflictError:
        raise HTTPException(409, "alert vừa được cập nhật (bởi SOAR hoặc người khác), hãy thử lại")
    return {"ok": True, "status": status, "verdict": verdict, "history": history[-100:]}


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


def decide_soar_step(alert_id: str, action: str, changes: dict[str, Any], note: dict[str, Any]) -> bool:
    """Bước `action` của SOAR đang chờ duyệt trên alert (playbook có `approval: true`) -> ghi quyết định: đã duyệt / từ
    chối, ai, lúc nào. Trước đây bước này hiện "chờ duyệt" mãi, không biết đã có ai quyết định chưa. False: không có
    bước nào đang chờ."""
    for _ in range(3):
        try:
            cur = es().get(index=settings.IDX_ALERTS, id=alert_id)
        except NotFoundError:
            return False
        src = cur["_source"]
        results = (src.get("soar") or {}).get("results") or []
        waiting = [r for r in results if r.get("action") == action and r.get("status") == "awaiting_approval"]
        if not waiting:
            return False
        for r in waiting:
            r.update(changes)
        history = ((src.get("alert") or {}).get("history") or []) + [note]
        try:
            es().update(index=settings.IDX_ALERTS, id=alert_id, refresh="wait_for",
                        if_seq_no=cur["_seq_no"], if_primary_term=cur["_primary_term"],
                        doc={"soar": {"results": results}, "alert": {"history": history[-100:]}})
            return True
        except ConflictError:
            continue                                # SOAR / người khác vừa sửa alert: đọc lại
    return False


@app.post("/api/v1/actions")
def create_action(body: NewAction, s: Session = Depends(triage)) -> dict[str, Any]:
    if body.type in ("isolate_host", "unisolate_host") and not has(s.role, "contain"):
        raise HTTPException(403, "cô lập / bỏ cô lập máy cần quyền contain (Trưởng nhóm IR)")
    if body.type not in store.ACTION_TYPES:
        raise HTTPException(400, f"loại lệnh không hỗ trợ: {body.type}")
    validate_action(body)
    a = store.create_action(es(), body.agent_id, body.type, body.params, alert_id=body.alert_id,
                            source="manual", requested_by=s.username)
    if body.alert_id:                               # tạo đúng lệnh SOAR đang chờ duyệt = duyệt bước đó
        try:
            decide_soar_step(body.alert_id, body.type, {"status": "approved", "approved_by": s.username,
                                                        "approved_at": a["created_at"], "action_id": a["id"]},
                             {"at": a["created_at"], "by": s.username, "text": f"duyệt bước SOAR {body.type} (lệnh {a['id']})"})
        except Exception as e:  # noqa: BLE001 - lệnh đã tạo; ghi quyết định lỗi không được làm hỏng thao tác
            log.warning("không ghi được quyết định duyệt trên alert %s: %s", body.alert_id, e)
    return a


class SoarDecline(BaseModel):
    action: str = Field(pattern=r"^(block_ip|kill_process|isolate_host)$")
    reason: str = Field("", max_length=2000)


@app.post("/api/v1/alerts/{alert_id}/soar/decline")
def decline_soar_step(alert_id: str, body: SoarDecline, s: Session = Depends(triage)) -> dict[str, Any]:
    """Không thực hiện bước SOAR đang chờ duyệt, ghi ai quyết định và vì sao. Cần cùng quyền với việc tự tạo lệnh đó
    (cô lập máy: contain)."""
    if body.action == "isolate_host" and not has(s.role, "contain"):
        raise HTTPException(403, "quyết định cô lập máy cần quyền contain (Trưởng nhóm IR)")
    reason = body.reason.strip()
    if len(reason) < 3:
        raise HTTPException(400, "từ chối phải ghi lý do")
    _get(settings.IDX_ALERTS, alert_id, "alert")
    now = store.now_iso()
    if not decide_soar_step(alert_id, body.action,
                            {"status": "declined", "declined_by": s.username, "declined_at": now, "reason": reason},
                            {"at": now, "by": s.username, "text": f"từ chối bước SOAR {body.action}: {reason}"}):
        raise HTTPException(409, "không có bước SOAR nào đang chờ duyệt (đã có người duyệt / từ chối?)")
    return {"ok": True, "status": "declined"}


@app.get("/api/v1/cases", dependencies=[Depends(current_user)])
def cases(status: str | None = None, q: str | None = None, alert_id: str | None = None,
          size: int = 100) -> list[dict[str, Any]]:
    filters: list[dict] = []
    if st := _csv(status):
        filters.append({"terms": {"status": st}})
    if alert_id:
        filters.append({"term": {"alert_ids": alert_id}})
    if q and q.strip():
        filters.append(_text_query(q.strip()[:200], ["title", "entity", "rule_id"], ["entity"], contains=("title",)))
    return store.search(es(), settings.IDX_CASES, {"bool": {"filter": filters}}, size=min(max(size, 1), 1000),
                        sort=[{"created_at": "desc"}])


CASE_STATUSES = r"^(open|in_progress|contained|closed|false_positive)$"
# Ai được đánh dấu task cần duyệt (nhãn `approval` trong config/case_playbooks.yml, bảng phân quyền ở README mục 4) ->
# quyền cần có (auth.PERMISSIONS). Nhãn lạ (vd playbook tự viết) cần contain. Chủ hệ thống không có tài khoản trên
# console: ai đồng ý thì ghi vào note.
APPROVAL_PERMISSIONS = {"Analyst L1": "triage", "Trưởng nhóm IR": "contain", "Trưởng nhóm IR + chủ hệ thống": "contain",
                        "SOC Manager": "declare"}
OWNER_APPROVAL = "chủ hệ thống"
# Luật Bảo vệ dữ liệu cá nhân 91/2025/QH15, Điều 23: thông báo vi phạm chậm nhất 72 giờ từ khi phát hiện. Tính từ lúc
# hệ thống phát hiện (tạo case), không từ lúc tuyên bố sự cố: cách tính thận trọng (SOC-OPERATIONS.md mục 6).
BREACH_NOTIFY_HOURS = 72


def approval_permission(task: dict[str, Any]) -> str | None:
    return APPROVAL_PERMISSIONS.get(task["approval"], "contain") if task.get("approval") else None


class CaseUpdate(BaseModel):
    status: str | None = Field(None, pattern=CASE_STATUSES)
    verdict: str | None = Field(None, pattern=VERDICT_PATTERN)
    priority: str | None = Field(None, pattern=r"^P[1-4]$")
    assignee: str | None = Field(None, max_length=64)
    note: str = Field("", max_length=4000)
    task_index: int | None = Field(None, ge=0)
    task_done: bool | None = None
    close_alerts: bool = True           # đóng case -> đóng luôn các alert còn mở trong case, cùng kết luận


@app.get("/api/v1/cases/{case_id}", dependencies=[Depends(current_user)])
def get_case(case_id: str) -> dict[str, Any]:
    """Case kèm tóm tắt các alert liên quan (tối đa 50 alert mới nhất) để mở từng alert."""
    case = _get(settings.IDX_CASES, case_id, "case")["_source"] | {"_id": case_id}
    ids = (case.get("alert_ids") or [])[-50:]
    case["alerts"] = [{"_id": a["_id"], "@timestamp": a.get("@timestamp"), "severity": a.get("severity"),
                       "rule": {k: (a.get("rule") or {}).get(k) for k in ("id", "name")},
                       "status": (a.get("alert") or {}).get("status")}
                      for a in store.search(es(), settings.IDX_ALERTS, {"terms": {"alert.id": ids}}, size=50)] if ids else []
    for t in case.get("tasks") or []:
        t["approval_permission"] = approval_permission(t)   # console khóa ô đánh dấu nếu tài khoản không đủ quyền
    return case


def _sla(case: dict[str, Any]) -> dict[str, Any]:
    """Hạn SLA của case; case tạo trước 13/10/2026 chỉ có sla_due (hạn triage)."""
    sla = dict(case.get("sla") or {})
    sla.setdefault("ack_due", case.get("sla_due"))
    sla.setdefault("contain_due", case.get("contain_due"))
    return sla


def _reprioritize(case: dict[str, Any], level: str, now: str) -> dict[str, Any]:
    """Đổi ưu tiên: nâng -> hạn chưa đạt kéo về sớm hơn (now + SLA mới, không lùi hạn); hạ -> hạn tính lại từ lúc tạo."""
    sla, changes = _sla(case), {"priority": level}
    if prio.higher(level, case.get("priority")):
        new = prio.policy().dues(now, level)
        for key, done in (("ack_due", "acknowledged_at"), ("contain_due", "contained_at")):
            if not case.get(done) and (not sla.get(key) or new[key] < sla[key]):
                sla[key] = new[key]
    else:
        sla.update(prio.policy().dues(case.get("created_at") or now, level))
    changes.update(sla=sla, sla_due=sla["ack_due"], contain_due=sla["contain_due"])
    return changes


# Đóng case -> đóng các alert còn mở của case (cùng kết luận), ghi vào lịch sử từng alert. Trước đây đóng case không
# đụng tới alert: 76 alert thử nghiệm còn "mở" dù case đã xử lý xong, KPI báo nhầm / MTTA không đo được.
CLOSE_CASE_ALERTS = """
def a = ctx._source.alert;
if (a != null && params.active.contains(a.status)) {
  a.status = params.status; a.verdict = params.verdict; a.closed_at = params.now; a.closed_by = params.by;
  a.updated_at = params.now; a.updated_by = params.by;
  if (a.acknowledged_at == null) { a.acknowledged_at = params.now; a.acknowledged_by = params.by; }
  if (a.history == null) { a.history = new ArrayList(); }
  a.history.add(['at': params.now, 'by': params.by, 'text': params.text]);
} else { ctx.op = 'noop'; }
"""


def close_case_alerts(case: dict[str, Any], case_id: str, status: str, verdict: str, who: str, now: str) -> int:
    ids = (case.get("alert_ids") or [])[-500:]
    if not ids:
        return 0
    try:
        r = es().update_by_query(index=settings.IDX_ALERTS, conflicts="proceed", refresh=True, query={"bool": {"filter": [
            {"terms": {"alert.id": ids}}, {"terms": {"alert.status": list(ACTIVE_ALERT_STATUSES)}}]}},
            script={"lang": "painless", "source": CLOSE_CASE_ALERTS, "params": {
                "active": list(ACTIVE_ALERT_STATUSES), "status": status, "verdict": verdict, "by": who, "now": now,
                "text": f"đóng theo case {case_id}: {VERDICTS[verdict]}"}})
        return int(r.get("updated", 0))
    except Exception as e:  # noqa: BLE001 - case đã đóng; alert còn mở thì analyst đóng tay, không được làm hỏng thao tác
        log.warning("không đóng được alert của case %s: %s", case_id, e)
        return -1


@app.patch("/api/v1/cases/{case_id}")
def update_case(case_id: str, body: CaseUpdate, s: Session = Depends(triage)) -> dict[str, Any]:
    """Cập nhật case: trạng thái (đóng phải có kết luận), ưu tiên, người xử lý, đánh dấu task playbook, ghi chú.
    Mọi thay đổi được ghi vào `notes` (lịch sử) kèm tài khoản thực hiện và thời điểm. Thao tác đầu tiên của người =
    xác nhận (acknowledged_at, KPI MTTA, SLA xác nhận); chuyển "Đã ngăn chặn" = khoanh vùng xong (KPI MTTC)."""
    cur = _get(settings.IDX_CASES, case_id, "case")
    case, now, who = cur["_source"], store.now_iso(), s.username
    changes: dict[str, Any] = {"updated_at": now}
    history: list[str] = []
    closed_as: tuple[str, str] | None = None
    if body.status and body.status != case.get("status"):
        status, verdict = closing(body.status, body.verdict, "case")
        if status in CLOSED_STATUSES and not body.note.strip():
            raise HTTPException(400, "đóng case phải ghi lý do / kết luận vào note")
        changes["status"] = status
        if status == "contained" and not case.get("contained_at"):
            changes["contained_at"] = now
        if status in CLOSED_STATUSES:
            changes.update(closed_at=now, closed_by=who, verdict=verdict)
            if verdict in ("true_positive", "benign_true_positive") and not case.get("contained_at"):
                changes["contained_at"] = now            # sự cố thật đã xử lý xong thì cũng đã khoanh vùng
            closed_as = (status, verdict)
        elif case.get("status") in CLOSED_STATUSES:     # mở lại case đã đóng
            changes.update(closed_at=None, closed_by=None, verdict=None)
        history.append(f"trạng thái: {case.get('status')} -> {status}" + (f" ({VERDICTS[verdict]})" if verdict else ""))
    if body.priority and body.priority != case.get("priority"):
        if not has(s.role, "contain"):
            raise HTTPException(403, "đổi ưu tiên case cần quyền contain (Trưởng nhóm IR)")
        if not body.note.strip():
            raise HTTPException(400, "đổi ưu tiên phải ghi lý do vào note")
        changes.update(_reprioritize(case, body.priority, now))
        history.append(f"ưu tiên: {case.get('priority')} -> {body.priority}")
    if body.assignee is not None and body.assignee != case.get("assignee"):
        changes["assignee"] = body.assignee or None
        history.append(f"giao cho: {body.assignee or '(bỏ giao)'}")
    if body.task_index is not None and body.task_done is not None:
        tasks = case.get("tasks") or []
        if body.task_index >= len(tasks):
            raise HTTPException(400, "task_index vượt quá số task")
        t = tasks[body.task_index]
        # task cần duyệt: chỉ người có thẩm quyền được đánh dấu / bỏ đánh dấu (trước đây analyst L1 tick được cả task
        # "cô lập máy, cần Trưởng nhóm IR duyệt": nhãn chỉ để hiển thị)
        need = approval_permission(t)
        if need and not has(s.role, need):
            raise HTTPException(403, f"task này cần {t['approval']} duyệt (quyền {need})")
        if body.task_done and need and OWNER_APPROVAL in t["approval"] and not body.note.strip():
            raise HTTPException(400, "task cần chủ hệ thống đồng ý: ghi vào note ai đã đồng ý và lúc nào")
        t.update(done=body.task_done, done_by=who if body.task_done else None,
                 done_at=now if body.task_done else None)
        changes["tasks"] = tasks
        history.append(f"{'hoàn thành' if body.task_done else 'bỏ đánh dấu'} task [{t['phase']}] {t['title']}"
                       + (f" (duyệt với vai trò {s.role}, task cần {t['approval']})" if need and body.task_done else ""))
    if body.note.strip():
        history.append(f"ghi chú: {body.note.strip()}")
    if not history:
        return case
    _timings(case, changes, now, who)
    changes["notes"] = (case.get("notes") or []) + [{"at": now, "by": who, "text": h} for h in history]
    try:
        es().update(index=settings.IDX_CASES, id=case_id, doc=changes, refresh="wait_for",
                    if_seq_no=cur["_seq_no"], if_primary_term=cur["_primary_term"])
    except Exception:  # noqa: BLE001 - người khác vừa sửa case
        raise HTTPException(409, "case vừa được người khác cập nhật, hãy tải lại")
    log.info("case %s cập nhật bởi %s: %s", case_id, who, "; ".join(history))
    out = case | changes
    if closed_as and body.close_alerts:
        out["alerts_closed"] = close_case_alerts(case, case_id, *closed_as, who, now)
    return out


def _timings(case: dict[str, Any], changes: dict[str, Any], now: str, who: str) -> None:
    """Mốc thời gian và SLA cho KPI (MTTA, MTTC, thời gian xử lý, tỉ lệ đạt SLA)."""
    merged = case | changes
    sla = dict(merged.get("sla") or _sla(case))
    metrics = dict(case.get("metrics") or {})
    if not case.get("acknowledged_at"):
        changes.update(acknowledged_at=now, acknowledged_by=who)
        metrics["tta_seconds"] = prio.seconds_between(case.get("created_at"), now)
        sla["ack_met"] = prio.met(now, sla.get("ack_due"))
    if changes.get("contained_at") and not case.get("contained_at"):
        metrics["ttc_seconds"] = prio.seconds_between(case.get("created_at"), changes["contained_at"])
        sla["contain_met"] = prio.met(changes["contained_at"], sla.get("contain_due"))
    if changes.get("closed_at"):
        metrics["ttr_seconds"] = prio.seconds_between(case.get("created_at"), changes["closed_at"])
    elif "closed_at" in changes:                        # mở lại
        metrics.pop("ttr_seconds", None)
    changes.update(metrics=metrics, sla=sla)


class IncidentAction(BaseModel):
    action: str = Field(pattern=r"^(declare|notified)$")
    personal_data: bool = False
    note: str = Field("", max_length=4000)


@app.post("/api/v1/cases/{case_id}/incident")
def case_incident(case_id: str, body: IncidentAction, s: Session = Depends(declare)) -> dict[str, Any]:
    """SOC Manager tuyên bố sự cố lớn (case thành P1, bắt đầu đếm hạn thông báo nếu lộ dữ liệu cá nhân) hoặc ghi nhận
    đã thông báo cơ quan chức năng / người bị ảnh hưởng."""
    cur = _get(settings.IDX_CASES, case_id, "case")
    case, now = cur["_source"], store.now_iso()
    note = body.note.strip()
    if len(note) < 3:
        raise HTTPException(400, "ghi rõ căn cứ tuyên bố / đã thông báo cho ai, lúc nào")
    inc = dict(case.get("incident") or {})
    if body.action == "declare":
        if inc.get("declared_at"):
            raise HTTPException(409, "case đã được tuyên bố là sự cố lớn")
        inc.update(declared_at=now, declared_by=s.username, personal_data=body.personal_data, note=note)
        if body.personal_data:
            start = case.get("created_at") or now
            inc["notify_due"] = (datetime.fromisoformat(start) + timedelta(hours=BREACH_NOTIFY_HOURS)).isoformat()
        changes: dict[str, Any] = {"incident": inc, "updated_at": now}
        if case.get("priority") != "P1":
            changes.update(_reprioritize(case, "P1", now))
        text = "tuyên bố sự cố lớn" + (" (có dữ liệu cá nhân, hạn thông báo 72 giờ)" if body.personal_data else "") + \
            f": {note}"
    else:
        if not inc.get("declared_at"):
            raise HTTPException(409, "case chưa được tuyên bố là sự cố lớn")
        inc.update(notified_at=now, notified_by=s.username, notified_note=note)
        changes = {"incident": inc, "updated_at": now}
        text = f"đã thông báo: {note}"
    changes["notes"] = (case.get("notes") or []) + [{"at": now, "by": s.username, "text": text}]
    try:
        es().update(index=settings.IDX_CASES, id=case_id, doc=changes, refresh="wait_for",
                    if_seq_no=cur["_seq_no"], if_primary_term=cur["_primary_term"])
    except Exception:  # noqa: BLE001
        raise HTTPException(409, "case vừa được người khác cập nhật, hãy tải lại")
    log.warning("case %s: %s (%s)", case_id, text, s.username)
    return case | changes


@app.get("/api/v1/stats")
def stats(s: Session = Depends(current_user)) -> dict[str, Any]:
    def count(index: str, query: dict | None = None) -> int:
        try:
            return es().count(index=index, query=query or {"match_all": {}})["count"]
        except Exception:  # noqa: BLE001
            return 0
    last24 = {"range": {"@timestamp": {"gte": "now-24h"}}}
    ag = store.list_agents(es())
    open_cases = {"terms": {"status": ["open", "in_progress", "contained"]}}
    # số yêu cầu đăng ký chờ duyệt: chỉ người có quyền quản lý tài khoản (người duyệt) cần, hiện trên menu Tài khoản
    pending = {"users_pending": sum(bool(u.get("pending")) for u in auth.users.list())} if has(s.role, "users") else {}
    return pending | {
        "events_24h": count(f"{settings.IDX_EVENTS}-*", last24),
        "alerts_24h": count(settings.IDX_ALERTS, {"bool": {"filter": [last24], "must_not": [NOT_SHADOW]}}),
        # cùng tập trạng thái với mục "Đang mở" của console (trước đây thiếu acknowledged: số trên menu nhỏ hơn danh sách)
        "alerts_open": count(settings.IDX_ALERTS, {"bool": {"filter": [
            {"terms": {"alert.status": list(ACTIVE_ALERT_STATUSES)}}], "must_not": [NOT_SHADOW]}}),
        "agents_total": len(ag),
        "agents_online": sum(a["status"] == "online" for a in ag),
        "actions_pending": count(settings.IDX_ACTIONS, {"terms": {"status": ["pending", "sent"]}}),
        "cases_open": count(settings.IDX_CASES, open_cases),
        # chưa ai nhận mà đã quá hạn xác nhận (SLA của mức ưu tiên)
        "cases_overdue": count(settings.IDX_CASES, {"bool": {"filter": [
            open_cases, {"range": {"sla_due": {"lt": "now"}}}], "must_not": [{"exists": {"field": "acknowledged_at"}}]}}),
        "ai_pending": count(settings.IDX_AI_PROPOSALS, {"term": {"status": "pending"}}),
    }


@app.get("/api/v1/kpi", dependencies=[Depends(current_user)])
def kpi_latest(fresh: bool = False) -> dict[str, Any]:
    """KPI mới nhất (fresh=true: tính lại ngay). Đích GĐ2 / GĐ4 và mức đạt nằm trong `targets` / `grade`."""
    doc = None if fresh else kpi.latest(es())
    return doc or compute_kpi()


ACTIVITY_FIELDS = ["@timestamp", "event.action", "event.category", "event.outcome", "event.reason", "user.name",
                   "user.target.name", "user.roles", "source.ip", "http.request.method", "url.path",
                   "http.response.status_code"]


@app.get("/api/v1/admin/activity")
def activity(user: str | None = Query(None, max_length=64),
             kind: str | None = Query(None, pattern="^(authentication|iam|configuration)$"),
             since: str = "7d", size: int = Query(200, ge=1, le=500),
             s: Session = Depends(require_perm("users"))) -> list[dict[str, Any]]:
    """Nhật ký của console (admin): đăng nhập / đăng xuất (authentication), tài khoản (iam), thao tác (configuration).
    `user`: việc người đó làm, và việc người khác làm trên tài khoản đó (vd admin khóa / duyệt)."""
    flt: list[dict[str, Any]] = [{"term": {"event.module": "console"}},
                                 {"range": {"@timestamp": {"gte": SINCE.get(since, "now-7d")}}}]
    if user:
        flt.append({"bool": {"should": [{"term": {"user.name": user}}, {"term": {"user.target.name": user}}],
                             "minimum_should_match": 1}})
    if kind:
        flt.append({"term": {"event.category": kind}})
    try:
        res = es().search(index=f"{settings.IDX_EVENTS}-*", size=size, query={"bool": {"filter": flt}},
                          sort=[{"@timestamp": "desc"}], source=ACTIVITY_FIELDS, ignore_unavailable=True)
    except NotFoundError:
        return []
    return [h["_source"] for h in res["hits"]["hits"]]


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
    if s.must_mfa:
        return RedirectResponse("/login?mfa=1&next=%2F", status_code=303)
    return FileResponse(STATIC / "console.html")


@app.get("/login", include_in_schema=False)
@app.get("/register", include_in_schema=False)          # trang đăng ký riêng: cùng file, login.html mở form theo đường dẫn
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


def _rule_modes() -> dict[str, Any]:
    from ..detection.rules import load_rules
    try:
        return {r.id: r for r in load_rules(settings.RULES_DIR)}
    except Exception as e:  # noqa: BLE001 - thư mục rule lỗi: danh sách đề xuất vẫn phải hiện
        log.warning("không đọc được rule: %s", e)
        return {}


@app.get("/api/v1/ai/proposals", dependencies=[Depends(current_user)])
def ai_proposals(status: str | None = None, size: int = 100) -> list[dict[str, Any]]:
    q = {"bool": {"filter": [{"term": {"status": status}}]}} if status else None
    rows = store.search(es(), settings.IDX_AI_PROPOSALS, q, size=min(size, 500), sort=[{"created_at": "desc"}])
    modes = _rule_modes() if any(r.get("status") == "approved" and r.get("kind") == "new_rule" for r in rows) else {}
    out = []
    for r in rows:
        # nhãn để mở phần "So sánh với rule hiện có" của dashboard Thư viện rule đúng đề xuất này
        r = r | {"catalog_pick": rules_catalog.pick(r | {"id": r.get("id") or r["_id"]})}
        rule = modes.get(str((r.get("proposal") or {}).get("id"))) if r.get("status") == "approved" else None
        if rule is not None:
            r["rule_mode"] = rule.mode
            if rule.mode == "shadow":
                st = ai_deploy.shadow_stats(es(), rule.id, rule.shadow_since)
                r["shadow"] = st | {"problems": ai_deploy.promotion_problems(st)}
        out.append(r)
    return out


@app.get("/api/v1/rules/{rule_id}/shadow", dependencies=[Depends(current_user)])
def rule_shadow(rule_id: str) -> dict[str, Any]:
    """Số liệu chạy bóng của một rule và các tiêu chí còn thiếu để bật chính thức."""
    rule = _rule_modes().get(rule_id)
    if not rule:
        raise HTTPException(404, "không có rule này")
    st = ai_deploy.shadow_stats(es(), rule.id, rule.shadow_since) if rule.mode == "shadow" else None
    return {"rule_id": rule.id, "mode": rule.mode, "stats": st,
            "problems": ai_deploy.promotion_problems(st) if st else []}


@app.post("/api/v1/rules/{rule_id}/promote")
def rule_promote(rule_id: str, s: Session = Depends(rules_perm)) -> dict[str, Any]:
    """Bật chính thức rule AI đang chạy bóng (Detection Engineer). Rule viết tay đổi `mode` qua kho rule + CI."""
    return _ai(ai_deploy.promote, es(), rule_id, s.username, settings.RULES_DIR, now=store.now_iso())


@app.post("/api/v1/ai/proposals/{pid}/approve")
def ai_approve(pid: str, s: Session = Depends(rules_perm)) -> dict[str, Any]:
    # Detection Engineer duyệt (quyền rules): người xử lý cảnh báo không tự duyệt rule mình dùng. Ngoại lệ cần 2 người
    # KHÁC NHAU duyệt: danh tính lấy từ phiên nên không giả được bằng cách đổi tên
    return _ai(ai_deploy.approve, es(), pid, s.username, settings.RULES_DIR, now=store.now_iso())


@app.post("/api/v1/ai/proposals/{pid}/reject")
def ai_reject(pid: str, body: AIDecision, s: Session = Depends(rules_perm)) -> dict[str, Any]:
    if len(body.reason.strip()) < 3:
        raise HTTPException(400, "từ chối phải ghi lý do (AI dùng lý do này để không lặp lại lỗi)")
    return _ai(ai_deploy.reject, es(), pid, s.username, body.reason.strip(), now=store.now_iso())


@app.post("/api/v1/ai/proposals/{pid}/rollback")
def ai_rollback(pid: str, body: AIDecision, s: Session = Depends(rules_perm)) -> dict[str, Any]:
    if len(body.reason.strip()) < 3:
        raise HTTPException(400, "gỡ phải ghi lý do")
    return _ai(ai_deploy.rollback, es(), pid, s.username, body.reason.strip(), settings.RULES_DIR, now=store.now_iso())


@app.post("/api/v1/ai/run")
def ai_run(s: Session = Depends(rules_perm)) -> dict[str, Any]:
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


app.include_router(soc.router)            # threat hunting, giao ca, AI hỗ trợ analyst
# Route bắt-tất-cả /grafana/{path} phải đăng ký SAU mọi route của app (vd /grafana/go/...), FastAPI khớp theo thứ tự
app.include_router(grafana_proxy.router)
