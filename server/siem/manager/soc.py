"""Quy trình vận hành SOC ngoài alert / case (SOC-OPERATIONS.md):

  /api/v1/hunts       nhật ký threat hunting theo PEAK: giả thuyết gắn kỹ thuật ATT&CK -> truy vấn -> kết luận, rule mới
                      nếu tìm được mẫu, dữ liệu còn thiếu (index siem-hunts; KPI "hunt hoàn thành / tháng")
  /api/v1/handover    biên bản giao ca: alert đang mở theo ưu tiên, case đang xử lý, case quá hạn, lệnh chặn sắp hết
                      hạn, bước SOAR chờ duyệt, sự cố nền tảng, sự cố lớn; lưu lại bản đã giao (siem-handovers)
  /api/v1/ai/assist   gửi việc cho AI hỗ trợ (tóm tắt, giải thích lệnh, nháp báo cáo, câu hỏi -> truy vấn; ai/triage.py),
                      đánh giá hữu ích / không (KPI tỉ lệ chấp nhận)
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from elasticsearch import NotFoundError
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .. import settings, store
from .auth import Session, current_user, has, require_perm

log = logging.getLogger("manager.soc")
router = APIRouter()
_es_getter: list[Any] = []

IDX_HUNTS, IDX_HANDOVERS = "siem-hunts", "siem-handovers"
TECH = re.compile(r"^T\d{4}(\.\d{3})?$")
HUNT_STATUSES = ("planned", "in_progress", "completed", "cancelled")
OUTCOMES = {"found_threat": "Tìm thấy mối đe dọa", "no_threat": "Không thấy dấu hiệu", "inconclusive": "Chưa kết luận được"}
# Giả thuyết mở đầu của kế hoạch SOC (mục Threat hunting)
STARTERS = [
    {"title": "Kerberoasting trên Domain Controller", "techniques": ["T1558.003"],
     "hypothesis": "Kẻ tấn công đã có tài khoản domain xin vé TGS mã hóa RC4 cho tài khoản dịch vụ để bẻ mật khẩu offline.",
     "data_sources": ["Windows Security 4769 trên DC"], "queries": "winlog.event_id:4769 AND winlog.event_data.TicketEncryptionType:0x17"},
    {"title": "Persistence bằng tác vụ hẹn giờ trên server", "techniques": ["T1053.005", "T1053.003"],
     "hypothesis": "Tác vụ hẹn giờ mới chạy script / LOLBin từ thư mục người dùng ghi được trên server.",
     "data_sources": ["Sysmon EID 1", "Security 4698", "auditd / cron"],
     "queries": "process.name:schtasks.exe AND process.command_line:*create*"},
    {"title": "DNS tunneling", "techniques": ["T1071.004", "T1048"],
     "hypothesis": "Máy nội bộ gửi nhiều truy vấn DNS có nhãn con dài, entropy cao tới một tên miền ít gặp.",
     "data_sources": ["DNS resolver log"], "queries": "_exists_:dns.question.name"},
    {"title": "Cặp tiến trình cha - con hiếm gặp", "techniques": ["T1059"],
     "hypothesis": "Ứng dụng văn phòng / web server / dịch vụ sinh trình thông dịch lệnh, hiếm gặp trong 30 ngày.",
     "data_sources": ["Sysmon EID 1", "siem-procs / auditd"], "queries": "event.category:process AND _exists_:process.parent.name"},
    {"title": "Tài khoản dịch vụ đăng nhập tương tác", "techniques": ["T1078.002"],
     "hypothesis": "Tài khoản dịch vụ (svc-*) đăng nhập kiểu tương tác / RDP (logon type 2, 10) — dấu hiệu bị chiếm.",
     "data_sources": ["Windows Security 4624"], "queries": "event.code:4624 AND user.name:svc* AND winlog.logon.type:(2 OR 10)"},
]


def setup(getter) -> None:
    """getter: hàm trả về client Elasticsearch đang dùng của manager (api.es)."""
    _es_getter[:] = [getter]


def es():
    return _es_getter[0]()


def _techniques(v: list[str]) -> list[str]:
    out = [str(t).strip().upper() for t in v]
    if bad := [t for t in out if not TECH.match(t)]:
        raise HTTPException(400, f"mã kỹ thuật ATT&CK không hợp lệ: {', '.join(bad)}")
    return out


# ------------------------------------------------------------------ threat hunting
class HuntNew(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    hypothesis: str = Field(min_length=10, max_length=2000)
    techniques: list[str] = Field(default_factory=list, max_length=10)
    data_sources: list[str] = Field(default_factory=list, max_length=10)
    queries: str = Field("", max_length=4000)


class HuntUpdate(BaseModel):
    status: str | None = Field(None, pattern="^(" + "|".join(HUNT_STATUSES) + ")$")
    queries: str | None = Field(None, max_length=4000)
    findings: str | None = Field(None, max_length=8000)
    outcome: str | None = Field(None, pattern="^(" + "|".join(OUTCOMES) + ")$")
    new_rules: list[str] | None = Field(None, max_length=20)
    data_gaps: list[str] | None = Field(None, max_length=20)
    note: str = Field("", max_length=4000)


@router.get("/api/v1/hunts", dependencies=[Depends(current_user)])
def hunts(status: str | None = None, size: int = 200) -> list[dict[str, Any]]:
    q = {"bool": {"filter": [{"terms": {"status": status.split(",")}}]}} if status else None
    return store.search(es(), IDX_HUNTS, q, size=min(max(size, 1), 500), sort=[{"created_at": {"order": "desc",
                                                                                             "unmapped_type": "date"}}])


@router.get("/api/v1/hunts/starters", dependencies=[Depends(current_user)])
def hunt_starters() -> list[dict[str, Any]]:
    return STARTERS


@router.post("/api/v1/hunts")
def hunt_create(body: HuntNew, s: Session = Depends(require_perm("hunt"))) -> dict[str, Any]:
    now, hid = store.now_iso(), store.new_id()
    doc = {"id": hid, "title": body.title.strip(), "hypothesis": body.hypothesis.strip(),
           "techniques": _techniques(body.techniques), "data_sources": [x.strip() for x in body.data_sources if x.strip()],
           "queries": body.queries, "status": "planned", "owner": s.username, "created_at": now, "updated_at": now,
           "@timestamp": now, "findings": None, "outcome": None, "new_rules": [], "data_gaps": [],
           "notes": [{"at": now, "by": s.username, "text": "tạo giả thuyết"}]}
    es().index(index=IDX_HUNTS, id=hid, document=doc, refresh="wait_for")
    return doc


@router.patch("/api/v1/hunts/{hunt_id}")
def hunt_update(hunt_id: str, body: HuntUpdate, s: Session = Depends(require_perm("hunt"))) -> dict[str, Any]:
    try:
        cur = es().get(index=IDX_HUNTS, id=hunt_id)
    except NotFoundError:
        raise HTTPException(404, "không tìm thấy cuộc hunt")
    h, now = cur["_source"], store.now_iso()
    changes: dict[str, Any] = {"updated_at": now}
    history = []
    for key in ("queries", "findings", "outcome"):
        v = getattr(body, key)
        if v is not None and v != h.get(key):
            changes[key] = v
            history.append(f"cập nhật {key}" if key != "outcome" else f"kết luận: {OUTCOMES[v]}")
    for key in ("new_rules", "data_gaps"):
        v = getattr(body, key)
        if v is not None:
            changes[key] = [x.strip() for x in v if x.strip()]
            history.append(f"cập nhật {key}")
    if body.status and body.status != h.get("status"):
        if body.status == "completed":
            merged = h | changes
            if len(str(merged.get("findings") or "").strip()) < 10 or not merged.get("outcome"):
                raise HTTPException(400, "hoàn thành cuộc hunt phải có phát hiện (findings) và kết luận (outcome)")
            changes["completed_at"] = now
        changes["status"] = body.status
        history.append(f"trạng thái: {h.get('status')} -> {body.status}")
    if body.note.strip():
        history.append(f"ghi chú: {body.note.strip()}")
    if not history:
        return h
    changes["notes"] = (h.get("notes") or []) + [{"at": now, "by": s.username, "text": t} for t in history]
    try:
        es().update(index=IDX_HUNTS, id=hunt_id, doc=changes, refresh="wait_for",
                    if_seq_no=cur["_seq_no"], if_primary_term=cur["_primary_term"])
    except Exception:  # noqa: BLE001
        raise HTTPException(409, "cuộc hunt vừa được người khác cập nhật, hãy tải lại")
    return h | changes


# ------------------------------------------------------------------ giao ca
ACTIVE_ALERT = ["open", "acknowledged", "in_progress"]
ACTIVE_CASE = ["open", "in_progress", "contained"]


def handover_summary(hours_ahead: int = 12) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    soon = (now + timedelta(hours=hours_ahead)).isoformat()
    not_shadow = [{"term": {"alert.shadow": True}}]
    alerts = store.search(es(), settings.IDX_ALERTS, {"bool": {"filter": [{"terms": {"alert.status": ACTIVE_ALERT}}],
                                                              "must_not": not_shadow}}, size=500)
    by_p: dict[str, int] = {}
    for a in alerts:
        by_p[a.get("priority") or "—"] = by_p.get(a.get("priority") or "—", 0) + 1
    cases = store.search(es(), settings.IDX_CASES, {"terms": {"status": ACTIVE_CASE}}, size=200,
                         sort=[{"priority": {"order": "asc", "unmapped_type": "keyword"}}, {"created_at": "asc"}])
    case_rows = [{k: c.get(k) for k in ("_id", "title", "priority", "status", "assignee", "entity", "sla_due",
                                        "acknowledged_at", "contained_at")} | {"overdue": bool(
                     not c.get("acknowledged_at") and c.get("sla_due") and c["sla_due"] < now.isoformat()),
                     "major": bool((c.get("incident") or {}).get("declared_at"))} for c in cases]
    blocks = store.search(es(), settings.IDX_ACTIONS, {"bool": {"filter": [
        {"term": {"type": "block_ip"}}, {"term": {"status": "success"}}, {"term": {"reverted": False}},
        {"range": {"expires_at": {"gte": now.isoformat(), "lte": soon}}}]}}, size=100, sort=[{"expires_at": "asc"}])
    waiting = [a for a in alerts if any(r.get("status") == "awaiting_approval" for r in (a.get("soar") or {}).get("results") or [])]
    platform = [a for a in alerts if (a.get("alert") or {}).get("source") == "health"]
    top = sorted((a for a in alerts if a.get("priority") in ("P1", "P2")),
                 key=lambda a: (a.get("priority"), a.get("@timestamp") or ""))[:20]
    pick = lambda a: {"_id": a.get("_id"), "@timestamp": a.get("@timestamp"), "priority": a.get("priority"),   # noqa: E731
                      "rule": (a.get("rule") or {}).get("name"), "status": (a.get("alert") or {}).get("status"),
                      "host": (a.get("host") or {}).get("name"), "source_ip": (a.get("source") or {}).get("ip")}
    return {"generated_at": now.isoformat(), "alerts_open": len(alerts), "alerts_by_priority": dict(sorted(by_p.items())),
            "alerts_top": [pick(a) for a in top], "cases": case_rows,
            "cases_overdue": sum(c["overdue"] for c in case_rows), "major_incidents": [c for c in case_rows if c["major"]],
            "blocks_expiring": [{k: b.get(k) for k in ("agent_id", "target", "expires_at", "alert_id")} for b in blocks],
            "awaiting_approval": [pick(a) for a in waiting][:20], "platform_incidents": [pick(a) for a in platform]}


class HandoverNew(BaseModel):
    note: str = Field("", max_length=4000)
    to: str | None = Field(None, max_length=64)


@router.get("/api/v1/handover", dependencies=[Depends(current_user)])
def handover() -> dict[str, Any]:
    return handover_summary()


@router.post("/api/v1/handover")
def handover_save(body: HandoverNew, s: Session = Depends(require_perm("triage"))) -> dict[str, Any]:
    doc = handover_summary() | {"by": s.username, "to": body.to, "note": body.note.strip(), "@timestamp": store.now_iso()}
    hid = store.new_id()
    es().index(index=IDX_HANDOVERS, id=hid, document=doc, refresh="wait_for")
    return doc | {"_id": hid}


@router.get("/api/v1/handovers", dependencies=[Depends(current_user)])
def handovers(size: int = 20) -> list[dict[str, Any]]:
    return store.search(es(), IDX_HANDOVERS, None, size=min(max(size, 1), 100))


# ------------------------------------------------------------------ AI hỗ trợ analyst
class AssistNew(BaseModel):
    task: str = Field(pattern="^(summary|explain|report|query)$")
    target_type: str | None = Field(None, pattern="^(alert|case)$")
    target_id: str | None = Field(None, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    text: str | None = Field(None, max_length=4000)


class AssistFeedback(BaseModel):
    useful: bool
    note: str = Field("", max_length=1000)


def _assist_user(s: Session = Depends(current_user)) -> Session:
    if not any(has(s.role, p) for p in ("triage", "hunt", "rules")):
        raise HTTPException(403, "vai trò của bạn không dùng được AI hỗ trợ")
    return s


@router.post("/api/v1/ai/assist")
def assist(body: AssistNew, s: Session = Depends(_assist_user)) -> dict[str, Any]:
    if body.task in ("summary", "report") and not (body.target_type and body.target_id):
        raise HTTPException(400, "tóm tắt / báo cáo cần chọn alert hoặc case")
    if body.task == "report" and body.target_type != "case":
        raise HTTPException(400, "nháp báo cáo sau sự cố chỉ làm cho case")
    if body.task in ("explain", "query") and not (body.text or (body.task == "explain" and body.target_type == "alert")):
        raise HTTPException(400, "cần nội dung (dòng lệnh / câu hỏi)")
    job = {"kind": "triage", "task": body.task, "status": "pending", "requested_by": s.username,
           "created_at": store.now_iso(), "target": {"type": body.target_type, "id": body.target_id, "text": body.text},
           "label": "AI - bản tham khảo, cần người kiểm tra"}
    r = es().index(index=settings.IDX_AI_JOBS, document=job, refresh="wait_for")
    return job | {"_id": r["_id"]}


@router.get("/api/v1/ai/assist", dependencies=[Depends(current_user)])
def assist_list(target_type: str | None = None, target_id: str | None = None, size: int = 10) -> list[dict[str, Any]]:
    flt: list[dict[str, Any]] = [{"term": {"kind": "triage"}}]
    if target_type and target_id:
        flt += [{"term": {"target.type": target_type}}, {"term": {"target.id": target_id}}]
    return store.search(es(), settings.IDX_AI_JOBS, {"bool": {"filter": flt}}, size=min(max(size, 1), 50),
                        sort=[{"created_at": {"order": "desc", "unmapped_type": "date"}}])


@router.get("/api/v1/ai/assist/{job_id}", dependencies=[Depends(current_user)])
def assist_get(job_id: str) -> dict[str, Any]:
    try:
        r = es().get(index=settings.IDX_AI_JOBS, id=job_id)
    except NotFoundError:
        raise HTTPException(404, "không tìm thấy việc AI")
    if r["_source"].get("kind") != "triage":
        raise HTTPException(404, "không tìm thấy việc AI")
    return r["_source"] | {"_id": job_id}


@router.post("/api/v1/ai/assist/{job_id}/feedback")
def assist_feedback(job_id: str, body: AssistFeedback, s: Session = Depends(_assist_user)) -> dict[str, Any]:
    job = assist_get(job_id)
    if job.get("status") != "done":
        raise HTTPException(409, "việc AI chưa xong")
    fb = {"useful": body.useful, "by": s.username, "at": store.now_iso(), "note": body.note.strip()}
    es().update(index=settings.IDX_AI_JOBS, id=job_id, doc={"feedback": fb}, refresh="wait_for")
    return job | {"feedback": fb}
