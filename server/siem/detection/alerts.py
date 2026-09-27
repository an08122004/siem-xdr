"""Dựng alert document chuẩn từ kết quả rule engine / ML."""
from __future__ import annotations

from typing import Any

from ..pipeline.normalize import Doc, get
from ..store import new_id, now_iso
from .rules import SEVERITY_SCORE, Detection

# Các trường thực thể (entity) được sao chép từ event kích hoạt lên alert,
# để SOAR/analyst biết "ai / máy nào / IP nào" mà không cần mở event gốc.
ENTITY_FIELDS = [
    "agent.id", "agent.hostname", "host.name", "source.ip", "source.port", "destination.ip",
    "destination.port", "user.name", "process.pid", "process.name", "process.command_line",
    "url.original", "asset.id", "asset.criticality", "threat.indicator.value", "event.module",
]

_CRIT_MULT = {"low": 0.8, "medium": 1.0, "high": 1.3, "critical": 1.6}


def _copy_entities(src: Doc, dst: Doc) -> None:
    for path in ENTITY_FIELDS:
        v = get(src, path)
        if v is None:
            continue
        cur = dst
        parts = path.split(".")
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        cur[parts[-1]] = v


def _risk(severity: str, event: Doc) -> float:
    base = SEVERITY_SCORE[severity] * 25
    mult = _CRIT_MULT.get(str(get(event, "asset.criticality", "medium")), 1.0)
    if get(event, "threat.matched"):
        mult += 0.2
    return round(min(100.0, base * mult), 1)


def _trigger(event: Doc) -> Doc:
    return {k: v for k, v in event.items() if k != "raw"}


def from_detection(d: Detection) -> Doc:
    r = d.rule
    alert: Doc = {
        "@timestamp": now_iso(),
        "alert": {"id": new_id(), "status": "open", "source": "rule"},
        "rule": {
            "id": r.id, "name": r.title, "description": r.description, "type": r.type,
            "severity": r.severity, "tags": r.tags,
            "mitre": {"tactic": r.mitre.get("tactic"), "technique": r.mitre.get("technique")},
        },
        "severity": r.severity,
        "severity_score": SEVERITY_SCORE[r.severity],
        "risk_score": _risk(r.severity, d.event),
        "group": {k.replace(".", "_"): v for k, v in d.group.items()},
        "count": d.count,
        "related_events": d.related,
        "event_time": d.event.get("@timestamp"),
        "trigger_event": _trigger(d.event),
    }
    _copy_entities(d.event, alert)
    alert["message"] = _message(alert)
    return alert


def from_anomaly(a: Any, severity: str, description: str, features: dict[str, Any]) -> Doc:
    alert: Doc = {
        "@timestamp": now_iso(),
        "alert": {"id": new_id(), "status": "open", "source": "ml"},
        "rule": {
            "id": "ML-001", "name": "Hành vi bất thường của IP nguồn (Isolation Forest)",
            "description": f"Điểm bất thường {a.score:.3f}. Đặc trưng nổi bật: {description}",
            "type": "ml", "severity": severity, "tags": ["ml", "anomaly"],
            "mitre": {"tactic": "Discovery", "technique": []},
        },
        "severity": severity,
        "severity_score": SEVERITY_SCORE[severity],
        "risk_score": _risk(severity, a.event),
        "ml": {"score": round(a.score, 4), "features": features},
        "count": int(features.get("n_events", 0)),
        "related_events": a.event_ids,
        "event_time": a.event.get("@timestamp"),
        "trigger_event": _trigger(a.event),
    }
    _copy_entities(a.event, alert)
    alert.setdefault("source", {})["ip"] = a.ip
    alert["message"] = _message(alert)
    return alert


def _message(alert: Doc) -> str:
    who = get(alert, "source.ip") or get(alert, "user.name") or get(alert, "process.name") or "?"
    where = get(alert, "host.name") or get(alert, "agent.id") or "?"
    return f"[{alert['severity'].upper()}] {alert['rule']['name']} | nguồn={who} | host={where} | count={alert['count']}"
