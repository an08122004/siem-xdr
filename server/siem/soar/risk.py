"""Risk-based alerting (RBA, SOC-OPERATIONS.md mục 4): cộng dồn điểm rủi ro theo THỰC THỂ thay vì xét từng alert.

Mỗi alert (trừ alert chạy bóng, alert RBA / sức khỏe nền tảng) cộng `risk_score` của nó (severity × mức quan trọng tài
sản, detection/alerts.py) vào máy (host.name) và tài khoản (user.name) liên quan trong cửa sổ RBA_WINDOW_HOURS giờ. Khi
tổng điểm ≥ RBA_THRESHOLD và đến từ ≥ RBA_MIN_RULES rule KHÁC NHAU, SOAR sinh alert RBA-001 gom mọi alert góp điểm (mức
high; critical khi gấp đôi ngưỡng). Vượt tiếp mỗi bội số của ngưỡng thì bắn lại để nâng mức.

Ý nghĩa: rule mức low (không mở case, không thông báo) dùng được làm tín hiệu săn tìm (tạo tài khoản, tạo dịch vụ, dò
tài khoản domain...): từng cái không đáng mở case, nhiều cái khác loại trên cùng một máy trong một ngày thì đáng. Trước
13/10/2026 5 alert medium khác nhau trên một máy vẫn chỉ là 5 alert rời (RULES.md mục 6)."""
from __future__ import annotations

import logging
import time
from collections import Counter, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from .. import priority as prio
from .. import settings, store
from ..detection.rules import SEVERITY_SCORE
from ..pipeline.normalize import get

log = logging.getLogger("soar.risk")

RULE_ID = "RBA-001"
SKIP_SOURCES = ("rba", "health")
IGNORE_VALUES = {"", "-", "?", "unknown", "n/a", "none", "soc-console"}
_CRIT = ("low", "medium", "high", "critical")


@dataclass
class Contribution:
    at: float
    alert_id: str
    rule_id: str
    rule_name: str
    score: float
    techniques: tuple[str, ...]
    tactic: str | None
    criticality: str | None
    agent_id: str | None


def _ts(alert: dict[str, Any]) -> float:
    try:
        return datetime.fromisoformat(str(alert.get("@timestamp")).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return time.time()


def eligible(alert: dict[str, Any]) -> bool:
    return not (get(alert, "alert.shadow") or get(alert, "alert.source") in SKIP_SOURCES
                or str(get(alert, "rule.id", "")).startswith(("RBA-", "HLT-")))


class RiskTracker:
    def __init__(self, threshold: float = 150, min_rules: int = 2, window_hours: float = 24,
                 fields: Iterable[str] = ("host.name", "user.name"), clock=time.time):
        self.threshold, self.min_rules = float(threshold), int(min_rules)
        self.window = float(window_hours) * 3600
        self.fields = tuple(fields)
        self.clock = clock
        self.entries: dict[tuple[str, str], deque[Contribution]] = {}
        self.fired: dict[tuple[str, str], int] = {}       # thực thể -> bội số ngưỡng đã báo
        self.seen: set[str] = set()

    # ------------------------------------------------------------------
    def entities(self, alert: dict[str, Any]) -> list[tuple[str, str]]:
        out = []
        for f in self.fields:
            v = get(alert, f) or (get(alert, "agent.id") if f == "host.name" else None)
            if v is not None and str(v).strip().lower() not in IGNORE_VALUES:
                out.append((f, str(v)))
        return out

    def _prune(self, key: tuple[str, str], now: float) -> deque[Contribution]:
        q = self.entries.setdefault(key, deque())
        while q and q[0].at < now - self.window:
            q.popleft()
        if not q:
            self.entries.pop(key, None)
            self.fired.pop(key, None)
            return deque()
        return q

    def add(self, alert: dict[str, Any], fire: bool = True) -> list[dict[str, Any]]:
        """Cộng điểm của alert; trả về các alert RBA cần phát (rỗng nếu chưa vượt ngưỡng)."""
        aid = str(get(alert, "alert.id") or "")
        if not eligible(alert) or not aid or aid in self.seen:
            return []                                   # Kafka giao lại sau khi SOAR khởi động lại: không cộng 2 lần
        self.seen.add(aid)
        if len(self.seen) > 200_000:
            self.seen = {c.alert_id for q in self.entries.values() for c in q}
        now = self.clock()
        tech = get(alert, "rule.mitre.technique") or []
        c = Contribution(_ts(alert), aid, str(get(alert, "rule.id")), str(get(alert, "rule.name") or ""),
                         float(alert.get("risk_score") or SEVERITY_SCORE.get(str(alert.get("severity")), 1) * 25),
                         tuple(tech if isinstance(tech, list) else [tech]), get(alert, "rule.mitre.tactic"),
                         get(alert, "asset.criticality"), get(alert, "agent.id"))
        if c.at < now - self.window:
            return []
        out = []
        for key in self.entities(alert):
            q = self.entries.setdefault(key, deque())
            q.append(c)
            q = self._prune(key, now)
            total = sum(x.score for x in q)
            level = int(total // self.threshold)
            rules = {x.rule_id for x in q}
            if level < 1:
                self.fired.pop(key, None)
            elif len(rules) >= self.min_rules and level > self.fired.get(key, 0):
                self.fired[key] = level
                if fire:
                    out.append(self.build(key, list(q), total, level))
        return out

    def build(self, key: tuple[str, str], items: list[Contribution], total: float, level: int) -> dict[str, Any]:
        field, value = key
        severity = "critical" if level >= 2 else "high"
        crit = max((x.criticality for x in items if x.criticality in _CRIT), key=_CRIT.index, default=None)
        techs = list(dict.fromkeys(t for x in items for t in x.techniques))
        tactic = Counter(x.tactic for x in items if x.tactic).most_common(1)
        rules = Counter(x.rule_id for x in items)
        first = min(x.at for x in items)
        now = store.now_iso()
        what = "máy" if field == "host.name" else "tài khoản"
        alert: dict[str, Any] = {
            "@timestamp": now,
            "alert": {"id": store.new_id(), "status": "open", "source": "rba"},
            "rule": {"id": RULE_ID, "name": f"Rủi ro tích lũy vượt ngưỡng trên {what} {value}",
                     "description": f"{len(items)} alert từ {len(rules)} rule khác nhau trong "
                                    f"{self.window / 3600:g} giờ, tổng điểm {total:g} (ngưỡng {self.threshold:g})",
                     "type": "rba", "severity": severity, "tags": ["rba", "correlation"],
                     "mitre": {"tactic": tactic[0][0] if tactic else None, "technique": techs[:20]}},
            "severity": severity, "severity_score": SEVERITY_SCORE[severity],
            "risk_score": min(100.0, round(total, 1)),
            "risk": {"total": round(total, 1), "threshold": self.threshold, "level": level,
                     "entity": {"field": field, "value": value}, "rules": dict(rules),
                     "window_hours": self.window / 3600},
            "contributions": [{"alert_id": x.alert_id, "rule_id": x.rule_id, "rule_name": x.rule_name,
                               "score": x.score, "at": datetime.fromtimestamp(x.at, timezone.utc).isoformat()}
                              for x in items][-100:],
            "related_alerts": [x.alert_id for x in items][-100:],
            "count": len(items),
            "first_event_time": datetime.fromtimestamp(first, timezone.utc).isoformat(),
        }
        if field == "host.name":
            alert["host"] = {"name": value}
            agent = next((x.agent_id for x in reversed(items) if x.agent_id), None)
            if agent:
                alert["agent"] = {"id": agent}
        else:
            alert["user"] = {"name": value}
        if crit:
            alert["asset"] = {"criticality": crit}
        alert["priority"] = prio.policy().priority(severity, crit)
        alert["metrics"] = {"ttd_seconds": prio.seconds_between(alert["first_event_time"], now)}
        alert["message"] = (f"[{severity.upper()}] {alert['rule']['name']} | {len(items)} alert, "
                            f"{len(rules)} rule | tổng điểm {total:g}")
        return alert

    # ------------------------------------------------------------------
    def load(self, es) -> int:
        """Khởi động lại SOAR: dựng lại cửa sổ từ alert trong RBA_WINDOW_HOURS giờ qua (không bắn lại), và mức đã báo
        từ các alert RBA đã sinh, để không báo trùng."""
        since = (datetime.now(timezone.utc) - timedelta(seconds=self.window)).isoformat()
        rows = store.search(es, settings.IDX_ALERTS, {"bool": {"filter": [{"range": {"@timestamp": {"gte": since}}}]}},
                            size=10000, sort=[{"@timestamp": {"order": "asc", "unmapped_type": "date"}}])
        n = 0
        for a in rows:
            if get(a, "rule.id") == RULE_ID:
                key = (str(get(a, "risk.entity.field")), str(get(a, "risk.entity.value")))
                self.fired[key] = max(self.fired.get(key, 0), int(get(a, "risk.level") or 1))
            elif eligible(a):
                self.add(a, fire=False)
                n += 1
        log.info("RBA: dựng lại %d alert trong %g giờ qua, %d thực thể", n, self.window / 3600, len(self.entries))
        return n


def from_settings() -> RiskTracker:
    return RiskTracker(settings.RBA_THRESHOLD, settings.RBA_MIN_RULES, settings.RBA_WINDOW_HOURS,
                       settings.RBA_ENTITY_FIELDS)
