"""Nguồn dữ liệu cho AI worker — lấy từ Elasticsearch bằng tài khoản siem_ai (CHỈ ĐỌC siem-*).

Nhãn thật đến từ quy trình case của analyst (không do AI tự sinh):
  - mẫu ÂM (false positive): alert có alert.status=false_positive + alert thuộc case đóng dạng false_positive
  - mẫu DƯƠNG (sự cố thật):  alert thuộc case đã xác nhận thật (contained / closed có kết luận)
    kèm các event liên quan (related_events) — ngoại lệ đề xuất KHÔNG được khớp bất kỳ event nào trong số này.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from .. import settings
from ..pipeline.normalize import Doc, get

log = logging.getLogger("ai.dataset")

REAL_CASE_STATUSES = ["contained", "closed"]


@dataclass
class RuleEvidence:
    fp: list[Doc] = field(default_factory=list)          # trigger event của alert báo nhầm
    tp: list[Doc] = field(default_factory=list)          # trigger + related event của alert sự cố thật
    fp_alert_ids: list[str] = field(default_factory=list)
    tp_alert_ids: list[str] = field(default_factory=list)


class ESDataSource:
    def __init__(self, es, lookback_days: int = settings.AI_LOOKBACK_DAYS,
                 replay_days: int = settings.AI_REPLAY_DAYS, max_events: int = settings.AI_REPLAY_MAX_EVENTS):
        self.es = es
        self.lookback = f"now-{lookback_days}d"
        self.replay_from = f"now-{replay_days}d"
        self.max_events = max_events
        self._events: list[Doc] | None = None

    # ------------------------------------------------------------ nhãn
    def _search(self, index: str, query: dict, size: int = 1000, source: Any = True, sort=None) -> list[dict]:
        try:
            res = self.es.search(index=index, query=query, size=size, _source=source, sort=sort)
        except Exception as e:  # noqa: BLE001 - index chưa tồn tại
            log.debug("search %s lỗi: %s", index, e)
            return []
        return res["hits"]["hits"]

    def evidence(self) -> dict[str, RuleEvidence]:
        since = {"range": {"@timestamp": {"gte": self.lookback}}}
        fp_ids = {h["_id"] for h in self._search(settings.IDX_ALERTS, {"bool": {"filter": [
            since, {"term": {"alert.status": "false_positive"}}]}}, source=False)}
        cases = self._search(settings.IDX_CASES, {"bool": {"filter": [
            since, {"terms": {"status": ["false_positive", *REAL_CASE_STATUSES]}}]}},
            source=["status", "alert_ids"])
        tp_ids: set[str] = set()
        for c in cases:
            ids = set(c["_source"].get("alert_ids") or [])
            (fp_ids if c["_source"]["status"] == "false_positive" else tp_ids).update(ids)
        tp_ids -= fp_ids  # analyst đã đánh dấu báo nhầm thì không coi là dương
        all_ids = list(fp_ids | tp_ids)
        if not all_ids:
            return {}
        alerts = self._search(settings.IDX_ALERTS, {"ids": {"values": all_ids[:5000]}}, size=5000,
                              source=["rule.id", "trigger_event", "related_events"])
        out: dict[str, RuleEvidence] = {}
        related: dict[str, list[str]] = {}
        for h in alerts:
            src = h["_source"]
            rid = get(src, "rule.id")
            ev = out.setdefault(rid, RuleEvidence())
            trig = src.get("trigger_event") or {}
            if h["_id"] in fp_ids:
                ev.fp.append(trig)
                ev.fp_alert_ids.append(h["_id"])
            else:
                ev.tp.append(trig)
                ev.tp_alert_ids.append(h["_id"])
                related.setdefault(rid, []).extend(src.get("related_events") or [])
        # event liên quan của alert thật: ngoại lệ làm mất event này có thể làm rule ngưỡng không đạt count
        for rid, ids in related.items():
            ids = [i for i in dict.fromkeys(ids) if i][:2000]
            if ids:
                hits = self._search(f"{settings.IDX_EVENTS}-*", {"terms": {"event.id": ids}}, size=len(ids),
                                    source={"excludes": ["raw"]})
                out[rid].tp.extend(h["_source"] for h in hits)
        return out

    # ------------------------------------------------------------ replay
    def _scan(self, query: dict, source: Any, limit: int) -> list[Doc]:
        """Event siem-events-* khớp `query`, sắp theo thời gian (đúng thứ tự để rule ngưỡng / chuỗi chạy đúng)."""
        events: list[Doc] = []
        after = None
        while len(events) < limit:
            kw: dict[str, Any] = {}
            if after:
                kw["search_after"] = after
            try:
                res = self.es.search(index=f"{settings.IDX_EVENTS}-*", size=min(5000, limit - len(events)), query=query,
                                     sort=[{"@timestamp": "asc"}, {"event.id": "asc"}], _source=source, **kw)
            except Exception as e:  # noqa: BLE001
                log.warning("không đọc được event: %s", e)
                break
            hits = res["hits"]["hits"]
            if not hits:
                break
            events.extend(h["_source"] for h in hits)
            after = hits[-1]["sort"]
        return events

    def replay_events(self) -> list[Doc]:
        """Event trong AI_REPLAY_DAYS gần nhất."""
        if self._events is None:
            self._events = self._scan({"range": {"@timestamp": {"gte": self.replay_from}}}, {"excludes": ["raw"]},
                                      self.max_events)
            log.info("replay: đã nạp %d event (%s -> nay)", len(self._events), self.replay_from)
        return self._events

    # ------------------------------------------------------------ gap-ml (sự cố ML đã xác nhận -> rule tần suất)
    def ml_incidents(self) -> list[dict]:
        """Alert ML-WEB / ML-AUTH có kết luận true_positive (analyst trên console, hoặc nhãn lab của tools/ml_eval.py)."""
        return [h["_source"] for h in self._search(settings.IDX_ALERTS, {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": self.lookback}}}, {"terms": {"rule.id": ["ML-WEB", "ML-AUTH"]}},
            {"term": {"alert.verdict": "true_positive"}}]}}, size=500, sort=[{"@timestamp": "asc"}],
            source=["alert.id", "rule", "source.ip", "ml", "event_time"])]

    def events_of(self, ip: str, start: str, end: str) -> list[Doc]:
        """Event của một IP trong [start, end], kèm dòng log gốc (raw.full_log) để bơm vào sandbox."""
        return self._scan({"bool": {"filter": [{"term": {"source.ip": ip}},
                                               {"range": {"@timestamp": {"gte": start, "lte": end}}}]}},
                          ["@timestamp", "event.id", "source.ip", "wazuh.rule", "raw.full_log", "raw.location", "message"],
                          5000)

    def rule_hits(self, sid: str) -> list[Doc]:
        """(thời điểm, IP) mọi event rule Wazuh `sid` khớp trong AI_REPLAY_DAYS: lưu lượng để đặt ngưỡng / đo báo nhầm."""
        return self._scan({"bool": {"filter": [{"term": {"wazuh.rule.id": sid}},
                                               {"range": {"@timestamp": {"gte": self.replay_from}}}]}},
                          ["@timestamp", "source.ip"], self.max_events)

    def alert_ips(self, start: str, end: str, real_only: bool = False) -> set[str]:
        """IP có alert trong [start, end], trừ alert analyst đã kết luận báo nhầm. real_only: chỉ alert thật của rule
        (không bóng, không phải ML), tức là hành vi đã có rule bắt."""
        flt = [{"range": {"@timestamp": {"gte": start, "lte": end}}}, {"exists": {"field": "source.ip"}}]
        skip: list[dict] = [{"term": {"alert.verdict": "false_positive"}}]
        if real_only:
            skip += [{"term": {"alert.source": "ml"}}, {"term": {"alert.shadow": True}}]
        try:
            res = self.es.search(index=settings.IDX_ALERTS, size=0, query={"bool": {"filter": flt, "must_not": skip}},
                                 aggs={"ip": {"terms": {"field": "source.ip", "size": 10000}}})
        except Exception as e:  # noqa: BLE001
            log.warning("không đọc được IP có alert: %s", e)
            raise
        return {b["key"] for b in res["aggregations"]["ip"]["buckets"]}

    # ------------------------------------------------------------ đề xuất cũ
    def proposals(self, statuses: list[str] | None = None, since: str = "now-30d", size: int = 500) -> list[dict]:
        flt: list[dict] = [{"range": {"created_at": {"gte": since}}}]
        if statuses:
            flt.append({"terms": {"status": statuses}})
        return [h["_source"] for h in self._search(settings.IDX_AI_PROPOSALS, {"bool": {"filter": flt}}, size=size,
                                                   sort=[{"created_at": "desc"}])]
