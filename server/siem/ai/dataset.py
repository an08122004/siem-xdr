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
GROUP_FIELDS = ["event.module", "event.category", "event.action"]


@dataclass
class RuleEvidence:
    fp: list[Doc] = field(default_factory=list)          # trigger event của alert báo nhầm
    tp: list[Doc] = field(default_factory=list)          # trigger + related event của alert sự cố thật
    fp_alert_ids: list[str] = field(default_factory=list)
    tp_alert_ids: list[str] = field(default_factory=list)


@dataclass
class EventGroup:
    key: dict[str, Any]
    count: int
    samples: list[Doc]

    @property
    def key_str(self) -> str:
        return "|".join(str(self.key.get(f) or "-") for f in GROUP_FIELDS)


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
    def replay_events(self) -> list[Doc]:
        """Event trong AI_REPLAY_DAYS gần nhất, sắp theo thời gian (đúng thứ tự để rule ngưỡng / chuỗi chạy đúng)."""
        if self._events is not None:
            return self._events
        events: list[Doc] = []
        after = None
        while len(events) < self.max_events:
            kw: dict[str, Any] = {}
            if after:
                kw["search_after"] = after
            try:
                res = self.es.search(index=f"{settings.IDX_EVENTS}-*", size=min(5000, self.max_events - len(events)),
                                     query={"range": {"@timestamp": {"gte": self.replay_from}}},
                                     sort=[{"@timestamp": "asc"}, {"event.id": "asc"}],
                                     _source={"excludes": ["raw"]}, **kw)
            except Exception as e:  # noqa: BLE001
                log.warning("không đọc được event để replay: %s", e)
                break
            hits = res["hits"]["hits"]
            if not hits:
                break
            events.extend(h["_source"] for h in hits)
            after = hits[-1]["sort"]
        self._events = events
        log.info("replay: đã nạp %d event (%s -> nay)", len(events), self.replay_from)
        return events

    # ------------------------------------------------------------ nhóm event
    def event_groups(self, min_count: int, max_groups: int = 30, samples: int = 15) -> list[EventGroup]:
        try:
            res = self.es.search(index=f"{settings.IDX_EVENTS}-*", size=0,
                                 query={"range": {"@timestamp": {"gte": self.replay_from}}},
                                 aggs={"g": {"composite": {"size": 500, "sources": [
                                     {f.replace(".", "_"): {"terms": {"field": f, "missing_bucket": True}}}
                                     for f in GROUP_FIELDS]}}})
        except Exception as e:  # noqa: BLE001
            log.warning("không nhóm được event: %s", e)
            return []
        buckets = sorted(res["aggregations"]["g"]["buckets"], key=lambda b: -b["doc_count"])
        groups = []
        for b in buckets:
            if b["doc_count"] < min_count or len(groups) >= max_groups:
                continue
            key = {f: b["key"][f.replace(".", "_")] for f in GROUP_FIELDS}
            flt: list[dict] = [{"range": {"@timestamp": {"gte": self.replay_from}}}]
            must_not: list[dict] = []
            for f, v in key.items():
                (flt.append({"term": {f: v}}) if v is not None else must_not.append({"exists": {"field": f}}))
            hits = self._search(f"{settings.IDX_EVENTS}-*", {"bool": {"filter": flt, "must_not": must_not}},
                                size=samples, source={"excludes": ["raw"]}, sort=[{"@timestamp": "desc"}])
            groups.append(EventGroup(key, b["doc_count"], [h["_source"] for h in hits]))
        return groups

    # ------------------------------------------------------------ đề xuất cũ
    def proposals(self, statuses: list[str] | None = None, since: str = "now-30d", size: int = 500) -> list[dict]:
        flt: list[dict] = [{"range": {"created_at": {"gte": since}}}]
        if statuses:
            flt.append({"terms": {"status": statuses}})
        return [h["_source"] for h in self._search(settings.IDX_AI_PROPOSALS, {"bool": {"filter": flt}}, size=size,
                                                   sort=[{"created_at": "desc"}])]
