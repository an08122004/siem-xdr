"""Vòng đời IOC và DÒ NGƯỢC (retro-hunt): IOC mới xuất hiện (file config/intel hoặc feed MISP) thì tìm lại
RETROHUNT_DAYS ngày event cũ, vì event đã vào hệ thống TRƯỚC khi biết IOC thì lúc đó không khớp được TI-001.

Mỗi chu kỳ (SOAR, 10 phút):
  1. Danh sách IOC đang hiệu lực so với index siem-intel (mỗi IOC một bản ghi: nguồn, mô tả, lần đầu hệ thống thấy,
     hạn, lần dò ngược, số event khớp, trạng thái active / expired).
  2. IOC mới -> tìm trong siem-events-* (IP: source.ip / destination.ip; domain: dns.question.name, url.domain,
     destination.domain, kể cả subdomain; hash: process.hash.*), BỎ event đã được gắn đúng IOC đó lúc vào (TI-001 đã báo).
     Mỗi chu kỳ dò tối đa RETROHUNT_MAX_PER_RUN IOC (feed MISP lần đầu có thể hàng nghìn IOC): phần còn lại dò ở các
     chu kỳ sau, SOAR không bị chặn xử lý alert.
  3. Có khớp -> alert TI-002 (high): số event, lần đầu / cuối, máy liên quan; SOAR thông báo và mở case (PB-06).
  4. IOC không còn trong danh sách / quá hạn -> trạng thái expired (không xóa: còn để tra cứu, báo cáo)."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from .. import priority as prio
from .. import settings, store
from ..detection.rules import SEVERITY_SCORE

log = logging.getLogger("soar.retrohunt")

IDX_INTEL = "siem-intel"
RULE_ID = "TI-002"
FIELDS = {"ip": ["source.ip", "destination.ip"], "domain": ["dns.question.name", "url.domain", "destination.domain"],
          "hash": ["process.hash.md5", "process.hash.sha1", "process.hash.sha256"]}



def ioc_id(m: dict[str, Any]) -> str:
    return f"{m['type']}:{m['value']}"


class RetroHunter:
    def __init__(self, es, indicators: Callable[[], list[dict[str, Any]]], emit: Callable[[dict[str, Any]], Any],
                 days: int = 30, max_per_run: int = 300):
        self.es, self.indicators, self.emit, self.days, self.max_per_run = es, indicators, emit, days, max_per_run

    def known(self) -> dict[str, dict[str, Any]]:
        rows = store.search(self.es, IDX_INTEL, {"match_all": {}}, size=10000, sort=[{"first_seen": {"order": "asc",
                                                                                               "unmapped_type": "date"}}])
        return {r["_id"]: r for r in rows}

    def run(self) -> list[dict[str, Any]]:
        now = store.now_iso()
        current = {ioc_id(m): m for m in self.indicators()}
        known = self.known()
        new = [m for k, m in current.items() if k not in known or known[k].get("status") != "active"]
        gone = [k for k, d in known.items() if d.get("status") == "active" and k not in current]
        ops: list[dict[str, Any]] = []
        for m in new:
            ops.append({"_index": IDX_INTEL, "_id": ioc_id(m), "_source": {
                "type": m["type"], "value": m["value"], "source": m.get("source"), "description": m.get("description"),
                "reference": m.get("event"), "expires_at": m.get("expires"), "status": "active",
                "first_seen": now, "@timestamp": now, "retro_hunted_at": None, "hits": 0}})
        for k in gone:
            ops.append({"_op_type": "update", "_index": IDX_INTEL, "_id": k,
                        "doc": {"status": "expired", "expired_at": now, "@timestamp": now}})
        if ops:
            store.bulk_index(self.es, ops)
        # IOC đang hiệu lực chưa dò: mới thêm lần này, hoặc còn lại từ chu kỳ trước (vượt giới hạn mỗi chu kỳ)
        pending = [m for k, m in current.items() if k not in known or known[k].get("status") != "active"
                   or not known[k].get("retro_hunted_at")][:self.max_per_run]
        alerts = [a for m in pending if (a := self.hunt(m, now))]
        for a in alerts:
            self.emit(a)
        if new or gone or pending:
            log.info("IOC: %d mới, %d hết hiệu lực; dò ngược %d IOC trong %d ngày, %d khớp",
                     len(new), len(gone), len(pending), self.days, len(alerts))
        return alerts

    def _clauses(self, kind: str, values: list[str], field: str) -> list[dict[str, Any]]:
        if kind == "ip":
            exact = [v for v in values if "/" not in v]
            cidr = [{"term": {field: v}} for v in values if "/" in v]   # ES: term trên trường ip nhận cả CIDR
            return ([{"terms": {field: exact}}] if exact else []) + cidr
        if kind == "domain":
            return [{"terms": {field: values}}] + [{"wildcard": {field: {"value": f"*.{v}", "case_insensitive": True}}}
                                                    for v in values[:50]]
        return [{"terms": {field: values}}]

    def hunt(self, m: dict[str, Any], now: str) -> dict[str, Any] | None:
        """Tìm IOC trong RETROHUNT_DAYS ngày event; có khớp thì trả về alert TI-002."""
        kind, v = m["type"], m["value"]
        since = (datetime.now(timezone.utc) - timedelta(days=self.days)).isoformat()
        should = [c for f in FIELDS[kind] for c in self._clauses(kind, [v], f)]
        q = {"bool": {"filter": [{"range": {"@timestamp": {"gte": since}}}], "should": should, "minimum_should_match": 1,
                      "must_not": [{"term": {"threat.indicator.value": v}}]}}       # TI-001 đã báo lúc event vào
        try:
            res = self.es.search(index=f"{settings.IDX_EVENTS}-*", size=1, query=q, sort=[{"@timestamp": "asc"}],
                                 aggs={"first": {"min": {"field": "@timestamp"}}, "last": {"max": {"field": "@timestamp"}},
                                       "hosts": {"terms": {"field": "host.name", "size": 10}},
                                       "agents": {"terms": {"field": "agent.id", "size": 1}}})
        except Exception as e:  # noqa: BLE001 - 1 IOC lỗi không chặn các IOC khác (lần sau dò lại)
            log.warning("dò ngược %s lỗi: %s", v, e)
            return None
        n = res["hits"]["total"]["value"]
        self.es.update(index=IDX_INTEL, id=ioc_id(m), doc={"retro_hunted_at": now, "hits": n})
        if not n:
            return None
        ag = res["aggregations"]
        first_ev = (res["hits"]["hits"] or [{}])[0].get("_source") or {}
        return self.alert(m, n, ag["first"].get("value_as_string"), ag["last"].get("value_as_string"),
                          [b["key"] for b in ag["hosts"]["buckets"]],
                          ([b["key"] for b in ag["agents"]["buckets"]] or [None])[0], first_ev)

    def alert(self, m: dict[str, Any], n: int, first: str | None, last: str | None, hosts: list[str],
              agent: str | None, ev: dict[str, Any]) -> dict[str, Any]:
        now = store.now_iso()
        kind = {"ip": "IP", "domain": "tên miền", "hash": "hash"}[m["type"]]
        a: dict[str, Any] = {
            "@timestamp": now,
            "alert": {"id": store.new_id(), "status": "open", "source": "retrohunt"},
            "rule": {"id": RULE_ID, "name": f"IOC mới khớp log cũ ({kind} {m['value']})",
                     "description": f"Dò ngược {self.days} ngày: {n} event khớp IOC mới từ {m.get('source')}"
                                    + (f" ({m['description']})" if m.get("description") else "")
                                    + f", từ {first} tới {last}, máy: {', '.join(hosts) or '—'}",
                     "type": "retrohunt", "severity": "high", "tags": ["threat-intel", "retrohunt"],
                     "mitre": {"tactic": "Command and Control", "technique": ["T1071"]}},
            "severity": "high", "severity_score": SEVERITY_SCORE["high"], "risk_score": 75.0, "count": n,
            "threat": {"matched": True, "indicator": {"type": m["type"], "value": m["value"], "provider": m.get("source"),
                                                      "description": m.get("description"), "reference": m.get("event")}},
            "retrohunt": {"days": self.days, "hits": n, "first": first, "last": last, "hosts": hosts},
            "first_event_time": first, "metrics": {"ttd_seconds": prio.seconds_between(first, now)},
        }
        if hosts:
            a["host"] = {"name": hosts[0]}
        if agent:
            a["agent"] = {"id": agent}
        for f in ("source.ip", "destination.ip", "user.name"):
            top, key = f.split(".")
            if (v := (ev.get(top) or {}).get(key)):
                a.setdefault(top, {})[key] = v
        a["priority"] = prio.policy().priority("high", (ev.get("asset") or {}).get("criticality"))
        a["message"] = f"[HIGH] {a['rule']['name']} | {n} event | máy {', '.join(hosts) or '?'}"
        return a
