"""Threat intelligence: vòng đời IOC (hạn trong file, hạn theo loại của MISP), feed MISP, dò ngược log cũ (TI-002)."""
from __future__ import annotations

import io
import json
from datetime import date, datetime, timedelta, timezone

from siem import store
from siem.pipeline.enrich import IOCSet, ThreatIntel, parse_line
from siem.pipeline.misp import MispFeed, parse
from siem.soar.retrohunt import RetroHunter

NOW = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)


def test_local_ioc_lines_with_expiry_and_description():
    today = date(2026, 10, 13)
    m = parse_line("203.0.113.66   # C2 Cobalt Strike, hết hạn: 2026-12-31", "ip", today)
    assert m == {"type": "ip", "value": "203.0.113.66", "source": "local", "expires": "2026-12-31",
                 "description": "C2 Cobalt Strike, hết hạn: 2026-12-31"}
    assert parse_line("198.51.100.7 # expires=2026-10-01", "ip", today) is None          # đã hết hạn
    assert parse_line("# chỉ là chú thích", "ip", today) is None and parse_line("", "ip", today) is None
    assert parse_line("Evil.Example", "domain", today)["value"] == "evil.example" and \
        parse_line("Evil.Example", "domain", today)["expires"] is None


def test_ioc_set_matches_cidr_and_subdomain(tmp_path):
    (tmp_path / "bad_ips.txt").write_text("198.51.100.0/24 # dải thử\n2001:db8::/32\n", encoding="utf-8")
    (tmp_path / "bad_domains.txt").write_text("evil-c2.example # C2 nhóm X\nold.example # hết hạn: 2020-01-01\n",
                                              encoding="utf-8")
    (tmp_path / "bad_hashes.txt").write_text("44D88612FEA8A8F36DE82E1278ABB02F\n", encoding="utf-8")
    ti = ThreatIntel(tmp_path)
    assert ti.match_ip("198.51.100.9")["value"] == "198.51.100.0/24" and ti.match_ip("2001:db8::5")
    assert ti.match_ip("10.0.0.1") is None and ti.match_ip("không-phải-ip") is None
    assert ti.match_domain("a.b.evil-c2.example")["description"] == "C2 nhóm X" and ti.match_domain("old.example") is None
    assert ti.match_hash("44d88612fea8a8f36de82e1278abb02f")
    doc = {"destination": {"ip": "198.51.100.9"}}
    ti.enrich(doc)
    assert doc["threat"]["indicator"]["provider"] == "local" and doc["threat"]["indicator"]["matched"] == "198.51.100.0/24"
    assert ti.iocs["domain"] == {"evil-c2.example"}                                    # giữ giao diện cũ


ATTRS = [
    {"type": "ip-dst", "value": "203.0.113.5", "to_ids": True, "timestamp": str(int((NOW - timedelta(days=5)).timestamp())),
     "event_id": "17", "Event": {"info": "Chiến dịch phishing tháng 10"}},
    {"type": "ip-dst", "value": "203.0.113.6", "to_ids": True, "timestamp": str(int((NOW - timedelta(days=40)).timestamp()))},
    {"type": "ip-src", "value": "203.0.113.7", "to_ids": False, "timestamp": str(int(NOW.timestamp()))},   # không to_ids
    {"type": "domain|ip", "value": "c2.evil.test|198.51.100.30", "to_ids": True,
     "last_seen": (NOW - timedelta(days=60)).isoformat(), "timestamp": str(int((NOW - timedelta(days=200)).timestamp()))},
    {"type": "filename|sha256", "value": "a.exe|" + "ab" * 32, "to_ids": True, "timestamp": str(int((NOW - timedelta(days=300)).timestamp()))},
    {"type": "url", "value": "http://x.test/a", "to_ids": True, "timestamp": str(int(NOW.timestamp()))},     # chưa hỗ trợ
]


def test_misp_attributes_lifetime_by_type():
    items = {(m["type"], m["value"]): m for m in parse(ATTRS, now=NOW)}
    assert set(items) == {("ip", "203.0.113.5"), ("domain", "c2.evil.test"), ("hash", "ab" * 32)}
    # IP 40 ngày > 30 ngày: hết hạn; domain|ip thấy 60 ngày trước: domain (90 ngày) còn, IP (30 ngày) hết
    assert items[("ip", "203.0.113.5")]["expires"] == (NOW + timedelta(days=25)).date().isoformat()
    assert items[("ip", "203.0.113.5")]["event"] == "misp:event/17" and items[("ip", "203.0.113.5")]["source"] == "misp"


def test_misp_feed_refresh_keeps_last_good_set_on_error():
    calls = []

    def opener(req):
        calls.append(json.loads(req.data))
        if len(calls) > 1:
            raise OSError("MISP không phản hồi")
        assert req.headers["Authorization"] == "khoa-bi-mat"
        return io.BytesIO(json.dumps({"response": {"Attribute": ATTRS}}).encode())
    feed = MispFeed("https://misp.example", "khoa-bi-mat", opener=opener)
    feed.ttl = {"ip": 3650, "domain": 3650, "hash": 3650}
    assert feed.refresh() == 5 and calls[0]["to_ids"] == 1 and calls[0]["enforceWarninglist"] is True
    assert feed.refresh() == -1 and "không phản hồi" in feed.last_error
    assert feed.snapshot().ip("203.0.113.6")                                    # vẫn dùng bộ IOC lần trước
    ti = ThreatIntel(__import__("pathlib").Path("khong-co-thu-muc"), feed=feed)
    assert ti.match_domain("www.c2.evil.test")["source"] == "misp"
    assert {(m["type"], m["value"]) for m in ti.indicators()} >= {("ip", "203.0.113.6"), ("hash", "ab" * 32)}


class RES:
    """ES giả cho RetroHunter: siem-intel trong bộ nhớ, event khớp theo IOC."""

    def __init__(self, hits):
        self.intel, self.hits, self.queries = {}, hits, []

    def search(self, index, size=1, query=None, sort=None, aggs=None, **_):
        self.queries.append(query)
        v = query["bool"]["must_not"][0]["term"]["threat.indicator.value"]
        n = self.hits.get(v, 0)
        return {"hits": {"total": {"value": n}, "hits": [{"_source": {"source": {"ip": "10.0.0.7"},
                                                                      "asset": {"criticality": "critical"}}}] if n else []},
                "aggregations": {"first": {"value_as_string": "2026-09-20T08:00:00Z"},
                                 "last": {"value_as_string": "2026-10-01T09:00:00Z"},
                                 "hosts": {"buckets": [{"key": "pc-01"}]}, "agents": {"buckets": [{"key": "002"}]}}}

    def update(self, index, id, doc, **_):
        self.intel[id].update(doc)


def test_retrohunt_new_iocs_hunt_old_events_and_lifecycle(monkeypatch):
    es = RES({"203.0.113.5": 12})
    monkeypatch.setattr(store, "search", lambda _es, index, *a, **kw: [{"_id": k, **v} for k, v in es.intel.items()])

    def bulk(_es, ops):
        for op in ops:
            if op.get("_op_type") == "update":
                es.intel[op["_id"]].update(op["doc"])
            else:
                es.intel[op["_id"]] = dict(op["_source"])
    monkeypatch.setattr(store, "bulk_index", bulk)
    iocs = [{"type": "ip", "value": "203.0.113.5", "source": "misp", "description": "C2"},
            {"type": "domain", "value": "evil.test", "source": "local"}]
    emitted = []
    h = RetroHunter(es, lambda: list(iocs), emitted.append, days=30, max_per_run=10)
    alerts = h.run()
    assert len(alerts) == 1 and emitted == alerts
    a = alerts[0]
    assert a["rule"]["id"] == "TI-002" and a["alert"]["source"] == "retrohunt" and a["count"] == 12
    assert a["host"] == {"name": "pc-01"} and a["agent"] == {"id": "002"} and a["priority"] == "P1"   # tài sản critical
    assert a["threat"]["indicator"]["value"] == "203.0.113.5" and "C2" in a["rule"]["description"]
    assert es.intel["ip:203.0.113.5"]["hits"] == 12 and es.intel["domain:evil.test"]["retro_hunted_at"]
    dom_q = next(q for q in es.queries if q["bool"]["must_not"][0]["term"]["threat.indicator.value"] == "evil.test")
    assert {"wildcard": {"url.domain": {"value": "*.evil.test", "case_insensitive": True}}} in dom_q["bool"]["should"]
    assert h.run() == [] and len(es.queries) == 2                               # đã dò rồi: không dò lại, không báo trùng
    iocs.pop(0)
    h.run()
    assert es.intel["ip:203.0.113.5"]["status"] == "expired"                     # gỡ khỏi nguồn: hết hiệu lực, không xóa


def test_retrohunt_limits_iocs_per_run(monkeypatch):
    es = RES({})
    monkeypatch.setattr(store, "search", lambda _es, index, *a, **kw: [{"_id": k, **v} for k, v in es.intel.items()])
    monkeypatch.setattr(store, "bulk_index", lambda _es, ops: [es.intel.__setitem__(o["_id"], dict(o["_source"]))
                                                               for o in ops if "_source" in o])
    iocs = [{"type": "ip", "value": f"203.0.113.{i}", "source": "misp"} for i in range(25)]
    h = RetroHunter(es, lambda: iocs, lambda a: None, max_per_run=10)
    h.run()
    assert len(es.queries) == 10 and len(es.intel) == 25                         # ghi đủ 25, dò 10
    h.run()
    h.run()
    assert len(es.queries) == 25 and all(d["retro_hunted_at"] for d in es.intel.values())
