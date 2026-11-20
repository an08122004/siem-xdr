"""Risk-based alerting (soar/risk.py) và giám sát sức khỏe nguồn log / nền tảng (soar/health.py)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from siem import settings, store
from siem.soar.health import HealthMonitor
from siem.soar.risk import RiskTracker

ROOT = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)


class Clock:
    def __init__(self, t: datetime = NOW):
        self.t = t.timestamp()

    def __call__(self) -> float:
        return self.t


def alert(aid, rule, score, host="web-01", user=None, minutes_ago=0, **kw):
    a = {"@timestamp": (NOW - timedelta(minutes=minutes_ago)).isoformat(), "alert": {"id": aid, "source": "rule"},
         "rule": {"id": rule, "name": f"rule {rule}", "mitre": {"tactic": "Execution", "technique": [f"T10{rule[-2:]}"]}},
         "severity": "medium", "risk_score": score, "host": {"name": host}, "agent": {"id": "001"}}
    if user:
        a["user"] = {"name": user}
    return a | kw


# ------------------------------------------------------------------ RBA
def test_rba_fires_when_score_from_several_rules_crosses_threshold():
    rt = RiskTracker(threshold=150, min_rules=2, clock=Clock())
    assert rt.add(alert("a1", "WIN-003", 50)) == [] and rt.add(alert("a2", "WIN-009", 50)) == []
    out = rt.add(alert("a3", "WIN-013", 50))                                   # 150 từ 3 rule
    assert len(out) == 1
    rba = out[0]
    assert rba["rule"]["id"] == "RBA-001" and rba["severity"] == "high" and rba["alert"]["source"] == "rba"
    assert rba["host"] == {"name": "web-01"} and rba["agent"] == {"id": "001"}
    assert rba["risk"]["total"] == 150 and rba["risk"]["rules"] == {"WIN-003": 1, "WIN-009": 1, "WIN-013": 1}
    assert [c["alert_id"] for c in rba["contributions"]] == ["a1", "a2", "a3"]
    assert set(rba["rule"]["mitre"]["technique"]) == {"T1003", "T1009", "T1013"} and rba["priority"] == "P2"
    assert rt.add(alert("a4", "WIN-003", 50)) == []                            # rule đã tính: không cộng thêm
    assert rt.add(alert("a5", "WIN-004", 100)) == []                           # 250: chưa tới bội số tiếp theo
    lvl2 = rt.add(alert("a6", "WIN-005", 50))                                  # 300 -> bắn lại, nâng critical
    assert len(lvl2) == 1 and lvl2[0]["severity"] == "critical" and lvl2[0]["risk"]["level"] == 2


def test_rba_event_matching_several_rules_counts_once():
    # rule phân bậc (rộng/low -> hẹp/high) cùng khớp một event: một bằng chứng, chỉ tính điểm cao nhất
    rt = RiskTracker(threshold=150, min_rules=2, clock=Clock())
    same = {"trigger_event": {"event": {"id": "e1"}}}
    for aid, rule, score in (("t1", "WIN-005-L", 25), ("t2", "WIN-005-M", 50), ("t3", "WIN-005-H", 75)):
        assert rt.add(alert(aid, rule, score, **same)) == []                   # trước 22/10/2026: 150 từ 3 "rule" -> bắn
    out = rt.add(alert("t4", "AUTH-005", 75, trigger_event={"event": {"id": "e2"}}))
    assert len(out) == 1 and out[0]["risk"]["total"] == 150                    # 75 (e1) + 75 (e2)


def test_rba_noisy_rule_counts_once_per_window():
    # rule ồn (vd lớp vỏ Ansible khớp rule low 100 lần/ngày) không tự đẩy thực thể qua ngưỡng
    rt = RiskTracker(threshold=150, min_rules=2, clock=Clock())
    for i in range(100):
        assert rt.add(alert(f"n{i}", "WIN-005-L", 25)) == []
    assert rt.add(alert("o1", "AUTH-005-L", 25)) == []                         # trước 22/10/2026: 2525 -> critical


def test_rba_needs_distinct_rules_ignores_duplicates_shadow_and_health():
    rt = RiskTracker(threshold=150, min_rules=2, clock=Clock())
    for i in range(4):
        assert rt.add(alert(f"s{i}", "WEB-001", 75)) == []                     # 1 rule ồn: không phải chuỗi tấn công
    assert rt.add(alert("s0", "WEB-003", 75)) == []                            # Kafka giao lại alert cũ: không cộng
    assert rt.add(alert("x1", "WEB-003", 75, alert={"id": "x1", "source": "rule", "shadow": True})) == []
    assert rt.add(alert("x2", "HLT-001", 75, alert={"id": "x2", "source": "health"})) == []
    assert len(rt.add(alert("ok", "WEB-003", 75))) == 1                         # rule thứ 2 thật


def test_rba_window_expires_and_entities_are_separate():
    clock = Clock()
    rt = RiskTracker(threshold=150, min_rules=2, window_hours=24, clock=clock)
    assert rt.add(alert("o1", "AUTH-005", 100, minutes_ago=25 * 60)) == []      # ngoài cửa sổ: bỏ
    rt.add(alert("a1", "AUTH-005", 100, host="h1", user="an"))
    clock.t += 23 * 3600
    out = rt.add(alert("a2", "AUTH-006", 60, host="h2", user="an"))             # khác máy, cùng tài khoản
    assert [o["user"]["name"] for o in out] == ["an"] and "host" not in out[0]
    clock.t += 2 * 3600                                                         # a1 hết hạn
    assert rt.add(alert("a3", "AUTH-004", 100, host="h3", user="an")) == []      # 160 nhưng a1 đã ra khỏi cửa sổ


def test_rba_rebuilds_window_after_restart_without_refiring(monkeypatch):
    old = [alert("a1", "WIN-003", 80), alert("a2", "WIN-009", 80),
           {"rule": {"id": "RBA-001"}, "risk": {"entity": {"field": "host.name", "value": "web-01"}, "level": 1}}]
    monkeypatch.setattr(store, "search", lambda *a, **kw: old)
    rt = RiskTracker(threshold=150, min_rules=2, clock=Clock())
    assert rt.load(None) == 2
    assert rt.add(alert("a3", "WIN-013", 10)) == []                            # đã báo mức 1 trước khi khởi động lại
    assert len(rt.add(alert("a4", "WIN-004", 140))) == 1                        # 310: mức 2


def test_soar_emits_rba_alert_and_opens_case():
    from test_pipeline import FakeES
    from siem.soar.cases import CasePlaybooks
    from siem.soar.engine import Notifier, Soar, load_playbooks
    es = FakeES()
    soar = Soar(es, load_playbooks(ROOT / "config" / "playbooks.yml"), whitelist=[], notifier=Notifier(),
                case_playbooks=CasePlaybooks(ROOT / "config" / "case_playbooks.yml"),
                risk=RiskTracker(threshold=100, min_rules=2, clock=Clock()))
    for aid, rule in (("l1", "WIN-003"), ("l2", "WIN-009")):
        soar.handle(alert(aid, rule, 50, severity="low", severity_score=1, message="x"))
    rba = [a for a in es.docs["siem-alerts"].values() if a.get("rule", {}).get("id") == "RBA-001"]
    assert len(rba) == 1 and rba[0]["soar"]["results"]                         # SOAR xử lý alert RBA như alert thường
    cases = list(es.docs["siem-cases"].values())
    assert [c["rule_id"] for c in cases] == ["RBA-001"] and cases[0]["entity"] == "web-01"   # 2 alert low: chỉ 1 case


# ------------------------------------------------------------------ sức khỏe
class HES:
    """ES giả cho HealthMonitor: aggregations nguồn log, cluster / node stats, cập nhật alert bằng script."""

    def __init__(self, sources=None, status="green", used=0.5):
        self.sources, self.updates = sources or [], []
        self.cluster = type("C", (), {"health": lambda _self: {"status": status}})()
        self.nodes = type("N", (), {"stats": lambda _self, metric=None: {"nodes": {"n1": {"name": "es-1", "fs": {
            "total": {"total_in_bytes": 100, "available_in_bytes": int(100 * (1 - used))}}}}}})()

    def search(self, index, size=0, query=None, aggs=None, **_):
        return {"aggregations": {"src": {"buckets": self.sources}}}

    def update(self, index, id, **kw):
        self.updates.append((id, kw))


def bucket(src, count, first_h, last_min, hour, host=None):
    ms = lambda dt: dt.timestamp() * 1000                                       # noqa: E731
    return {"key": src, "doc_count": count, "first": {"value": ms(NOW - timedelta(hours=first_h))},
            "last": {"value": ms(NOW - timedelta(minutes=last_min))}, "hour": {"doc_count": hour},
            "host": {"buckets": [{"key": host or src}]}}


@pytest.fixture()
def hm(monkeypatch):
    emitted, bulk = [], []
    monkeypatch.setattr(store, "search", lambda *a, **kw: [])
    monkeypatch.setattr(store, "bulk_index", lambda es, actions: bulk.extend(actions) or len(bulk))

    def make(es=None, **kw):
        m = HealthMonitor(es or HES(), emitted.append, clock=Clock(), **kw)
        m.emitted, m.bulk = emitted, bulk
        return m
    return make


def test_health_agent_down_once_then_recovered(hm, monkeypatch):
    now = NOW.isoformat()
    agents = [{"agent_id": "001", "hostname": "demo-web", "wazuh_status": "disconnected", "synced_at": now,
               "last_seen": (NOW - timedelta(minutes=20)).isoformat(), "ip": "10.0.0.5"},
              {"agent_id": "002", "hostname": "pc-01", "wazuh_status": "disconnected", "synced_at": now,
               "last_seen": (NOW - timedelta(minutes=5)).isoformat()}]                      # chưa đủ 15 phút
    monkeypatch.setattr(store, "list_agents", lambda es: agents)
    m = hm()
    m.check_agents()
    m.check_agents()                                                                       # không báo trùng
    assert [(a["rule"]["id"], a["host"]["name"]) for a in m.emitted] == [("HLT-001", "demo-web")]
    a = m.emitted[0]
    assert a["alert"]["source"] == "health" and a["severity"] == "medium" and "20 phút" in a["rule"]["description"]
    agents[0]["wazuh_status"] = "active"
    m.check_agents()
    assert m.es.updates and "kết nối lại" in m.es.updates[-1][1]["script"]["params"]["text"]
    assert ("HLT-001", "demo-web") not in m.open


def test_health_wazuh_sync_stale(hm, monkeypatch):
    monkeypatch.setattr(settings, "WAZUH_API_PASSWORD", "x")
    monkeypatch.setattr(store, "list_agents", lambda es: [{"agent_id": "001", "wazuh_status": "active",
                                                          "synced_at": (NOW - timedelta(minutes=30)).isoformat()}])
    m = hm()
    m.check_agents()
    assert [a["rule"]["id"] for a in m.emitted] == ["HLT-004"] and m.emitted[0]["severity"] == "high"


def test_health_silent_source_and_volume_deviation(hm):
    es = HES(sources=[bucket("001", 100 * 24 * 7, 7 * 24, 120, 0, "demo-web"),      # 100/giờ, im 2 giờ
                      bucket("002", 50 * 24 * 7, 7 * 24, 1, 50, "pc-01"),           # bình thường
                      bucket("syslog-10.0.0.1", 200 * 48, 48, 1, 20),               # 200/giờ, giờ qua chỉ 20
                      bucket("003", 2, 7 * 24, 300, 0),                             # nguồn thưa: im là bình thường
                      bucket("soc-console", 1000, 48, 600, 0)])
    m = hm(es)
    m.check_sources()
    got = {(a["rule"]["id"], a["health"]["key"]): a for a in m.emitted}
    assert set(got) == {("HLT-002", "001"), ("HLT-003", "syslog-10.0.0.1")}
    assert got[("HLT-003", "syslog-10.0.0.1")]["severity"] == "low" and "thấp hơn" in got[("HLT-003", "syslog-10.0.0.1")]["rule"]["description"]
    status = {d["_id"]: d["_source"]["status"] for d in m.bulk}
    assert status == {"001": "silent", "002": "ok", "syslog-10.0.0.1": "deviation", "003": "ok"}


def test_health_kafka_lag_and_elasticsearch(hm):
    lag = {"siem-analyzer": 9000, "siem-soar": 0}
    m = hm(HES(status="red", used=0.85), kafka_lag=lambda: lag)
    m.check_kafka()
    assert m.emitted == []                                                    # tụt chưa đủ 5 phút
    m.clock.t += 6 * 60
    m.check_kafka()
    assert [(a["rule"]["id"], a["health"]["key"]) for a in m.emitted] == [("HLT-005", "siem-analyzer")]
    m.check_elasticsearch()
    hlt6 = {a["health"]["key"]: a["severity"] for a in m.emitted if a["rule"]["id"] == "HLT-006"}
    assert hlt6 == {"cluster": "critical", "disk:es-1": "high"}
    lag["siem-analyzer"] = 0
    m.check_kafka()
    assert ("HLT-005", "siem-analyzer") not in m.open


def test_health_snapshot_policy(hm):
    class SLM:
        def __init__(self, pol):
            self.pol = pol

        def get_lifecycle(self, policy_id):
            if self.pol is None:
                raise RuntimeError("404 resource_not_found_exception")
            return {policy_id: self.pol}
    ms = lambda h: (NOW - timedelta(hours=h)).timestamp() * 1000                  # noqa: E731
    es = HES()
    m = hm(es)
    es.slm = SLM(None)
    m.check_snapshots()                                                          # chưa có chính sách
    es.slm = SLM({"last_success": {"time": ms(48)}, "modified_date_millis": ms(24 * 10)})
    m.open.clear()
    m.check_snapshots()                                                          # bản gần nhất 48 giờ trước
    es.slm = SLM({"last_success": {"time": ms(30)}, "last_failure": {"time": ms(5), "details": "disk full"}})
    m.open.clear()
    m.check_snapshots()
    got = [(a["severity"], a["rule"]["description"]) for a in m.emitted if a["rule"]["id"] == "HLT-007"]
    assert [s for s, _ in got] == ["medium", "high", "high"]
    assert "chưa có chính sách" in got[0][1] and "36 giờ" in got[1][1] and "disk full" in got[2][1]
    es.slm = SLM({"last_success": {"time": ms(2)}, "last_failure": {"time": ms(30)}})
    m.check_snapshots()
    assert ("HLT-007", "daily-snapshots") not in m.open                           # đã có bản mới: hồi phục
