"""Test phần tích hợp Wazuh: chuẩn hóa event archives/alerts, cầu nối cảnh báo ruleset Wazuh, analyzer,
SOAR ra lệnh qua Wazuh API (API và Elasticsearch giả lập). Không cần Wazuh / Kafka / ES thật."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from siem import settings, store
from siem.detection import wazuh as bridge
from siem.detection.rules import RuleEngine, load_rules
from siem.pipeline.enrich import Enricher
from siem.pipeline.normalize import get, normalize
from siem.soar import wazuh as soar_wazuh

ROOT = Path(__file__).resolve().parent.parent
AGENT = {"id": "001", "name": "demo-web", "ip": "172.18.0.8"}


def wz(event_type="wazuh", **ev):
    """Event thô đúng như Vector (vector/wazuh.yaml) đưa vào Kafka."""
    ev = {"timestamp": "2026-09-28T15:31:34.123+0000", "agent": AGENT, "manager": {"name": "wazuh-manager"},
          "id": "1790609494.501537", **ev}
    return {"timestamp": ev["timestamp"], "agent_id": "wazuh-001", "source": "wazuh", "event_type": event_type,
            "data": ev}


@pytest.fixture(scope="module")
def enricher():
    return Enricher(ROOT / "config")


@pytest.fixture()
def engine():
    return RuleEngine(load_rules(ROOT / "rules"))


def fired(engine, enricher, raws):
    return [d.rule.id for r in raws for d in engine.process(enricher.enrich(normalize(r)))]


# ------------------------------------------------------------------ chuẩn hóa
def test_apache_via_wazuh_keeps_existing_rules(engine, enricher):
    line = '203.0.113.9 - - [28/Sep/2026:15:31:34 +0000] "GET /p?id=1%20union%20select%201,2 HTTP/1.1" 200 5 "-" "curl"'
    raw = wz(full_log=line, decoder={"name": "web-accesslog"}, location="/usr/local/apache2/logs/access_log")
    doc = enricher.enrich(normalize(raw))
    assert get(doc, "agent.id") == "001" and get(doc, "agent.type") == "wazuh" and get(doc, "host.name") == "demo-web"
    assert get(doc, "event.id").startswith("wazuh-001-1790609494.501537-")
    assert get(normalize(raw), "event.id") == get(doc, "event.id")       # cố định -> đọc lại không tạo bản ghi trùng
    assert get(doc, "@timestamp") == "2026-09-28T15:31:34+00:00"          # thời gian trong dòng log
    assert get(doc, "source.ip") == "203.0.113.9" and get(doc, "url.decoded") == "/p?id=1 union select 1,2"
    assert get(doc, "asset.id") == "S001-DEMO"                             # tra theo tên agent
    assert get(doc, "wazuh.location") == "/usr/local/apache2/logs/access_log"
    assert "WEB-001" in fired(engine, enricher, [raw])


def test_events_sharing_wazuh_id_get_distinct_event_ids():
    # Wazuh đặt id = <giây>.<vị trí alerts.log>: mọi event không sinh cảnh báo trong cùng giây chung 1 id (đã gặp
    # thật: 8 event chung id, ES chỉ giữ 1). Hai tiến trình khác nhau phải là 2 bản ghi.
    lines = [f"ossec: output: 'siem-procs': siem-proc: pid={p} ppid=1 uid=0 name=sh parent=init exe=- cmd=" for p in (5, 6)]
    ids = {get(normalize(wz(full_log=line, location="siem-procs")), "event.id") for line in lines}
    assert len(ids) == 2
    ids.add(get(normalize(wz(full_log=lines[0], location="siem-procs", timestamp="2026-09-28T15:31:34.124+0000")), "event.id"))
    assert len(ids) == 3                                                  # cùng dòng nhưng khác thời điểm (ms)


def test_windows_eventchannel_mapped_to_existing_parser():
    raw = wz(location="EventChannel", agent={"id": "002", "name": "PC-01"}, data={"win": {
        "system": {"eventID": "4625", "channel": "Security", "providerName": "Microsoft-Windows-Security-Auditing",
                   "computer": "PC-01.lab.local", "eventRecordID": "99", "message": "\"An account failed to log on.\""},
        "eventdata": {"targetUserName": "admin", "ipAddress": "10.0.0.66", "ipPort": "50000", "logonType": "3",
                      "status": "0xc000006d"}}})
    doc = normalize(raw)
    assert get(doc, "event.code") == 4625 and get(doc, "event.outcome") == "failure"
    assert get(doc, "user.name") == "admin" and get(doc, "source.ip") == "10.0.0.66"
    assert get(doc, "winlog.logon.type") == "network"
    assert get(doc, "host.name") == "PC-01" and get(doc, "winlog.computer_name") == "PC-01.lab.local"
    assert get(doc, "message") == "An account failed to log on."


def test_sysmon_process_via_wazuh(engine, enricher):
    raw = wz(location="EventChannel", agent={"id": "002", "name": "PC-01"}, data={"win": {
        "system": {"eventID": "1", "channel": "Microsoft-Windows-Sysmon/Operational",
                   "providerName": "Microsoft-Windows-Sysmon", "computer": "PC-01"},
        "eventdata": {"image": "C:\\Windows\\System32\\vssadmin.exe", "commandLine": "vssadmin.exe delete shadows /all",
                      "parentImage": "C:\\Windows\\System32\\cmd.exe", "processId": "4242"}}})
    doc = normalize(raw)
    assert get(doc, "event.module") == "sysmon" and get(doc, "process.name") == "vssadmin.exe"
    assert get(doc, "process.pid") == 4242 and get(doc, "process.parent.name") == "cmd.exe"
    assert "WIN-010" in fired(engine, enricher, [raw])


def test_siem_procs_line_triggers_lnx002(engine, enricher):
    full = ("ossec: output: 'siem-procs': siem-proc: pid=947 ppid=560 uid=33 name=sh parent=httpd exe=/usr/bin/dash "
            "cmd=sh -c ping -c 1 -W 1 127.0.0.1;sleep 15 2>&1 ")
    raw = wz(full_log=full, location="siem-procs", decoder={"name": "ossec"})
    doc = normalize(raw)
    assert get(doc, "process.pid") == 947 and get(doc, "process.name") == "sh"
    assert get(doc, "process.parent.name") == "httpd" and get(doc, "process.executable") == "/usr/bin/dash"
    assert get(doc, "process.command_line").startswith("sh -c ping")
    assert "LNX-002" in fired(engine, enricher, [raw])


def test_fim_event():
    raw = wz(location="syscheck", syscheck={
        "path": "/usr/local/apache2/htdocs/shell.php", "event": "added", "size_after": "31", "perm_after": "rw-r--r--",
        "uname_after": "root", "md5_after": "a" * 32, "sha256_after": "b" * 64},
        rule={"id": "100100", "level": 10, "description": "File mới trong thư mục web", "groups": ["local", "syscheck"],
              "mitre": {"id": ["T1505.003"], "tactic": ["Persistence"]}})
    doc = normalize(raw)
    assert get(doc, "event.module") == "fim" and get(doc, "event.category") == "file"
    assert get(doc, "event.action") == "file_created" and get(doc, "event.type") == "creation"
    assert get(doc, "file.path") == "/usr/local/apache2/htdocs/shell.php" and get(doc, "file.name") == "shell.php"
    assert get(doc, "file.size") == 31 and get(doc, "file.hash.sha256") == "b" * 64
    assert get(doc, "wazuh.rule.id") == "100100"


def test_registry_fim_windows():
    doc = normalize(wz(location="syscheck", syscheck={
        "path": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "event": "modified",
        "value_name": "evil"}))
    assert get(doc, "event.category") == "registry" and get(doc, "event.action") == "registry_modified"
    assert get(doc, "registry.value") == "evil"


RESULT_LINE = ("2026/09/28 15:42:01 siem-xdr: action=6534698eb33249c5a1647035c8d15791 type=kill_process target=947 "
               "status=success detail=đã kill PID 947 (sh) và 1 tiến trình con")


@pytest.mark.parametrize("location,full", [
    ("/var/ossec/logs/active-responses.log", RESULT_LINE),
    ("active-response\\active-responses.log", RESULT_LINE),                       # Windows: đường dẫn tương đối
    ("C:\\Program Files (x86)\\ossec-agent\\active-response\\active-responses.log", RESULT_LINE),
    ("active-response\\active-responses.log", "\ufeff" + RESULT_LINE),            # BOM của PowerShell 5.1
])
def test_response_result_line(location, full):
    doc = normalize(wz(full_log=full, location=location))
    assert get(doc, "event.action") == "response_result" and get(doc, "event.outcome") == "success"
    assert get(doc, "siem.action") == {"id": "6534698eb33249c5a1647035c8d15791", "type": "kill_process",
                                       "target": "947", "status": "success",
                                       "output": "đã kill PID 947 (sh) và 1 tiến trình con"}


# ------------------------------------------------------------------ chống tiêm dòng telemetry giả
# Trước 11/10/2026 dòng "siem-proc:" / "siem-xdr:" được tìm ở MỌI dòng log và xét trước access log / auth log: kẻ tấn
# công đặt chúng vào User-Agent hay tên user SSH là tạo được event tiến trình giả (LNX-002 -> SOAR tự kill PID do kẻ
# tấn công chọn) hoặc biến request tấn công thành "kết quả lệnh" (thoát mọi rule web).
FORGED_PROC = "siem-proc: pid=7 ppid=1 uid=33 name=sh parent=httpd exe=/bin/sh cmd=sh"
FORGED_RESULT = "siem-xdr: action=deadbeef type=block_ip target=1.1.1.1 status=success detail="


@pytest.mark.parametrize("forged", [FORGED_PROC, FORGED_RESULT])
def test_forged_telemetry_in_user_agent_is_still_a_web_attack(engine, enricher, forged):
    line = ('203.0.113.9 - - [28/Sep/2026:15:31:34 +0000] "GET /p?id=1%20union%20select%201,2 HTTP/1.1" 200 5 "-" '
            f'"x {forged}"')
    raw = wz(full_log=line, decoder={"name": "web-accesslog"}, location="/usr/local/apache2/logs/access_log")
    doc = normalize(raw)
    assert get(doc, "event.category") == "web" and get(doc, "event.action") == "http_request"
    assert get(doc, "source.ip") == "203.0.113.9" and get(doc, "process.pid") is None
    ids = fired(engine, enricher, [raw])
    assert "WEB-001" in ids and "LNX-002" not in ids


def test_forged_telemetry_in_ssh_username_is_not_a_process(engine, enricher):
    full = (f"Sep 28 15:31:34 demo-web sshd[812]: Invalid user {FORGED_PROC} from 203.0.113.9 port 51234")
    raw = wz(full_log=full, location="/var/log/auth.log", decoder={"name": "sshd"})
    doc = normalize(raw)
    assert get(doc, "event.category") != "process" and get(doc, "process.pid") != 7
    assert "LNX-002" not in fired(engine, enricher, [raw])


@pytest.mark.parametrize("location,full", [
    ("/var/log/syslog", "ossec: output: 'siem-procs': " + FORGED_PROC),           # đúng định dạng, sai nguồn
    ("/var/log/syslog", RESULT_LINE),
    # script active response khác của Wazuh ghi cả alert (có thể chứa dữ liệu kẻ tấn công) vào cùng file kết quả
    ("/var/ossec/logs/active-responses.log",
     '2026/09/28 15:42:01 active-response/bin/firewall-drop: {"parameters":{"alert":{"full_log":"x '
     + RESULT_LINE[20:] + '"}}}'),
])
def test_telemetry_lines_only_trusted_from_their_own_source(location, full):
    doc = normalize(wz(full_log=full, location=location))
    assert get(doc, "event.action") not in ("response_result", "process_created")
    assert get(doc, "siem.action") is None and get(doc, "event.category") != "process"


def test_siem_procs_without_alias_uses_command_path():
    full = "ossec: output: '/usr/local/sbin/siem-procs': " + FORGED_PROC
    doc = normalize(wz(full_log=full, location="/usr/local/sbin/siem-procs"))
    assert get(doc, "event.category") == "process" and get(doc, "process.pid") == 7


def test_auditd_execve_and_sca_and_auth():
    doc = normalize(wz(location="/var/log/audit/audit.log", decoder={"name": "auditd"}, data={"audit": {
        "type": "EXECVE", "syscall": "59", "exe": "/usr/bin/curl", "command": "curl", "pid": "77", "ppid": "70",
        "auid": "1000", "execve": {"a0": "curl", "a1": "http://x/s.sh"}}}))
    assert get(doc, "event.module") == "auditd" and get(doc, "process.name") == "curl"
    assert get(doc, "process.command_line") == "curl http://x/s.sh" and get(doc, "process.parent.pid") == 70

    doc = normalize(wz(location="sca", data={"sca": {"type": "check", "policy": "CIS Debian 13",
                                                     "check": {"id": "7001", "title": "Ensure X", "result": "failed"}}}))
    assert get(doc, "event.module") == "sca" and get(doc, "sca.check.result") == "failed"

    line = "Sep 28 15:40:01 ubuntu-01 sshd[1234]: Failed password for root from 198.51.100.7 port 51000 ssh2"
    doc = normalize(wz(full_log=line, location="/var/log/auth.log", decoder={"name": "sshd"}))
    assert get(doc, "event.action") == "ssh_login" and get(doc, "event.outcome") == "failure"
    assert get(doc, "source.ip") == "198.51.100.7" and get(doc, "host.name") == "ubuntu-01"


def test_garbage_wazuh_event_does_not_crash():
    for data in ({}, {"agent": "x", "data": [], "syscheck": "y"}, {"full_log": 5, "location": None}):
        doc = normalize({"event_type": "wazuh", "source": "wazuh", "data": data})
        assert doc["event"]["category"]


# ------------------------------------------------------------------ cầu nối cảnh báo Wazuh
def test_bridge_selects_groups_and_levels():
    g = {"syscheck", "rootcheck"}                                                     # giới hạn nhóm bằng cấu hình
    assert bridge.should_bridge({"level": 7, "groups": ["ossec", "syscheck"]}, groups=g)
    assert not bridge.should_bridge({"level": 5, "groups": ["syscheck"]}, groups=g)   # dưới ngưỡng
    assert not bridge.should_bridge({"level": 7, "groups": ["sca"]}, groups=g)
    assert not bridge.should_bridge({"level": 10, "groups": ["sshd"]}, groups=g)
    assert bridge.should_bridge({"level": 12, "groups": ["web"]}, groups=g)           # rất nghiêm trọng: lấy hết
    assert [bridge.severity_for(x) for x in (3, 7, 10, 12)] == ["low", "medium", "high", "critical"]


def test_any_group_level7_bridged_by_default():
    assert bridge.should_bridge({"id": "60122", "level": 10, "groups": ["windows", "authentication_failures"]})
    assert bridge.should_bridge({"id": "5710", "level": 7, "groups": ["sshd"]})


def test_sca_not_bridged_by_default():
    sca = {"id": "19007", "level": 7, "groups": ["sca"]}
    assert not bridge.should_bridge(sca) and not bridge.should_bridge({**sca, "level": 12})
    assert bridge.should_bridge(sca, exclude_groups=set())
    assert bridge.should_bridge({"id": "100500", "level": 7, "groups": ["sca"]})      # rule tự viết luôn chuyển


def test_level6_not_bridged():
    assert not bridge.should_bridge({"id": "31101", "level": 5, "groups": ["web"]})
    assert bridge.should_bridge({"id": "100200", "level": 3, "groups": ["web"]})     # rule tự viết: luôn chuyển


def test_shadow_group_marks_alert_shadow(enricher):
    raw = wz("wazuh_alert", location="syscheck", rule={
        "id": "104001", "level": 10, "description": "x", "groups": ["siem", "web", "shadow", "legacy_WEB-001"]})
    a = bridge.to_alert(enricher.enrich(normalize(raw)))
    assert a["alert"]["shadow"] is True and a["rule"]["mode"] == "shadow" and a["rule"]["legacy_id"] == "WEB-001"
    assert a["rule"]["id"] == "WZH-104001" and a["rule"]["groups"] == ["siem", "web", "shadow", "legacy_WEB-001"]


def test_non_shadow_wazuh_alert_is_active(enricher):
    raw = wz("wazuh_alert", rule={"id": "5710", "level": 8, "description": "x", "groups": ["sshd"]})
    a = bridge.to_alert(enricher.enrich(normalize(raw)))
    assert not get(a, "alert.shadow") and a["rule"]["legacy_id"] is None and a["rule"]["groups"] == ["sshd"]


def test_same_rule_same_source_suppressed_60s():
    s = bridge.Suppressor(60)
    assert not s.seen(("WZH-104001", "203.0.113.5"), 0) and s.seen(("WZH-104001", "203.0.113.5"), 30)
    assert not s.seen(("WZH-104001", "198.51.100.7"), 30) and not s.seen(("WZH-104001", "203.0.113.5"), 61)
    s.seen(("x", "y"), 1000)
    assert len(s._seen) == 1                       # khóa quá hạn bị xóa, bộ nhớ không phình


def test_bridge_alert_document(enricher):
    raw = wz("wazuh_alert", location="syscheck", syscheck={"path": "/var/www/html/x.php", "event": "added"},
             rule={"id": "100100", "level": 10, "description": "File mới trong thư mục web", "groups": ["syscheck", "web"],
                   "mitre": {"id": ["T1505.003"], "tactic": ["Persistence"]}})
    alert = bridge.to_alert(enricher.enrich(normalize(raw)))
    assert alert["rule"]["id"] == "WZH-100100" and alert["severity"] == "high" and alert["alert"]["source"] == "wazuh"
    assert alert["rule"]["mitre"] == {"tactic": "Persistence", "technique": ["T1505.003"]}
    assert alert["file"]["path"] == "/var/www/html/x.php" and alert["agent"]["id"] == "001"
    archived = normalize(wz(location="syscheck", syscheck={"path": "/var/www/html/x.php", "event": "added"}))
    assert alert["related_events"] == [get(archived, "event.id")]       # trỏ đúng event bản archives
    assert bridge.to_alert(enricher.enrich(normalize(wz("wazuh_alert", rule={"id": "5402", "level": 3})))) is None


def test_analyzer_does_not_store_wazuh_alert_twice(enricher, engine):
    from siem.analyzer import Analyzer
    an = Analyzer.__new__(Analyzer)
    an.enricher, an.engine, an.detector, an.buffer, an.stats = enricher, engine, None, [], {"events": 0, "alerts": 0}
    emitted = []
    an.emit = emitted.append
    an.suppressor = bridge.Suppressor(60)
    # file không thuộc FIM-001 (rule đó chạy chính thức thì cảnh báo 550 của /etc/passwd không chuyển nữa: test_fim_rules.py)
    an.handle(wz("wazuh_alert", location="syscheck", syscheck={"path": "/etc/hostname", "event": "modified"},
                 rule={"id": "550", "level": 7, "description": "Integrity checksum changed.", "groups": ["syscheck"]}))
    assert an.buffer == [] and [a["rule"]["id"] for a in emitted] == ["WZH-550"]
    an.handle(wz(full_log="x", location="/var/log/syslog"))
    assert len(an.buffer) == 1


def test_analyzer_acknowledges_kafka_only_after_events_are_stored(enricher, engine, monkeypatch):
    """Offset Kafka chỉ được xác nhận khi event đã nằm trong ES: ES lỗi -> không xác nhận -> lần sau đọc lại."""
    from siem import analyzer as mod

    class Stream:
        acked = 0

        def done(self):
            self.acked += 1

    class Producer:
        def flush(self, _t):
            return 0
    an = mod.Analyzer.__new__(mod.Analyzer)
    an.enricher, an.engine, an.detector, an.buffer, an.stats = enricher, engine, None, [], {"events": 0, "alerts": 0}
    an.stream, an.producer, an.es, an.last_rules_check = Stream(), Producer(), None, 10 ** 12
    an.last_flush = 0
    an.emit = lambda a: None
    calls = []

    def bulk(es, docs):
        calls.append(len(docs))
        if len(calls) == 1:
            raise ConnectionError("ES tạm lỗi")
        return len(docs)
    monkeypatch.setattr(mod.store, "bulk_index", bulk)
    monkeypatch.setattr(mod.time, "sleep", lambda s: None)
    an.handle(wz(full_log="x", location="/var/log/syslog"))
    an.tick()
    assert calls == [1] and an.stream.acked == 0 and len(an.buffer) == 1      # ES lỗi: giữ bộ đệm, chưa xác nhận
    an.tick()
    assert calls == [1, 1] and an.stream.acked == 1 and an.buffer == []       # ghi xong mới xác nhận


def test_case_playbooks_have_titled_tasks():
    """Mỗi task phải có title: chuỗi có ': ' trong YAML thành mapping -> SOAR lỗi khi tạo case (đã gặp với PB-08)."""
    data = yaml.safe_load((ROOT / "config" / "case_playbooks.yml").read_text(encoding="utf-8"))
    for pb in data["playbooks"]:
        for ph in pb["phases"]:
            for t in ph["tasks"]:
                assert isinstance(t, str) or "title" in t, (pb["id"], t)


# ------------------------------------------------------------------ SOAR -> Wazuh API
class FakeAPI:
    def __init__(self, failed_for=(), agents=()):
        self.calls, self.failed_for, self._agents = [], set(failed_for), list(agents)

    def active_response(self, agent_id, arguments, script):
        self.calls.append((agent_id, arguments, script))
        if agent_id in self.failed_for:
            return {"data": {"affected_items": [], "failed_items": [{"error": {"message": "Agent is not active"}}]}}
        return {"data": {"affected_items": [agent_id], "failed_items": []}}

    def agents(self):
        return self._agents


class FakeES:
    def __init__(self):
        self.updates, self.deleted_query = [], None
        self.docs = {"002": {"platform": "windows"}}

    def update(self, index, id, doc, **kw):
        self.updates.append((index, id, doc))

    def get(self, index, id):
        if id not in self.docs:
            raise KeyError(id)
        return {"_source": self.docs[id]}

    def delete_by_query(self, index, query, **kw):
        self.deleted_query = query


@pytest.fixture()
def actions(monkeypatch):
    acts = {
        "a" * 32: {"id": "a" * 32, "agent_id": "001", "type": "block_ip", "params": {"ip": "203.0.113.9"}},
        "b" * 32: {"id": "b" * 32, "agent_id": "002", "type": "kill_process", "params": {"pid": 4242}},
        "c" * 32: {"id": "c" * 32, "agent_id": "003", "type": "isolate_host", "params": {}},
        "d" * 32: {"id": "d" * 32, "agent_id": "001", "type": "block_ip", "params": {"ip": "1.2.3.4; rm -rf /"}},
    }
    for a in acts.values():
        a["status"] = "pending"
    finished = {}
    monkeypatch.setattr(store, "claim_pending_actions",
                        lambda es, agent_id=None: [dict(a) for a in acts.values() if a["status"] == "pending"])
    monkeypatch.setattr(store, "finish_action", lambda es, i, aid, st, out: acts[i]["agent_id"] == aid and
                        finished.__setitem__(i, (st, out)) is None)
    return acts, finished


def test_dispatch_sends_validated_commands(actions):
    acts, finished = actions
    api, es = FakeAPI(failed_for={"003"}), FakeES()
    sent = soar_wazuh.Responder(es, api).dispatch()
    assert sent == 2
    assert ("001", ["block_ip", "203.0.113.9", "a" * 32], "siem-xdr") in api.calls
    assert ("002", ["kill_process", "4242", "b" * 32], "siem-xdr.cmd") in api.calls     # agent Windows
    assert finished["c" * 32][0] == "failed" and "not active" in finished["c" * 32][1]   # Wazuh từ chối
    assert finished["d" * 32][0] == "failed" and not any(c[1][2] == "d" * 32 for c in api.calls)  # IP bẩn: không gửi


def test_collect_results_only_from_same_agent(monkeypatch):
    waiting = [{"id": "a" * 32, "agent_id": "001", "status": "sent"}, {"id": "b" * 32, "agent_id": "002", "status": "sent"}]
    events = [{"agent": {"id": "001"}, "siem": {"action": {"id": "a" * 32, "status": "success", "output": "đã chặn"}}},
              # agent 001 cố báo kết quả cho lệnh của agent 002 -> bị bỏ qua
              {"agent": {"id": "001"}, "siem": {"action": {"id": "b" * 32, "status": "success", "output": "giả"}}}]
    monkeypatch.setattr(store, "search", lambda es, index, q=None, **kw: waiting if index == settings.IDX_ACTIONS else events)
    done = {}
    monkeypatch.setattr(store, "finish_action", lambda es, i, aid, st, out: (next(w for w in waiting if w["id"] == i)
                                                                            ["agent_id"] == aid) and done.setdefault(i, st))
    assert soar_wazuh.Responder(FakeES(), FakeAPI()).collect_results() == 1
    assert done == {"a" * 32: "success"}


def test_sync_agents_and_status(monkeypatch):
    rows = {}
    monkeypatch.setattr(store, "upsert_agent", lambda es, info, ip: rows.__setitem__(info["agent_id"], info | {"ip": ip}))
    api = FakeAPI(agents=[{"id": "000", "name": "wazuh-manager", "status": "active"},
                          {"id": "001", "name": "demo-web", "ip": "172.18.0.8", "status": "active", "version": "Wazuh v4.14.7",
                           "os": {"name": "Debian GNU/Linux", "version": "13", "platform": "debian"},
                           "lastKeepAlive": "2026-09-28T15:34:47+00:00"},
                          {"id": "002", "name": "PC-01", "status": "disconnected", "os": {"platform": "windows"}}])
    es = FakeES()
    r = soar_wazuh.Responder(es, api)
    assert r.sync_agents() == 2 and set(rows) == {"001", "002"}                   # bỏ 000 (chính manager)
    assert rows["001"]["os"] == "Debian GNU/Linux 13" and rows["001"]["platform"] == "debian"
    assert es.deleted_query == {"bool": {"must_not": [{"terms": {"agent_id": ["001", "002"]}}]}}   # xóa agent cũ
    assert r.platforms["002"] == "windows"


def test_soar_no_endpoint_action_for_syslog_source(monkeypatch):
    """Alert từ log syslog (firewall) mang agent.id giả syslog-<ip>: không có agent để kill / cô lập / chặn tại chỗ."""
    from siem.soar.engine import Soar
    created = []
    monkeypatch.setattr(store, "create_action", lambda *a, **kw: created.append(a) or {"id": "x"})
    soar = Soar(FakeES(), [], whitelist=[])
    alert = {"alert": {"id": "a"}, "agent": {"id": "syslog-192.168.1.1"}, "source": {"ip": "203.0.113.5"},
             "process": {"pid": 5}}
    assert soar.run_step({"action": "kill_process"}, alert)["status"] == "skipped"
    assert soar.run_step({"action": "block_ip", "scope": "origin"}, alert)["status"] == "skipped"
    # sự kiện đăng nhập của chính SOC console (agent.id soc-console): cũng không có agent nào
    console = alert | {"agent": {"id": "soc-console"}}
    assert soar.run_step({"action": "isolate_host"}, console)["status"] == "skipped"
    assert soar.run_step({"action": "block_ip", "scope": "origin"}, console)["status"] == "skipped"
    assert created == []


def test_soar_auto_kill_only_by_pid(monkeypatch):
    """Tự kill theo tên giết mọi tiến trình cùng tên (vd httpd -> sập web): chỉ tự kill khi alert có PID."""
    from siem.soar.engine import Soar
    created = []
    monkeypatch.setattr(store, "create_action", lambda es, aid, t, p, **kw: created.append((aid, t, p)) or {"id": "x"})
    soar = Soar(FakeES(), [], whitelist=[])
    no_pid = {"alert": {"id": "a"}, "agent": {"id": "001"}, "process": {"name": "httpd"}}
    assert soar.run_step({"action": "kill_process"}, no_pid)["status"] == "skipped"
    with_pid = {"alert": {"id": "b"}, "agent": {"id": "001"}, "process": {"name": "sh", "pid": 4242}}
    assert soar.run_step({"action": "kill_process"}, with_pid)["status"] == "queued"
    # kèm tên trong alert để agent không kill PID đã được cấp lại; tên có ký tự lạ thì không gửi (kill như trước)
    odd_name = {"alert": {"id": "c"}, "agent": {"id": "001"}, "process": {"name": "php-fpm: pool", "pid": 77}}
    assert soar.run_step({"action": "kill_process"}, odd_name)["status"] == "queued"
    assert created == [("001", "kill_process", {"pid": 4242, "expect": "sh"}), ("001", "kill_process", {"pid": 77})]


def test_soar_auto_kill_rate_limited_per_agent(monkeypatch):
    """Alert giả / báo nhầm hàng loạt không được biến SOAR thành công cụ kill dần mọi tiến trình trên một máy."""
    from siem.soar.engine import AUTO_KILL_WINDOW_SECONDS, Soar
    created, t = [], [0.0]
    monkeypatch.setattr(store, "create_action", lambda es, aid, typ, p, **kw: created.append(aid) or {"id": "x"})
    soar = Soar(FakeES(), [], whitelist=[], max_auto_kills=2, clock=lambda: t[0])
    kill = lambda agent, pid: soar.run_step({"action": "kill_process"}, {   # noqa: E731
        "alert": {"id": f"a{pid}"}, "agent": {"id": agent}, "process": {"name": "sh", "pid": pid}})
    assert [kill("001", p)["status"] for p in (11, 12, 13)] == ["queued", "queued", "skipped"]
    assert "analyst" in kill("001", 14)["detail"]
    assert kill("002", 21)["status"] == "queued"                            # agent khác: đếm riêng
    t[0] = AUTO_KILL_WINDOW_SECONDS + 1
    assert kill("001", 15)["status"] == "queued"                            # hết cửa sổ: tự kill lại được
    assert created == ["001", "001", "002", "001"]
    assert Soar(FakeES(), [], whitelist=[]).max_auto_kills == 0             # mặc định không giới hạn


def _es_match(doc, q):
    """Đánh giá tối giản query Elasticsearch (term / terms / range / exists / bool filter+should+must_not)."""
    if "bool" in q:
        b = q["bool"]
        ok = all(_es_match(doc, c) for c in b.get("filter", [])) and not any(_es_match(doc, c) for c in b.get("must_not", []))
        if b.get("should"):
            ok = ok and sum(_es_match(doc, c) for c in b["should"]) >= b.get("minimum_should_match", 1)
        return ok
    (kind, spec), = q.items()
    if kind == "exists":
        return doc.get(spec["field"]) is not None
    (field, val), = spec.items()
    v = doc.get(field)
    if kind == "term":
        return v == val
    if kind == "terms":
        return v in val
    if kind == "range":
        return v is not None and all({"gt": v > x, "gte": v >= x, "lt": v < x, "lte": v <= x}[op] for op, x in val.items())
    raise AssertionError(kind)


def test_expired_block_is_retried_until_unblock_succeeds(monkeypatch):
    """Hết hạn chặn -> tạo lệnh gỡ; chưa gỡ được thì 15 phút sau tạo lại (trước đây đánh dấu đã gỡ ngay, lệnh gỡ lỗi
    là IP bị chặn mãi)."""
    from datetime import datetime, timedelta, timezone
    from siem.soar import engine as eng
    now = datetime.now(timezone.utc)
    block = {"_id": "blk", "agent_id": "001", "type": "block_ip", "target": "203.0.113.9", "status": "success",
             "reverted": False, "created_at": (now - timedelta(hours=2)).isoformat(),
             "expires_at": (now - timedelta(hours=1)).isoformat()}
    unblocks = []

    class ES:
        def update(self, index, id, doc, **kw):
            block.update(doc)
    monkeypatch.setattr(store, "search", lambda es, index, query=None, **kw: [block] if _es_match(block, query) else [])
    monkeypatch.setattr(store, "create_action", lambda es, aid, t, p, **kw: unblocks.append((aid, t, p)) or {"id": "u"})
    soar = eng.Soar(ES(), [], whitelist=[])
    soar.housekeeping()
    assert unblocks == [("001", "unblock_ip", {"ip": "203.0.113.9"})] and block["reverted"] is False
    soar.housekeeping()
    assert len(unblocks) == 1                                   # vừa yêu cầu gỡ: chờ kết quả, không gửi trùng
    block["revert_requested_at"] = (now - timedelta(minutes=eng.REVERT_RETRY_MINUTES + 1)).isoformat()
    soar.housekeeping()
    assert len(unblocks) == 2                                   # lệnh gỡ lần trước không thành công -> thử lại


def test_already_blocked_ignores_stale_permanent_block(monkeypatch):
    """Lệnh chặn thành công từ lâu, không có hạn: iptables có thể đã mất khi agent khởi động lại -> chặn lại."""
    from datetime import datetime, timedelta, timezone
    from siem.soar.engine import Soar
    now = datetime.now(timezone.utc)
    iso = lambda **kw: (now + timedelta(**kw)).isoformat()   # noqa: E731
    base = {"agent_id": "001", "type": "block_ip", "target": "172.18.0.1", "reverted": False}
    docs = []
    monkeypatch.setattr(store, "search", lambda es, index, query=None, **kw: [d for d in docs if _es_match(d, query)])
    soar = Soar(FakeES(), [], whitelist=[])
    docs[:] = [{**base, "status": "success", "created_at": iso(days=-2), "expires_at": None}]
    assert not soar._active_block("001", "172.18.0.1")                     # cũ, không hạn -> chặn lại
    docs[:] = [{**base, "status": "success", "created_at": iso(minutes=-3), "expires_at": None}]
    assert soar._active_block("001", "172.18.0.1")                         # vừa chặn xong
    docs[:] = [{**base, "status": "success", "created_at": iso(hours=-2), "expires_at": iso(hours=20)}]
    assert soar._active_block("001", "172.18.0.1")                         # chặn có hạn, còn hạn
    docs[:] = [{**base, "status": "sent", "created_at": iso(hours=-2), "expires_at": None}]
    assert soar._active_block("001", "172.18.0.1")                         # đang chờ agent báo kết quả
    docs[:] = [{**base, "status": "success", "created_at": iso(minutes=-1), "expires_at": None, "reverted": True}]
    assert not soar._active_block("001", "172.18.0.1")                     # đã gỡ
    docs[:] = [{**base, "status": "success", "created_at": iso(minutes=-3), "expires_at": iso(minutes=-1),
                "revert_requested_at": iso(seconds=-20)}]
    assert not soar._active_block("001", "172.18.0.1")                     # hết hạn, lệnh gỡ đang chạy


# ------------------------------------------------------------------ SOAR: gia hạn chặn, gỡ chặn, gom case, thông báo
class SoarES:
    """ES giả cho SOAR: lệnh phản ứng nằm trong `docs` (store.search / create_action được thay bằng bản đọc-ghi
    `docs`), update theo doc thì ghi vào đúng bản ghi, mọi lệnh gọi được lưu lại để kiểm tra."""

    def __init__(self, docs):
        self.docs, self.calls = docs, []

    def index(self, index, id, document, **kw):
        self.calls.append(("index", index, id, document, kw))

    def update(self, index, id, doc=None, **kw):
        self.calls.append(("update", index, id, doc, kw))
        for d in self.docs:
            if doc is not None and d.get("_id") == id:
                d.update(doc)


@pytest.fixture()
def soar_env(monkeypatch):
    from datetime import datetime, timezone
    docs = []

    def create_action(es, agent_id, typ, params, **kw):
        d = {"_id": f"act{len(docs)}", "id": f"act{len(docs)}", "agent_id": agent_id, "type": typ, "params": params,
             "target": str(params.get("ip")), "status": "pending", "reverted": False,
             "created_at": datetime.now(timezone.utc).isoformat(), "expires_at": kw.get("expires_at")}
        docs.append(d)
        return d
    monkeypatch.setattr(store, "search", lambda es, index, query=None, **kw:
                        [d for d in docs if index == settings.IDX_ACTIONS and _es_match(d, query)])
    monkeypatch.setattr(store, "create_action", create_action)
    monkeypatch.setattr(store, "list_agents", lambda es: [{"agent_id": "001", "status": "online"}])
    return docs, SoarES(docs)


def _auth_alert(rule_id, severity, score, ip="203.0.113.50"):
    return {"alert": {"id": f"al-{rule_id}", "source": "rule"}, "rule": {"id": rule_id, "name": rule_id},
            "severity": severity, "severity_score": score, "source": {"ip": ip}, "agent": {"id": "001"}, "message": "x"}


def test_longer_block_extends_shorter_one(soar_env):
    """AUTH-001 chặn 1 giờ rồi AUTH-002 (đăng nhập thành công sau dò mật khẩu, playbook chặn 24 giờ) cùng IP: trước
    đây lần chặn 24 giờ bị bỏ qua vì "đã chặn sẵn", IP được gỡ sau 1 giờ."""
    from datetime import datetime, timedelta, timezone
    from siem.soar.engine import Soar, load_playbooks
    docs, es = soar_env
    soar = Soar(es, load_playbooks(ROOT / "config" / "playbooks.yml"), whitelist=[])
    soar.create_case = lambda alert: {"status": "created"}
    block = lambda res: next(r for r in res if r["action"] == "block_ip")   # noqa: E731
    left = lambda: datetime.fromisoformat(docs[0]["expires_at"]) - datetime.now(timezone.utc)   # noqa: E731

    assert block(soar.handle(_auth_alert("AUTH-001", "high", 3)))["status"] == "queued"
    docs[0]["status"] = "success"
    r = block(soar.handle(_auth_alert("AUTH-002", "critical", 4)))
    assert r["status"] == "extended" and "gia hạn" in r["detail"] and len(docs) == 1   # không gửi lệnh chặn mới
    assert left() > timedelta(hours=23)
    ext, = [c for c in es.calls if c[1] == settings.IDX_ACTIONS]
    assert ext[3] == {"expires_at": docs[0]["expires_at"]} and ext[4]["refresh"] == "wait_for"   # giữ updated_at
    r = block(soar.handle(_auth_alert("AUTH-001", "high", 3)))                       # chặn ngắn hơn: giữ hạn 24 giờ
    assert r["status"] == "skipped" and left() > timedelta(hours=23)
    alert_status = [c[3]["alert"]["status"] for c in es.calls if c[1] == settings.IDX_ALERTS]
    assert alert_status == ["in_progress", "in_progress", "open"]                    # gia hạn cũng là đã phản ứng


def test_permanent_block_extends_and_stays_permanent(soar_env):
    from siem.soar.engine import Soar
    docs, es = soar_env
    soar = Soar(es, [], whitelist=[])
    alert = _auth_alert("X", "high", 3)
    assert soar.block_ip({"duration": 3600}, alert)["status"] == "queued"
    docs[0]["status"] = "success"
    assert soar.block_ip({"duration": 0}, alert)["status"] == "extended" and docs[0]["expires_at"] is None
    assert soar.block_ip({"duration": 86400}, alert)["status"] == "skipped" and docs[0]["expires_at"] is None


def test_unblock_marks_only_blocks_created_before_it():
    """Hết hạn -> SOAR tạo lệnh gỡ; IP tấn công lại ngay -> lệnh chặn mới (gửi SAU lệnh gỡ, luật còn trên agent). Trước
    đây lệnh gỡ thành công đánh dấu cả lệnh chặn mới là đã gỡ -> housekeeping không bao giờ gỡ nó: chặn vĩnh viễn."""
    unblock = {"id": "u1", "agent_id": "001", "type": "unblock_ip", "target": "203.0.113.50",
               "created_at": "2026-10-11T10:00:00+00:00"}
    blocks = [{"id": "old", "agent_id": "001", "type": "block_ip", "target": "203.0.113.50", "reverted": False,
               "created_at": "2026-10-11T09:00:00+00:00"},
              {"id": "new", "agent_id": "001", "type": "block_ip", "target": "203.0.113.50", "reverted": False,
               "created_at": "2026-10-11T10:00:05+00:00"}]

    class ES:
        def get(self, index, id):
            return {"_source": unblock}

        def update(self, index, id, doc, **kw):
            unblock.update(doc)

        def update_by_query(self, index, query, script, **kw):
            for b in blocks:
                if _es_match(b, query):
                    b["reverted"] = True
    assert store.finish_action(ES(), "u1", "001", "success", "đã gỡ chặn")
    assert {b["id"]: b["reverted"] for b in blocks} == {"old": True, "new": False}


def test_case_merge_adds_alert_atomically_on_es(monkeypatch):
    """Gom alert vào case bằng script trên ES (thêm vào bản mới nhất, bỏ qua alert đã có), không ghi đè alert_ids bằng
    danh sách đọc từ search (trễ tới 1 giây -> alert dồn dập ghi đè nhau, mất khỏi case)."""
    from siem.soar.engine import CASE_ADD_ALERT, Soar
    monkeypatch.setattr(store, "search", lambda es, index, query=None, **kw: [{"_id": "c1", "alert_ids": ["a0"]}])
    es = SoarES([])
    res = Soar(es, [], whitelist=[]).create_case({"alert": {"id": "a1"}, "rule": {"id": "AUTH-001"},
                                                  "source": {"ip": "203.0.113.50"}})
    assert res == {"status": "updated", "case_id": "c1"}
    (kind, index, case_id, doc, kw), = es.calls
    assert index == settings.IDX_CASES and case_id == "c1" and doc is None
    assert kw["script"]["source"] == CASE_ADD_ALERT and kw["script"]["params"]["id"] == "a1"
    assert kw["retry_on_conflict"] >= 3 and "contains(params.id)" in CASE_ADD_ALERT


def test_notify_and_case_run_once_per_alert(soar_env):
    """LNX-002 (critical) khớp playbook "Diệt tiến trình" VÀ "Cảnh báo chung mức critical": trước đây thông báo 2 lần."""
    from siem.soar.engine import Soar, load_playbooks
    docs, es = soar_env
    soar = Soar(es, load_playbooks(ROOT / "config" / "playbooks.yml"), whitelist=[])
    soar.create_case = lambda alert: {"status": "created"}
    res = soar.handle({"alert": {"id": "a1", "source": "rule"}, "rule": {"id": "LNX-002", "name": "x"},
                       "severity": "critical", "severity_score": 4, "agent": {"id": "001"},
                       "process": {"pid": 4242, "name": "sh"}, "message": "x"})
    notify = [r for r in res if r["action"] == "notify"]
    assert [r["status"] for r in notify] == ["logged", "skipped"] and "playbook trước" in notify[1]["detail"]
    assert sum(r["action"] == "create_case" and r["status"] == "created" for r in res) == 1


def test_notifier_cooldown_merges_same_rule_and_entity(monkeypatch):
    from siem.soar.engine import Notifier
    sent, t = [], [0.0]
    monkeypatch.setattr(Notifier, "_post", staticmethod(lambda url, payload: sent.append(payload["text"])))
    n = Notifier(webhook="http://hook.invalid", cooldown=300, clock=lambda: t[0])
    a = lambda ip: {"rule": {"id": "WIN-006"}, "source": {"ip": ip}, "message": "m"}   # noqa: E731
    assert n.send(a("10.0.0.5"))["status"] == "sent"
    t[0] = 10
    assert n.send(a("10.0.0.5"))["status"] == "throttled"
    assert n.send(a("10.0.0.5"))["status"] == "throttled"
    assert n.send(a("10.0.0.6"))["status"] == "sent"                   # thực thể khác: gửi
    t[0] = 400
    assert n.send(a("10.0.0.5"))["status"] == "sent" and "+2 cảnh báo" in sent[-1]
    assert Notifier(webhook="http://hook.invalid").send(a("10.0.0.5"))["status"] == "sent"   # mặc định không giới hạn


def test_ar_arguments_validation():
    ok = soar_wazuh.ar_arguments({"id": "x", "type": "kill_process", "params": {"name": "xmrig"}})
    assert ok == ["kill_process", "xmrig", "x"]
    ok = soar_wazuh.ar_arguments({"id": "x", "type": "kill_process", "params": {"pid": 947, "expect": "sh"}})
    assert ok == ["kill_process", "947", "x", "sh"]                         # tham số 4: tên tiến trình mong đợi
    for bad in ({"type": "kill_process", "params": {"name": "a b"}}, {"type": "block_ip", "params": {"ip": "$(id)"}},
                {"type": "format_disk", "params": {}},
                {"type": "kill_process", "params": {"pid": 947, "expect": "sh; reboot"}},
                {"type": "kill_process", "params": {"name": "xmrig", "expect": "xmrig"}}):   # expect chỉ đi với PID
        with pytest.raises(ValueError):
            soar_wazuh.ar_arguments({"id": "x", **bad})
