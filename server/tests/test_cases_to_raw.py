"""Bộ đổi ca ECS (server/rules/cases) sang log gốc (tools/cases_to_raw.py): từng loại log + cả bộ."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import cases_to_raw as c2r  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]


def test_apache_line():
    doc = {"@timestamp": "2026-01-05T09:00:00+00:00", "source": {"ip": "203.0.113.50"},
           "http": {"request": {"method": "GET"}, "version": "1.1", "response": {"status_code": 404, "bytes": 512}},
           "url": {"original": "/p.php?id=1%27"}, "user_agent": {"original": "curl/8"}}
    assert c2r.apache_line(doc) == ('203.0.113.50 - - [05/Jan/2026:09:00:00 +0000] "GET /p.php?id=1%27 HTTP/1.1" '
                                    '404 512 "-" "curl/8"')


def test_auth_lines():
    fail = {"event": {"category": "authentication", "outcome": "failure"}, "source": {"ip": "203.0.113.7"},
            "user": {"name": "admin"}}
    assert c2r.auth_line(fail) == "Oct 31 10:00:00 host sshd[1234]: Failed password for admin from 203.0.113.7 port 4444 ssh2"
    ok = {"event": {"category": "authentication", "outcome": "success"}, "source": {"ip": "10.0.0.5"},
          "user": {"name": "root"}}
    assert c2r.auth_line(ok).endswith("Accepted password for root from 10.0.0.5 port 4444 ssh2")
    add = {"event": {"category": "iam", "action": "user_created"}, "user": {"name": "backdoor"}}
    assert c2r.auth_line(add) == ("Oct 31 10:00:00 host useradd[1234]: new user: name=backdoor, UID=1001, GID=1001, "
                                  "home=/home/backdoor, shell=/bin/bash")
    sudo = {"event": {"action": "sudo"}, "user": {"name": "deploy"}, "process": {"command_line": "/bin/bash"}}
    assert c2r.auth_line(sudo) == ("Oct 31 10:00:00 host sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; "
                                   "COMMAND=/bin/bash")


def test_filterlog_line():
    doc = {"event": {"action": "deny"}, "source": {"ip": "203.0.113.10"}, "destination": {"ip": "10.0.0.5", "port": 22}}
    assert c2r.filterlog_line(doc) == ("Oct 31 10:00:00 pfsense filterlog[1234]: 5,,,1000000103,em0,match,block,in,4,0x0,,"
                                       "64,12345,0,none,6,tcp,60,203.0.113.10,10.0.0.5,50000,22,0,S,123456,,64240,,mss")
    assert ",pass," in c2r.filterlog_line({**doc, "event": {"action": "allow"}})


def test_filterlog_line_parses_with_the_repo_parser():
    """Dòng sinh ra phải qua đúng parse_firewall của pipeline, nếu không ca không còn giống log thật."""
    from siem.pipeline.normalize import parse_firewall
    doc = {"event": {"action": "deny"}, "source": {"ip": "203.0.113.10"}, "destination": {"ip": "10.0.0.5", "port": 22}}
    out: dict = {}
    assert parse_firewall(c2r.filterlog_line(doc).split(": ", 1)[1], out)
    assert out["source"]["ip"] == "203.0.113.10" and out["destination"]["port"] == 22 and out["event"]["action"] == "deny"


def test_eve_line():
    doc = {"source": {"ip": "203.0.113.13"}, "suricata": {"severity": 1, "signature_id": 2010935}}
    ev = json.loads(c2r.eve_line(doc))
    assert ev["event_type"] == "alert" and ev["src_ip"] == "203.0.113.13"
    assert ev["alert"]["severity"] == 1 and ev["alert"]["signature_id"] == 2010935


def test_syscheck_event():
    doc = {"event": {"action": "file_modified"}, "file": {"path": "/root/.ssh/authorized_keys"}}
    assert c2r.syscheck_event(doc) == {"path": "/root/.ssh/authorized_keys", "type": "modified"}


def test_siem_proc_line_matches_normalize_regex():
    from siem.pipeline.normalize import _SIEM_PROC
    doc = {"process": {"name": "sh", "pid": 947, "command_line": "sh -c sleep 15", "parent": {"name": "httpd"}}}
    line = c2r.proc_line(doc)
    assert line == "ossec: output: 'siem-procs': siem-proc: pid=947 ppid=900 uid=0 name=sh parent=httpd exe=/usr/bin/sh cmd=sh -c sleep 15"
    m = _SIEM_PROC.match(line)
    assert m["name"] == "sh" and m["parent"] == "httpd" and m["cmd"] == "sh -c sleep 15"


def test_audit_line():
    line = c2r.audit_line({"process": {"name": "bash", "command_line": "bash -i"}}, 7)
    assert line.startswith("type=SYSCALL msg=audit(1767225600.007:7)") and 'exe="/usr/bin/bash"' in line
    assert "type=EXECVE" in line and 'a0="bash" a1="-i"' in line


def test_security_event_eventchannel():
    doc = {"event": {"code": 4625}, "source": {"ip": "203.0.113.20"}, "user": {"name": "administrator"}}
    raw = json.loads(c2r.windows_event(doc, 1))
    xml = raw["Event"]
    assert "<EventID>4625</EventID>" in xml and "<Channel>Security</Channel>" in xml
    assert "<Data Name='IpAddress'>203.0.113.20</Data>" in xml and "<Data Name='TargetUserName'>administrator</Data>" in xml
    assert "<EventRecordID>" in xml and raw["Message"]
    # Wazuh suy severityValue từ Keywords/Level: 4625 phải là audit thất bại, 1102 mức INFORMATION
    assert "<Keywords>0x8010000000000000</Keywords>" in xml
    assert "<Level>4</Level>" in json.loads(c2r.windows_event({"event": {"code": 1102}}, 2))["Event"]


def test_security_group_event_has_well_known_sid():
    doc = {"event": {"code": 4732}, "group": {"name": "Administrators"}, "user": {"name": "an"}}
    assert "<Data Name='TargetSid'>S-1-5-32-544</Data>" in json.loads(c2r.windows_event(doc, 1))["Event"]


def test_sysmon_event_for_windows_process():
    doc = {"event": {"category": "process"},
           "process": {"name": "powershell.exe", "command_line": "powershell.exe -enc AAAA", "parent": {"name": "winword.exe"}}}
    xml = json.loads(c2r.windows_event(doc, 1))["Event"]
    assert "<EventID>1</EventID>" in xml and "<Data Name='CommandLine'>powershell.exe -enc AAAA</Data>" in xml
    assert "<Data Name='ParentImage'>C:\\Windows\\System32\\winword.exe</Data>" in xml


def test_build_covers_all_rule_codes_and_shapes():
    cases, skipped = c2r.build(ROOT / "server/rules/cases")
    flat = [c for lst in cases.values() for c in lst]
    assert {"positive", "negative"} == {c["kind"] for c in flat}
    assert all("rule" not in c and "none" not in c and c["events"] for c in flat)
    codes = {c["legacy"] for c in flat} | set(skipped)
    assert len(codes) == 41 and "TI-001" in skipped
    assert set(cases) == {"auth", "fim", "linux", "network", "web", "windows"}
    web = [c for c in cases["web"] if c["legacy"] == "WEB-009" and c["kind"] == "positive"][0]
    assert len(web["events"]) == 300 and web["log_format"] == "apache"
