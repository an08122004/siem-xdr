"""Test đọc và gắn nhãn log endpoint ghi thật (Splunk attack_data, OTRF) — mẫu nhỏ theo đúng định dạng của hai bộ dữ liệu."""
from __future__ import annotations

import base64
import json
import zipfile

from siem.ai.endpoint_logs import (decoded, label_atomic_run, label_file, match_test, read_log, to_raw, tokens)
from siem.pipeline.normalize import get, normalize

NS = "xmlns='http://schemas.microsoft.com/win/2004/08/events/event'"


def sysmon1(guid, pguid, image, cmd, parent="C:\\Windows\\System32\\cmd.exe", pcmd="cmd.exe"):
    data = {"ProcessGuid": guid, "ParentProcessGuid": pguid, "ProcessId": "1", "Image": image, "CommandLine": cmd,
            "ParentImage": parent, "ParentCommandLine": pcmd, "User": "ATTACKRANGE\\Administrator"}
    body = "".join(f"<Data Name='{k}'>{v.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')}</Data>"
                   for k, v in data.items())
    return (f"<Event {NS}><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>1</EventID>"
            f"<TimeCreated SystemTime='2021-04-15T15:34:10Z'/><EventRecordID>7</EventRecordID>"
            f"<Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>win-dc</Computer></System>"
            f"<EventData>{body}</EventData></Event>")


def enc(ps: str) -> str:
    return base64.b64encode(ps.encode("utf-16-le")).decode()


def test_atomic_run_labels_attack_harness_and_background(tmp_path):
    """Con cháu của Invoke-AtomicTest (qua trình thực thi) là tấn công; whoami do công cụ tự gọi, cài đặt, WinRM là công cụ thử;
    dịch vụ hệ thống là nền. Sự kiện trải nhiều dòng vẫn đọc được."""
    PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    lines = [
        sysmon1("{W}", "{SVC}", "C:\\Windows\\System32\\WinrsHost.exe", "WinrsHost.exe -Embedding", "svchost.exe"),
        sysmon1("{P0}", "{W}", PS, "powershell -EncodedCommand " + enc('Invoke-AtomicTest "T1003.001" -GetPrereqs'), PS),
        sysmon1("{D}", "{P0}", "C:\\Windows\\System32\\curl.exe", "curl -o procdump.zip https://download.sysinternals.com"),
        sysmon1("{P1}", "{W}", PS, "powershell -EncodedCommand " + enc('Import-Module X; Invoke-AtomicTest "T1003.001"'), PS),
        sysmon1("{WH}", "{P1}", "C:\\Windows\\System32\\whoami.exe", "whoami", PS),
        sysmon1("{C}", "{P1}", "C:\\Windows\\System32\\cmd.exe", 'cmd.exe /c "procdump.exe -accepteula -ma lsass.exe x.dmp"', PS),
        sysmon1("{A}", "{C}", "C:\\AtomicRedTeam\\atomics\\T1003.001\\bin\\procdump.exe",
                "procdump.exe -accepteula\n-ma lsass.exe x.dmp"),           # dòng lệnh có xuống dòng -> XML nhiều dòng
        sysmon1("{H}", "{C}", "C:\\Windows\\System32\\conhost.exe", "conhost.exe 0xffffffff"),
        sysmon1("{B}", "{SVC}", "C:\\Windows\\System32\\svchost.exe", "svchost.exe -k netsvcs", "services.exe"),
    ]
    f = tmp_path / "windows-sysmon.log"
    f.write_text("\n".join(lines) + "\n", encoding="utf-8")
    procs = read_log(f)
    assert len(procs) == 9 and procs[6].cmd == "procdump.exe -accepteula\n-ma lsass.exe x.dmp"
    tags = {p.name: t for p, t in zip(procs, label_atomic_run(procs).values())}
    assert tags["procdump.exe"] == "attack" and tags["svchost.exe"] == "background"
    assert tags["whoami.exe"] == tags["curl.exe"] == tags["conhost.exe"] == tags["WinrsHost.exe"] == "harness"
    out = {p.name: (tag, guid) for p, tag, guid, _ in label_file(
        procs, [("g1", "Dump LSASS.exe Memory using ProcDump", tokens("procdump.exe -accepteula -ma lsass.exe x.dmp"))],
        "atomic")}
    assert out["procdump.exe"] == ("attack", "g1") and out["svchost.exe"][0] == "normal" and "curl.exe" not in out


def test_curated_file_without_harness_is_not_used_as_normal(tmp_path):
    f = tmp_path / "windows-security.log"
    f.write_text("\n".join([
        sysmon1("{R}", "{X}", "C:\\Windows\\System32\\rundll32.exe", "rundll32.exe C:\\windows\\System32\\comsvcs.dll MiniDump 840 l.dmp full"),
        sysmon1("{N}", "{X}", "C:\\Windows\\System32\\notepad.exe", "notepad.exe")]) + "\n", encoding="utf-8")
    tests = [("g2", "comsvcs", tokens("rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump $pid l.dmp full"))]
    out = {p.name: tag for p, tag, _, _ in label_file(read_log(f), tests, "atomic")}
    assert out == {"rundll32.exe": "attack", "notepad.exe": "scenario"}


def test_wineventlog_text_4688_and_auditd_and_otrf(tmp_path):
    txt = tmp_path / "windows-security.log"
    txt.write_text(
        "03/23/2021 01:40:45 PM\nLogName=Security\nSourceName=Microsoft Windows security auditing.\nEventCode=4688\n"
        "ComputerName=win-dc.attackrange.local\nRecordNumber=258296\nMessage=A new process has been created.\n\n"
        "Creator Subject:\n\tAccount Name:\t\tAdministrator\n\nProcess Information:\n\tNew Process ID:\t\t0x584\n"
        "\tNew Process Name:\tC:\\Windows\\System32\\rundll32.exe\n\tCreator Process ID:\t0xdb4\n"
        "\tCreator Process Name:\tC:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n"
        "\tProcess Command Line:\t\"C:\\Windows\\System32\\rundll32.exe\" comsvcs.dll MiniDump 840 x.dmp full\n\n"
        "Token Elevation Type indicates the type of token.\n", encoding="utf-8")
    [p] = read_log(txt)
    assert (p.source, p.name, p.pid, p.ppid) == ("4688", "rundll32.exe", "1412", "3508")
    doc = normalize(to_raw(p, {"dataset": "t"}, 1))
    assert get(doc, "process.name") == "rundll32.exe" and "MiniDump" in get(doc, "process.command_line")
    assert get(doc, "process.parent.name") == "powershell.exe"

    aud = tmp_path / "auditd.log"
    aud.write_text(
        "type=PROCTITLE msg=audit(1723042099.699:13369): proctitle=7375646F00636174002F6574632F736861646F77\n"
        "type=SYSCALL msg=audit(1723042099.699:13369): arch=c000003e syscall=59 ppid=10 pid=11 uid=0 comm=\"sudo\" "
        "exe=\"/usr/bin/sudo\" key=\"x\"\n"
        "type=PROCTITLE msg=audit(02/20/2025 13:07:46.504:118908) : proctitle=cat /etc/shadow /etc/gshadow \n",
        encoding="utf-8")
    ps = read_log(aud)
    assert [(p.cmd, p.image) for p in ps] == [("sudo cat /etc/shadow", "/usr/bin/sudo"),
                                             ("cat /etc/shadow /etc/gshadow", "cat")]
    doc = normalize(to_raw(ps[0], {"dataset": "t"}, 1))
    assert get(doc, "event.category") == "process" and get(doc, "process.command_line") == "sudo cat /etc/shadow"

    z = tmp_path / "x.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("x.json", "\n".join(json.dumps(e) for e in [
            {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1, "Image": "C:\\Windows\\System32\\ntdsutil.exe",
             "CommandLine": "ntdsutil \"ac i ntds\" ifm", "ParentImage": "C:\\Windows\\System32\\cmd.exe",
             "Hostname": "DC01", "@timestamp": "2023-07-19T09:02:23Z"},
            {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 10, "Image": "x"}]))
    [p] = read_log(z)
    assert p.name == "ntdsutil.exe" and p.computer == "DC01"


def test_ansible_wrappers_are_harness_not_attack(tmp_path):
    """Lớp bọc Ansible (PowerShell mã hóa lồng 2 lần, sudo BECOME-SUCCESS) không được tính là tấn công;
    lệnh tấn công gọi file trong C:\\AtomicRedTeam\\atomics vẫn là tấn công."""
    from siem.ai.endpoint_logs import Proc, is_harness
    inner = "powershell -EncodedCommand " + enc("$exec_wrapper_str = $input | Out-String")
    wrapper = Proc("windows", "sysmon", "C:\\Windows\\System32\\cmd.exe", "cmd.exe /C PowerShell -EncodedCommand " + enc(inner))
    become = Proc("linux", "auditd", "/usr/bin/sudo", "sudo -H -S -n -u root /bin/sh -c echo BECOME-SUCCESS-abc ; python3 x")
    tool = Proc("windows", "sysmon", "C:\\AtomicRedTeam\\atomics\\T1087.002\\src\\AdFind.exe", "AdFind.exe -sc dclist")
    assert is_harness(wrapper) and is_harness(become) and not is_harness(tool)
    out = [(p.name, tag) for p, tag, _, _ in label_file([become, Proc("linux", "auditd", "/usr/bin/cat", "cat /etc/shadow")],
                                                         [], "auditd")]
    assert out == [("cat", "attack")]


def test_match_test_and_decoded_powershell():
    tests = [("g1", "procdump", tokens("procdump.exe -accepteula -ma lsass.exe C:\\Windows\\Temp\\lsass_dump.dmp")),
             ("g2", "comsvcs", tokens("rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 1 x.dmp full"))]
    assert match_test("C:\\AtomicRedTeam\\atomics\\T1003.001\\bin\\procdump.exe  -accepteula -ma lsass.exe "
                      "C:\\Windows\\Temp\\lsass_dump.dmp", tests) == ("g1", "procdump")
    assert match_test("notepad.exe report.txt", tests) is None
    assert "Invoke-AtomicTest" in decoded("powershell -EncodedCommand " + enc('Invoke-AtomicTest "T1059"'))
