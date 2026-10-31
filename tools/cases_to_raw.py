"""Đổi ca test ECS của 41 rule YAML cũ (server/rules/cases/*.yml) về LOG GỐC theo nguồn, để chạy qua ruleset Wazuh gốc.

    python tools/cases_to_raw.py            # ghi wazuh/manager/tests/legacy/<auth|fim|linux|network|web|windows>.yml

Mỗi ca ra: legacy (mã rule cũ), kind (positive|negative), name, log_format, location, events (log gốc) — KHÔNG có
`rule:`/`none:` nên bộ chạy mặc định và lint (chỉ đọc tests/cases/) không đụng tới. Kết quả chạy: `wazuh_rule_test.py --report`.

Nguồn log: Apache access (apache), sshd/sudo/useradd (syslog), pfSense filterlog (syslog), Suricata eve.json (json),
Windows Security/System/Sysmon/PowerShell/Defender (eventchannel), syscheck (map {path, type}), tiến trình Linux
(dòng `siem-proc:` của agent, cộng bản auditd khi ca không cần tên tiến trình cha). Ca ECS không có log gốc tương ứng
thì KHÔNG bịa: ghi vào `skipped` (xem Unrenderable), bộ báo cáo đánh decision `convert` kèm lý do.
Event Windows dùng <EventData> cho mọi trường (kể cả 1102, thật ra là <UserData>): đủ cho rule khớp theo eventID/trường.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import yaml  # noqa: E402
from siem.detection import ruletest  # noqa: E402
from siem.pipeline.normalize import get  # noqa: E402

import wazuh_coverage as cov  # noqa: E402

CASES_DIR = ROOT / "server/rules/cases"
OUT_DIR = ROOT / "wazuh/manager/tests/legacy"
SYSLOG_TS = "Oct 31 10:00:00"
_EC_PREFIX = "f:EventChannel:"
_AUDIT_PREFIX = "1:/var/log/audit/audit.log:"
_FIM_TYPE = {"file_created": "added", "file_modified": "modified", "file_deleted": "deleted"}
_SIDS = {"administrators": "S-1-5-32-544", "users": "S-1-5-32-545", "remote desktop users": "S-1-5-32-555"}


class Unrenderable(Exception):
    """Ca ECS không dựng được thành log gốc trung thực (lý do là nội dung ngoại lệ)."""


# ---------------------------------------------------------------- Linux / web / mạng (chuỗi một dòng)
def apache_line(doc: dict) -> str:
    ts = datetime.fromisoformat(doc["@timestamp"]).strftime("%d/%b/%Y:%H:%M:%S %z")
    return (f'{get(doc, "source.ip")} - - [{ts}] "{get(doc, "http.request.method", "GET")} {get(doc, "url.original")} '
            f'HTTP/{get(doc, "http.version", "1.1")}" {get(doc, "http.response.status_code", 200)} '
            f'{get(doc, "http.response.bytes", 512)} "-" "{get(doc, "user_agent.original", "-")}"')


def auth_line(doc: dict) -> str:
    user, ip = get(doc, "user.name", "-"), get(doc, "source.ip", "-")
    action, cat = get(doc, "event.action"), get(doc, "event.category")
    if action == "sudo":
        return (f"{SYSLOG_TS} host sudo:   {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; "
                f"COMMAND={get(doc, 'process.command_line', '/bin/true')}")
    if cat == "iam":
        if action == "user_created":
            return (f"{SYSLOG_TS} host useradd[1234]: new user: name={user}, UID=1001, GID=1001, "
                    f"home=/home/{user}, shell=/bin/bash")
        return f"{SYSLOG_TS} host userdel[1234]: delete user '{user}'"
    verb = "Accepted" if get(doc, "event.outcome") == "success" else "Failed"
    return f"{SYSLOG_TS} host sshd[1234]: {verb} password for {user} from {ip} port 4444 ssh2"


def filterlog_line(doc: dict) -> str:
    act = "pass" if get(doc, "event.action") == "allow" else "block"
    return (f"{SYSLOG_TS} pfsense filterlog[1234]: 5,,,1000000103,em0,match,{act},in,4,0x0,,64,12345,0,none,6,tcp,60,"
            f"{get(doc, 'source.ip')},{get(doc, 'destination.ip', '10.0.0.5')},50000,{get(doc, 'destination.port', 0)},"
            "0,S,123456,,64240,,mss")


def eve_line(doc: dict) -> str:
    return json.dumps({"timestamp": "2026-10-31T10:00:00.000000+0700", "flow_id": 1, "in_iface": "eth0",
                       "event_type": "alert", "src_ip": get(doc, "source.ip"), "src_port": 4444,
                       "dest_ip": get(doc, "destination.ip", "10.0.0.5"), "dest_port": 80, "proto": "TCP",
                       "alert": {"action": "allowed", "gid": 1, "signature_id": get(doc, "suricata.signature_id"),
                                 "rev": 1, "signature": "ET TEST signature", "category": "Misc Attack",
                                 "severity": get(doc, "suricata.severity")}}, separators=(",", ":"))


def syscheck_event(doc: dict) -> dict:
    if get(doc, "event.category") == "registry":
        raise Unrenderable("ca registry: bộ bơm syscheck chỉ dựng được sự kiện file, không có sự kiện registry")
    return {"path": get(doc, "file.path"), "type": _FIM_TYPE[get(doc, "event.action")]}


def proc_line(doc: dict) -> str:
    name = get(doc, "process.name", "bash")
    return (f"ossec: output: 'siem-procs': siem-proc: pid={get(doc, 'process.pid', 1000)} ppid=900 uid=0 name={name} "
            f"parent={get(doc, 'process.parent.name', 'bash')} exe=/usr/bin/{name} "
            f"cmd={get(doc, 'process.command_line', name)}")


def audit_line(doc: dict, aid: int) -> str:
    name = get(doc, "process.name", "bash")
    return cov.audit_message(aid, f"/usr/bin/{name}", get(doc, "process.command_line", name))[len(_AUDIT_PREFIX):]


# ---------------------------------------------------------------- Windows (eventchannel)
# Wazuh suy severityValue từ Keywords (audit thành công/thất bại) hoặc Level (4 = INFORMATION, 3 = WARNING, 5 = VERBOSE):
# thiếu thì rule gốc (60104, 63108...) không bao giờ khớp -> event phải mang đúng hai trường này như event thật.
AUDIT_OK, AUDIT_FAIL, CLASSIC = "0x8020000000000000", "0x8010000000000000", "0x8080000000000000"


def _event(rid: int, channel: str, provider: str, eid: int, data: dict, level: int = 0, keywords: str = AUDIT_OK) -> str:
    fields = "".join(f"<Data Name='{k}'>{escape(str(v))}</Data>" for k, v in data.items())
    xml = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
           f"<Provider Name='{provider}'/><EventID>{eid}</EventID><Version>0</Version><Level>{level}</Level><Task>0</Task>"
           f"<Opcode>0</Opcode><Keywords>{keywords}</Keywords><TimeCreated SystemTime='2026-02-01T00:00:01.000000Z'/>"
           f"<EventRecordID>{rid}</EventRecordID><Correlation/><Execution ProcessID='700' ThreadID='800'/>"
           f"<Channel>{channel}</Channel><Computer>win-host</Computer><Security/></System><EventData>{fields}</EventData></Event>")
    message = f"Event {eid}:\r\n" + "\r\n".join(f"{k}: {v}" for k, v in data.items())
    return json.dumps({"Message": message, "Event": xml})


def _logon(doc: dict) -> dict:
    return {"SubjectUserSid": "S-1-0-0", "SubjectUserName": "-", "SubjectDomainName": "-", "SubjectLogonId": "0x0",
            "TargetUserSid": "S-1-0-0", "TargetUserName": get(doc, "user.name", "-"), "TargetDomainName": ".",
            "LogonType": "3", "LogonProcessName": "NtLmSsp", "AuthenticationPackageName": "NTLM",
            "WorkstationName": "ATTACKER", "ProcessId": "0x0", "ProcessName": "-",
            "IpAddress": get(doc, "source.ip", "-"), "IpPort": "49152"}


_ADMIN = {"SubjectUserSid": "S-1-5-21-1-2-3-500", "SubjectUserName": "Administrator", "SubjectDomainName": "WIN",
          "SubjectLogonId": "0x3e7"}
SEC, AUD = "Security", "Microsoft-Windows-Security-Auditing"
_DEF = ("Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-Windows Defender")
_OK, _FAIL, _INFO, _WARN = (0, AUDIT_OK), (0, AUDIT_FAIL), (4, CLASSIC), (3, CLASSIC)       # (Level, Keywords)
# mã event.code -> (channel, provider, (Level, Keywords), hàm dựng trường từ doc)
WIN_EVENTS = {
    4625: (SEC, AUD, _FAIL, lambda d: {**_logon(d), "Status": "0xc000006d", "SubStatus": "0xc000006a", "FailureReason": "%%2313"}),
    4624: (SEC, AUD, _OK, _logon),
    1102: (SEC, "Microsoft-Windows-Eventlog", (4, "0x4020000000000000"), lambda d: dict(_ADMIN)),
    4720: (SEC, AUD, _OK, lambda d: {**_ADMIN, "TargetUserName": get(d, "user.name", "-"), "TargetDomainName": "WIN",
                                     "TargetSid": "S-1-5-21-1-2-3-1105"}),
    4722: (SEC, AUD, _OK, lambda d: {**_ADMIN, "TargetUserName": get(d, "user.name", "-"), "TargetDomainName": "WIN",
                                     "TargetSid": "S-1-5-21-1-2-3-1105"}),
    4732: (SEC, AUD, _OK, lambda d: {**_ADMIN, "MemberName": get(d, "user.name", "-"), "MemberSid": "S-1-5-21-1-2-3-1106",
                                     "TargetUserName": get(d, "group.name", "-"), "TargetDomainName": "Builtin",
                                     "TargetSid": _SIDS.get(str(get(d, "group.name", "")).lower(), "S-1-5-32-999")}),
    7045: ("System", "Service Control Manager", _INFO,
           lambda d: {"ServiceName": "updsvc", "ImagePath": get(d, "process.command_line", ""),
                      "ServiceType": "user mode service", "StartType": "auto start", "AccountName": "LocalSystem"}),
    1116: (*_DEF, _WARN, lambda d: {"Threat Name": "Trojan:Win32/Wacatac.B!ml", "Severity Name": "Severe",
                                    "Path": "file:_" + str(get(d, "file.path", "")), "Detection User": "WIN\\an"}),
    2000: (*_DEF, _INFO, lambda d: {"Current Signature Version": "1.425.1.0", "Previous Signature Version": "1.425.0.0"}),
}


def windows_event(doc: dict, rid: int) -> str:
    """JSON mà agent Windows gửi cho một ca ECS (Security/System/Defender theo event.code, PowerShell, hoặc Sysmon EID 1)."""
    if (code := get(doc, "event.code")) in WIN_EVENTS:
        channel, provider, (level, keywords), fields = WIN_EVENTS[code]
        return _event(rid, channel, provider, code, fields(doc), level, keywords)
    if (script := get(doc, "powershell.script_block")) is not None:
        return _event(rid, "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell", 4104,
                      {"MessageNumber": "1", "MessageTotal": "1", "ScriptBlockText": script,
                       "ScriptBlockId": "11111111-2222-3333-4444-555555555555", "Path": ""}, 5, "0x0")
    if (name := get(doc, "process.name")):
        parent = get(doc, "process.parent.name")
        return cov.sysmon_message(rid, f"C:\\Windows\\System32\\{name}", get(doc, "process.command_line", name),
                                  f"C:\\Windows\\System32\\{parent}" if parent else "C:\\Windows\\explorer.exe",
                                  parent or "explorer.exe", "WIN\\an")[len(_EC_PREFIX):]
    raise Unrenderable(f"không có bộ dựng event Windows cho {get(doc, 'event')}")


# ---------------------------------------------------------------- cả bộ
def _render(code: str, docs: list[dict]) -> list[tuple[str, str, list]]:
    """Một ca ECS -> các biến thể log gốc [(log_format, location, events)] (LNX có thêm bản auditd)."""
    prefix = code.split("-")[0]
    if prefix == "AUTH":
        return [("syslog", "/var/log/auth.log", [auth_line(d) for d in docs])]
    if prefix == "FIM":
        return [("syscheck", "syscheck", [syscheck_event(d) for d in docs])]
    if prefix == "LNX":
        out = [("syslog", "siem-procs", [proc_line(d) for d in docs])]
        if not any(get(d, "process.parent") for d in docs):          # auditd chỉ có ppid, không có tên tiến trình cha
            out.append(("audit", "/var/log/audit/audit.log", [audit_line(d, 100 + i) for i, d in enumerate(docs)]))
        return out
    if prefix == "NET":
        if get(docs[0], "event.category") == "intrusion_detection":
            return [("json", "/var/log/suricata/eve.json", [eve_line(d) for d in docs])]
        return [("syslog", "/var/log/filter.log", [filterlog_line(d) for d in docs])]
    if prefix == "WEB":
        return [("apache", "/var/log/apache2/access.log", [apache_line(d) for d in docs])]
    if prefix == "WIN":
        return [("eventchannel", "EventChannel", [windows_event(d, i + 1) for i, d in enumerate(docs)])]
    if code == "TI-001":
        raise Unrenderable("phụ thuộc làm giàu MISP (threat.matched do pipeline gắn), log gốc của kết nối không có trường này")
    raise Unrenderable(f"không biết nguồn log của {code}")


def build(cases_dir: Path = CASES_DIR) -> tuple[dict[str, list[dict]], dict[str, str]]:
    """({tên file: [ca log gốc]}, {mã rule: lý do ca không dựng được}). Mã có ca dương nào dựng được thì chỉ ghi chú thêm."""
    out: dict[str, list[dict]] = {}
    skipped: dict[str, str] = {}
    for path in sorted(cases_dir.glob("*.y*ml")):
        out[path.stem] = []
    for c in ruletest.load_cases(cases_dir):
        stem = c.source.split(".")[0]
        try:
            docs = ruletest.expand(c.spec)
            for fmt, loc, events in _render(c.rule, docs):
                tag = " (auditd)" if fmt == "audit" else ""
                out[stem].append({"legacy": c.rule, "kind": "positive" if c.expect == "alert" else "negative",
                                  "name": c.name + tag, "log_format": fmt, "location": loc, "events": events})
        except Unrenderable as e:
            skipped[c.rule] = f"{skipped[c.rule]}; {e}" if c.rule in skipped and str(e) not in skipped[c.rule] else str(e)
    return out, skipped


def main() -> None:
    cases, skipped = build()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for stem, lst in cases.items():
        head = (f"# Ca test rule cũ {stem} đổi sang LOG GỐC bởi tools/cases_to_raw.py (nguồn: server/rules/cases/{stem}.yml).\n"
                "# Không có khóa rule:/none: -> bộ chạy mặc định bỏ qua; chạy bằng `wazuh_rule_test.py --report`.\n")
        body = yaml.safe_dump(lst, allow_unicode=True, sort_keys=False, width=10**9)
        (OUT_DIR / f"{stem}.yml").write_text(head + body, encoding="utf-8", newline="\n")
        print(f"{stem}.yml: {len(lst)} ca")
    for code, why in skipped.items():
        print(f"BỎ QUA {code}: {why}")


if __name__ == "__main__":
    main()
