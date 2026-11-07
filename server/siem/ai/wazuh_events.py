"""Dựng event thô đúng định dạng agent gửi wazuh-manager, để bơm vào sandbox Wazuh (sandbox.py, R67).

Mỗi event mang một số `ident` riêng để ghép alert về đúng event (sandbox.alert_ident):
  eventchannel : Sysmon EventID 1 {"Message", "Event": <XML>}, hàng đợi 'f', EventRecordID = ident
  siem-proc    : dòng của script agent siem-procs (decoder 0102-siem-procs.xml), header agent "(sbx-<ident>)"
  apache       : dòng access log, header agent "(sbx-<ident>)" (rule web chỉ nhận vị trí dạng agent, S7)
Đo S4 (06/11/2026): alert của event có header agent ghi agent.name = "sbx-<ident>"; location chỉ còn đường dẫn.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from xml.sax.saxutils import escape

from ..pipeline.normalize import get

# Rule Wazuh khớp theo CẤU TRÚC chung chung chứ không theo hành vi tấn công (đọc định nghĩa trong ruleset 4.14.7).
# Báo cáo độ phủ (tools/wazuh_coverage.py) và cổng AI không tính chúng là phát hiện.
GENERIC = {
    "80792": "ghi nhận MỌI lệnh auditd có key audit-wazuh-c (89/94 lệnh bình thường cũng khớp)",
    "92032": "mọi tiến trình con có cha là `cmd.exe /c` (script, trình cài đặt cũng vậy)",
    "92036": "`net.exe` có cha là `cmd.exe /c` (con của 92032)",
    "92041": "regex `add.+\\/d\\s+(\")?(?:[A-Za-z\\d+\\/]{4})*(...)?`: mọi nhóm sau `/d` đều tùy chọn nên khớp MỌI "
             "`reg add ... /d`, không riêng giá trị Base64",
}
WEB_LOCATION = "/var/log/apache2/access.log"
_PROC_DATASETS = {"atomic-red-team", "baseline-endpoint"}
_BACKGROUND = {"splunk-background", "scenario-background"}      # lệnh bình thường ghi thật (extra_normal)


@dataclass(frozen=True)
class RawEvent:
    ident: int
    fmt: str        # eventchannel | siem-proc | apache
    msg: str        # message gửi vào hàng đợi analysisd (queue/sockets/queue)


def sysmon_message(rid: int, image: str, cmd: str, parent: str, parent_cmd: str, user: str) -> str:
    base = re.split(r"[\\/]", image)[-1]
    fields = {"RuleName": "-", "UtcTime": "2026-02-01 00:00:01.000", "ProcessGuid": "{00000000-0000-0000-0000-000000000000}",
              "ProcessId": str(4000 + rid % 60000), "Image": image, "FileVersion": "-", "Description": "-",
              "Product": "-", "Company": "-", "OriginalFileName": base, "CommandLine": cmd, "CurrentDirectory": "C:\\",
              "User": user, "LogonGuid": "{00000000-0000-0000-0000-000000000000}", "LogonId": "0x3e7",
              "TerminalSessionId": "1", "IntegrityLevel": "High", "Hashes": "-",
              "ParentProcessGuid": "{00000000-0000-0000-0000-000000000000}", "ParentProcessId": "3999",
              "ParentImage": parent, "ParentCommandLine": parent_cmd, "ParentUser": user}
    data = "".join(f"<Data Name='{k}'>{escape(str(v))}</Data>" for k, v in fields.items())
    xml = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
           "<Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/>"
           "<EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode>"
           "<Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2026-02-01T00:00:01.000000Z'/>"
           f"<EventRecordID>{rid}</EventRecordID><Correlation/><Execution ProcessID='3000' ThreadID='4000'/>"
           "<Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>bench-win</Computer>"
           "<Security UserID='S-1-5-18'/></System><EventData>" + data + "</EventData></Event>")
    message = "Process Create:\r\n" + "\r\n".join(f"{k}: {v}" for k, v in fields.items())
    return "f:EventChannel:" + json.dumps({"Message": message, "Event": xml})


def sysmon_event(ident: int, image: str, cmd: str, parent: str, parent_cmd: str, user: str) -> RawEvent:
    return RawEvent(ident, "eventchannel", sysmon_message(ident, image, cmd, parent, parent_cmd, user))


def _word(v: str) -> str:
    return re.sub(r"\s", "_", v) or "-"         # như script siem-procs: name/parent/exe không có khoảng trắng, vắng là "-"


def siem_proc_event(ident: int, exe: str, cmd: str, name: str, parent: str, uid: int = 0) -> RawEvent:
    # một dòng = một event (logcollector cắt theo dòng); NUL cắt chuỗi C trong analysisd
    cmd = re.sub(r"[\r\n\x00]+", " ", cmd)
    body = (f"ossec: output: 'siem-procs': siem-proc: pid={ident} ppid=1 uid={uid} name={_word(name)} "
            f"parent={_word(parent)} exe={_word(exe)} cmd={cmd}")
    return RawEvent(ident, "siem-proc", f"1:[001] (sbx-{ident}) any->siem-procs:{body}")


def apache_event(ident: int, line: str) -> RawEvent:
    return RawEvent(ident, "apache", f"1:[001] (sbx-{ident}) any->{WEB_LOCATION}:{line}")


def _process_event(ident: int, doc: dict, platform: str) -> RawEvent | None:
    exe = str(get(doc, "process.executable") or get(doc, "process.name") or "")
    if not exe:
        return None
    cmd = str(get(doc, "process.command_line") or "")
    if platform == "windows":
        parent = str(get(doc, "process.parent.executable") or get(doc, "process.parent.name") or "")
        return sysmon_event(ident, exe, cmd, parent, str(get(doc, "process.parent.command_line") or parent),
                            str(get(doc, "user.name") or ""))
    uid = str(get(doc, "user.id") or "")
    return siem_proc_event(ident, exe, cmd, str(get(doc, "process.name") or re.split(r"/", exe)[-1]),
                           str(get(doc, "process.parent.name") or "sh"), int(uid) if uid.isdigit() else 0)


def golden_events(g, data_dir: Path, extra_normal: bool = True) -> dict[int, RawEvent]:
    """Event thô cho mẫu của `g` (PublicDatasets), khóa id(Labeled.doc): chỉ dùng trong một chu kỳ (id đổi khi nạp lại).
    Phạm vi như tools/wazuh_coverage.load_items: CSIC (dòng access log gốc), Atomic Red Team, lệnh bình thường tự soạn,
    và (extra_normal) lệnh bình thường ghi thật. Không có khóa: mục không dựng được log thô (log ghi thật Splunk/EVTX
    là event Security/khác, không phải tiến trình Sysmon). Log thô lấy từ chính doc (normalize giữ nguyên dòng gốc ở
    `message` và `raw`), nên `data_dir` không cần đọc lại: giữ tham số cho khớp giao diện."""
    out: dict[int, RawEvent] = {}
    for x in (*g.attack, *g.normal):
        ds, ident = x.label.get("dataset"), len(out) + 1
        if ds == "csic2010" and isinstance(x.doc.get("message"), str):
            e = apache_event(ident, x.doc["message"])
        elif ds in _PROC_DATASETS or (extra_normal and ds in _BACKGROUND):
            e = _process_event(ident, x.doc, x.label.get("platform") or "linux")
        else:
            e = None
        if e:
            out[id(x.doc)] = e
    return out
