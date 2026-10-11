"""Log endpoint GHI THẬT khi chạy tấn công (Splunk attack_data, OTRF Security-Datasets) -> event thô như agent gửi + nhãn.

Chỉ lấy event TẠO TIẾN TRÌNH — loại event rule endpoint và AI worker đang dùng:
  Windows: Sysmon EventID 1 (XML, hoặc văn bản WinEventLog của Splunk), Security 4688; Linux: Sysmon for Linux EventID 1,
  auditd (PROCTITLE / EXECVE / SYSCALL).

Gắn nhãn từng event (xem `label_atomic_run`):
  - Thư mục `atomic_red_team` của Splunk: Ansible gọi `Invoke-AtomicTest "<kỹ thuật>"` qua WinRM. Tiến trình con cháu của lần
    gọi chạy bài thử (không kèm -GetPrereqs / -Cleanup / -ShowDetails...) là TẤN CÔNG, trừ tiến trình phụ của công cụ chạy bài
    thử (conhost, csc / cvtres do Add-Type, chcp). Tiến trình khác thuộc cây điều khiển của Ansible (cài module, tải công cụ,
    khởi động lại) là CÔNG CỤ THỬ — bỏ, không tính là bình thường. Mọi tiến trình còn lại là HOẠT ĐỘNG NỀN của máy Attack Range
    (dịch vụ Windows, Splunk forwarder, khởi động máy...) -> tập BÌNH THƯỜNG thật.
  - auditd của Splunk: file đã được lọc sẵn chỉ còn phần tấn công -> mọi tiến trình là tấn công.
  - Thư mục khác của Splunk và OTRF: chỉ biết CẢ BỘ log thuộc kỹ thuật nào -> dùng đo theo bộ (rule có bắn trên ít nhất một
    tiến trình của bộ không), không dùng làm mẫu từng event.
"""
from __future__ import annotations

import base64
import json
import re
import tarfile
import zipfile
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator
from xml.etree import ElementTree as ET

MAX_CMD = 2000


@dataclass
class Proc:
    """Một sự kiện tạo tiến trình, chung cho mọi nguồn."""
    platform: str                    # windows / linux
    source: str                      # sysmon / 4688 / auditd
    image: str
    cmd: str
    parent_image: str = ""
    parent_cmd: str = ""
    guid: str = ""
    parent_guid: str = ""
    pid: str = ""
    ppid: str = ""
    user: str = ""
    computer: str = ""
    time: str = ""
    record: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return re.split(r"[\\/]", self.image)[-1] if self.image else ""

    def key(self) -> str:
        return self.guid or f"{self.computer}|{self.pid}"

    def parent_key(self) -> str:
        return self.parent_guid or f"{self.computer}|{self.ppid}"


# ---------------------------------------------------------------- đọc từng nguồn
def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _xml_event(text: str) -> tuple[dict[str, str], dict[str, str]] | None:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    sysd: dict[str, str] = {}
    data: dict[str, str] = {}
    for el in root:
        n = _local(el.tag)
        if n == "System":
            for s in el:
                sn = _local(s.tag)
                if sn == "Provider":
                    sysd["Provider"] = s.get("Name") or ""
                elif sn == "TimeCreated":
                    sysd["Time"] = s.get("SystemTime") or ""
                else:
                    sysd[sn] = (s.text or "").strip()
        elif n == "EventData":
            for i, d in enumerate(el):
                data[d.get("Name") or f"param{i + 1}"] = (d.text or "").strip()
    return sysd, data


def _proc_from_fields(eid: int, channel: str, f: dict[str, str], computer: str, time: str, record: str) -> Proc | None:
    linux = "linux" in channel.lower()
    if eid == 1 and "sysmon" in channel.lower():
        return Proc("linux" if linux else "windows", "sysmon", f.get("Image", ""), f.get("CommandLine", ""),
                    f.get("ParentImage", ""), f.get("ParentCommandLine", ""), f.get("ProcessGuid", ""),
                    f.get("ParentProcessGuid", ""), f.get("ProcessId", ""), f.get("ParentProcessId", ""),
                    f.get("User", ""), computer, time, record)
    if eid == 4688:
        return Proc("windows", "4688", f.get("NewProcessName", ""), f.get("CommandLine", ""),
                    f.get("ParentProcessName", ""), "", "", "", _hexpid(f.get("NewProcessId")), _hexpid(f.get("ProcessId")),
                    f.get("SubjectUserName", ""), computer, time, record)
    return None


def _hexpid(v: Any) -> str:
    s = str(v or "").strip()
    try:
        return str(int(s, 16) if s.lower().startswith("0x") else int(s))
    except ValueError:
        return s


_WANT = ("<EventID>1</EventID>", "<EventID>4688</EventID>")


def iter_xml_file(path: Path) -> Iterator[Proc]:
    """Mỗi event XML một dòng (đôi khi trải nhiều dòng khi dòng lệnh có xuống dòng)."""
    buf: list[str] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not buf and "<Event" not in line:
                continue
            buf.append(line)
            if "</Event>" not in line:
                continue
            text = "".join(buf).strip()
            buf = []
            if not any(w in text for w in _WANT):
                continue
            ev = _xml_event(text[text.find("<Event"):])
            if not ev:
                continue
            sysd, data = ev
            p = _proc_from_fields(int(sysd.get("EventID") or 0), sysd.get("Channel", ""), data,
                                  sysd.get("Computer", ""), sysd.get("Time", ""), sysd.get("EventRecordID", ""))
            if p:
                yield p


_TS_LINE = re.compile(r"^\d{2}/\d{2}/\d{4} \d{1,2}:\d{2}:\d{2} [AP]M\s*$")


def _grab(text: str, label: str) -> str:
    m = re.search(rf"^\s*{re.escape(label)}:[ \t]*(.*)$", text, re.M)
    return m.group(1).strip() if m else ""


def _text_block(lines: list[str]) -> Proc | None:
    kv: dict[str, str] = {}
    msg: list[str] = []
    in_msg = False
    for line in lines[1:]:
        if in_msg:
            msg.append(line)
        elif line.startswith("Message="):
            in_msg = True
            msg.append(line[8:])
        else:
            k, _, v = line.partition("=")
            kv[k.strip()] = v.strip()
    code = int(kv.get("EventCode") or 0)
    text = "\n".join(msg)
    channel = kv.get("LogName", "")
    if code == 4688:
        f = {"NewProcessName": _grab(text, "New Process Name"), "CommandLine": _grab(text, "Process Command Line"),
             "ParentProcessName": _grab(text, "Creator Process Name"), "NewProcessId": _grab(text, "New Process ID"),
             "ProcessId": _grab(text, "Creator Process ID"), "SubjectUserName": _grab(text, "Account Name")}
    elif code == 1 and "sysmon" in (channel + kv.get("SourceName", "")).lower():
        f = {k: _grab(text, k) for k in ("Image", "CommandLine", "ParentImage", "ParentCommandLine", "ProcessGuid",
                                          "ParentProcessGuid", "ProcessId", "ParentProcessId", "User")}
        channel = "Microsoft-Windows-Sysmon/Operational"
    else:
        return None
    return _proc_from_fields(code, channel or "Security", f, kv.get("ComputerName", ""), lines[0].strip(),
                             kv.get("RecordNumber", ""))


def iter_wineventlog_text(path: Path) -> Iterator[Proc]:
    """Định dạng WinEventLog văn bản của Splunk: dòng thời gian, các dòng key=value, Message= nhiều dòng."""
    block: list[str] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\r\n")
            if _TS_LINE.match(line) and block:
                if (p := _text_block(block)):
                    yield p
                block = []
            block.append(line)
    if block and (p := _text_block(block)):
        yield p


_AUDIT = re.compile(r"type=(\w+) msg=audit\(([^)]*)\)\s*:?\s*(.*)")
_KV = re.compile(r"(\w+)=(\"[^\"]*\"|\S+)")


def _unhex(v: str) -> str:
    v = v.strip()
    if v.startswith('"') and v.endswith('"'):
        return v[1:-1]
    if len(v) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]{2,}", v):
        try:
            return bytes.fromhex(v).replace(b"\x00", b" ").decode("utf-8", "replace").strip()
        except ValueError:
            return v
    return v


def iter_auditd(path: Path) -> Iterator[Proc]:
    """Gom các dòng cùng mã audit; dòng lệnh lấy từ PROCTITLE (hex hoặc dạng đã giải mã của ausearch -i), không có thì EXECVE."""
    groups: dict[str, dict[str, str]] = {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = _AUDIT.search(line)
            if not m:
                continue
            typ, stamp, rest = m.groups()
            g = groups.setdefault(stamp.rsplit(":", 1)[-1], {"_stamp": stamp})
            g.setdefault(typ, rest.strip())
    for aid, g in groups.items():
        cmd = ""
        if (pt := g.get("PROCTITLE")) and "proctitle=" in pt:
            cmd = _unhex(pt.split("proctitle=", 1)[1])
        if not cmd and (ex := g.get("EXECVE")):
            a = dict(_KV.findall(ex))
            args = sorted((int(k[1:]), v) for k, v in a.items() if re.fullmatch(r"a\d+", k))
            cmd = " ".join(_unhex(v) for _, v in args)
        if not cmd:
            continue
        s = {k: _unhex(v) for k, v in _KV.findall(g.get("SYSCALL", ""))}
        exe = s.get("exe") or cmd.split()[0]
        yield Proc("linux", "auditd", exe, cmd[:MAX_CMD], "", "", "", "", s.get("pid", ""), s.get("ppid", ""),
                   s.get("uid", ""), "", g["_stamp"], aid, {"comm": s.get("comm", ""), "key": s.get("key", "")})


def iter_otrf_archive(path: Path) -> Iterator[Proc]:
    """OTRF: zip / tar.gz chứa file JSON mỗi dòng một event (winlogbeat / logstash)."""
    def lines() -> Iterator[str]:
        if path.name.endswith(".zip"):
            with zipfile.ZipFile(path) as z:
                for n in z.namelist():
                    if n.endswith((".json", ".log")):
                        yield from z.read(n).decode("utf-8", "replace").splitlines()
        else:
            with tarfile.open(path) as t:
                for m in t.getmembers():
                    if m.isfile() and m.name.endswith((".json", ".log")) and (f := t.extractfile(m)):
                        yield from f.read().decode("utf-8", "replace").splitlines()
    for line in lines():
        if not line.startswith("{") or ('"EventID":1,' not in line and '"EventID":4688' not in line
                                         and '"EventID": 1,' not in line and '"EventID": 4688' not in line):
            continue
        try:
            e = json.loads(line)
        except ValueError:
            continue
        eid = int(e.get("EventID") or 0)
        f = {k: str(v) for k, v in e.items() if isinstance(v, (str, int))}
        p = _proc_from_fields(eid, str(e.get("Channel") or e.get("channel") or ""), f, str(e.get("Hostname") or ""),
                              str(e.get("@timestamp") or ""), str(e.get("RecordNumber") or ""))
        if p:
            yield p


def read_log(path: Path) -> list[Proc]:
    """Chọn bộ đọc theo nội dung đầu file."""
    if path.name.endswith((".zip", ".tar.gz")):
        return list(iter_otrf_archive(path))
    with open(path, "rb") as fh:
        head = fh.read(512).lstrip()
    if head.startswith(b"<Event"):
        return list(iter_xml_file(path))
    if head.startswith(b"type="):
        return list(iter_auditd(path))
    if _TS_LINE.match(head.split(b"\n", 1)[0].decode("utf-8", "replace")):
        return list(iter_wineventlog_text(path))
    return []


# ---------------------------------------------------------------- gắn nhãn bộ chạy Atomic Red Team
_ENC = re.compile(r"-e(?:nc|ncodedcommand)?\s+([A-Za-z0-9+/=]{16,})", re.I)
_RUN = re.compile(r"invoke-atomictest", re.I)
_NOT_RUN = re.compile(r"-(getprereqs|cleanup|showdetails|checkprereqs)\b", re.I)
# tiến trình phụ do công cụ chạy bài thử / .NET tự sinh (biên dịch Add-Type, NGEN, báo lỗi), không phải hành vi tấn công
_HARNESS_HELPERS = {"conhost.exe", "csc.exe", "cvtres.exe", "chcp.com", "winrshost.exe", "wsmprovhost.exe",
                    "mscorsvw.exe", "ngen.exe", "ngentask.exe", "werfault.exe"}
_EXECUTORS = {"cmd.exe", "powershell.exe", "pwsh.exe", "pwsh", "sh", "bash", "dash"}


def decoded(cmd: str, depth: int = 2) -> str:
    """Dòng lệnh, kèm phần -EncodedCommand đã giải mã (PowerShell base64 UTF-16); giải tiếp 1 lớp lồng (Ansible bọc 2 lần)."""
    m = _ENC.search(cmd or "")
    if not m or depth <= 0:
        return cmd or ""
    try:
        inner = base64.b64decode(m.group(1) + "=" * (-len(m.group(1)) % 4)).decode("utf-16-le", "replace")
    except ValueError:
        return cmd
    return cmd + " " + decoded(inner, depth - 1)


_ANSIBLE = re.compile(r"exec_wrapper|\$json_raw|become-success|\.ansible[/\\]tmp|ansible_|AnsiballZ", re.I)


def is_harness(p: Proc) -> bool:
    """Tiến trình của công cụ điều khiển bài thử: WinRM, Invoke-AtomicTest, lớp bọc / become của Ansible."""
    d = decoded(p.cmd)
    return p.name.lower() in ("winrshost.exe", "wsmprovhost.exe") or bool(_RUN.search(d)) or bool(_ANSIBLE.search(d))


def has_atomic_run(procs: list[Proc]) -> bool:
    return any(_RUN.search(d) and not _NOT_RUN.search(d) for d in (decoded(p.cmd) for p in procs))


def label_atomic_run(procs: list[Proc]) -> dict[int, str]:
    """index trong `procs` -> "attack" | "harness" | "background".
    attack  : con cháu của lần gọi Invoke-AtomicTest chạy bài thử thật (trừ tiến trình phụ của công cụ chạy bài thử)
    harness : cây điều khiển của Ansible / Invoke-AtomicTest còn lại (cài đặt, tải công cụ, dọn dẹp) — bỏ
    background: mọi tiến trình khác — hoạt động nền của máy."""
    by_key: dict[str, list[int]] = defaultdict(list)
    for i, p in enumerate(procs):
        by_key[p.key()].append(i)
    children: dict[str, list[int]] = defaultdict(list)
    for i, p in enumerate(procs):
        children[p.parent_key()].append(i)
    out = {i: "background" for i in range(len(procs))}

    def mark(i: int, tag: str, depth: int = 0) -> None:
        if depth > 50 or (out[i] == "attack" and tag != "attack"):
            return
        if out[i] == tag and depth:
            return
        out[i] = tag
        for c in children.get(procs[i].key(), []):
            if c != i:
                mark(c, tag, depth + 1)

    # cây điều khiển từ xa (WinRM), lệnh gọi Invoke-AtomicTest, lớp bọc của Ansible -> công cụ thử. KHÔNG dựa vào đường dẫn
    # C:\AtomicRedTeam\atomics\...: chính lệnh tấn công cũng gọi file trong đó (procdump.exe, AdFind.exe)
    for i, p in enumerate(procs):
        if is_harness(p):
            mark(i, "harness")
    # lần gọi chạy bài thử thật -> con cháu là tấn công. Bài thử luôn chạy qua một trình thực thi (cmd.exe /c, powershell.exe
    # & {...}, sh -c); con trực tiếp không phải trình thực thi (whoami / hostname Invoke-AtomicTest tự gọi để ghi log) là công cụ
    for i, p in enumerate(procs):
        d = decoded(p.cmd)
        if _RUN.search(d) and not _NOT_RUN.search(d):
            for c in children.get(p.key(), []):
                if c != i and procs[c].name.lower() in _EXECUTORS:
                    mark(c, "attack", 1)
    for i, p in enumerate(procs):
        if out[i] == "attack" and p.name.lower() in _HARNESS_HELPERS:
            out[i] = "harness"
    return out


# ---------------------------------------------------------------- ghép với bài thử Atomic (biết bài thử nào)
_TOK = re.compile(r"[a-z0-9_.\-]{3,}")
_COMMON = {"exe", "cmd", "c:\\", "windows", "system32", "users", "temp", "appdata", "local", "powershell", "program",
           "files", "administrator", "admini", "null", "out-null", "true", "false"}


def tokens(cmd: str) -> set[str]:
    return {t for t in _TOK.findall(cmd.lower()) if t not in _COMMON}


def match_test(cmd: str, tests: list[tuple[str, str, set[str]]]) -> tuple[str, str] | None:
    """(guid, tên bài thử) có dòng lệnh giống nhất (tỉ lệ token của bài thử xuất hiện ≥ 0,6)."""
    ev = tokens(cmd)
    best, score = None, 0.0
    for guid, name, tt in tests:
        if not tt:
            continue
        s = len(tt & ev) / len(tt)
        if s > score:
            best, score = (guid, name), s
    return best if score >= 0.6 else None


def label_file(procs: list[Proc], tests: list[tuple[str, str, set[str]]], kind: str) -> list[tuple[Proc, str, str, str]]:
    """-> [(tiến trình, nhãn, guid bài thử, tên bài thử)], nhãn: attack / normal / scenario (bỏ tiến trình 'harness').
    kind: "auditd" (Splunk đã lọc sẵn chỉ còn tấn công), "atomic" (thư mục atomic_red_team), "scenario" (còn lại)."""
    out: list[tuple[Proc, str, str, str]] = []
    if kind == "scenario":
        return [(p, "scenario", "", "") for p in procs]
    tags = label_atomic_run(procs) if kind == "atomic" else {i: "attack" for i in range(len(procs))}
    has_run = kind == "atomic" and has_atomic_run(procs)
    for i, p in enumerate(procs):
        tag = tags[i]
        if tag == "harness" or (tag != "attack" and is_harness(p)) or (kind == "auditd" and is_harness(p)):
            continue
        m = match_test(decoded(p.cmd), tests) if tests else None
        if tag == "background":
            if m:
                tag = "attack"           # vd tác vụ / dịch vụ bài thử tạo ra, chạy sau, ngoài cây Invoke-AtomicTest
            elif not has_run:
                tag = "scenario"         # file đã lọc sẵn, không thấy công cụ chạy bài thử: không dám coi là bình thường
            else:
                tag = "normal"
        out.append((p, tag, *(m or ("", ""))))
    return out


# ---------------------------------------------------------------- chuyển sang event thô như agent gửi
def to_raw(p: Proc, label: dict[str, Any], n: int) -> dict[str, Any]:
    ts = p.time or "2026-01-01T00:00:00Z"
    if p.platform == "windows":
        if p.source == "4688":
            fields = {"NewProcessName": p.image, "CommandLine": p.cmd[:MAX_CMD], "ParentProcessName": p.parent_image,
                      "NewProcessId": p.pid, "SubjectUserName": p.user}
            data = {"event_id": 4688, "channel": "Security", "provider": "Microsoft-Windows-Security-Auditing",
                    "computer": p.computer, "record_id": n, "fields": fields}
        else:
            fields = {"Image": p.image, "CommandLine": p.cmd[:MAX_CMD], "ParentImage": p.parent_image,
                      "ParentCommandLine": p.parent_cmd[:MAX_CMD], "User": p.user, "ProcessId": p.pid}
            data = {"event_id": 1, "channel": "Microsoft-Windows-Sysmon/Operational", "provider": "Microsoft-Windows-Sysmon",
                    "computer": p.computer, "record_id": n, "fields": fields}
        return {"timestamp": ts, "agent_id": f"dataset-{label.get('dataset')}", "hostname": p.computer or "dataset-win",
                "os": "windows", "source": "eventlog", "event_type": "windows_event", "data": data, "label": label}
    name = p.extra.get("comm") or p.name
    return {"timestamp": ts, "agent_id": f"dataset-{label.get('dataset')}", "hostname": p.computer or "dataset-linux",
            "os": "linux", "source": "process", "event_type": "process_creation",
            "data": {"pid": p.pid, "ppid": p.ppid, "uid": p.user, "name": name, "executable": p.image,
                     "command_line": p.cmd[:MAX_CMD], "parent_name": re.split(r"[\\/]", p.parent_image)[-1]},
            "label": label}


_MASK = re.compile(r"0x[0-9a-f]+|\{[0-9a-f-]{8,}\}|[0-9a-f]{16,}|\d+", re.I)


def dedupe_key(p: Proc) -> tuple[str, str, str]:
    """Hoạt động nền lặp lại rất nhiều (svchost, splunk forwarder): gộp theo chương trình + dòng lệnh đã che số / GUID."""
    return p.platform, p.name.lower(), _MASK.sub("#", (p.cmd or "").lower())[:400]


def iter_unique(procs: Iterable[Proc]) -> Iterator[Proc]:
    seen: set[tuple[str, str, str]] = set()
    for p in procs:
        k = dedupe_key(p)
        if k not in seen:
            seen.add(k)
            yield p
