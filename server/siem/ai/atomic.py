"""Atomic Red Team (Red Canary, MIT) -> mẫu tấn công ENDPOINT có nhãn cho AI worker (tools/convert_datasets.py).

Atomic Red Team mô tả các bài thử tấn công theo từng kỹ thuật ATT&CK: lệnh chạy trên Windows (cmd / PowerShell)
và Linux (sh / bash). Mỗi bài thử được dựng thành event thô ĐÚNG ĐỊNH DẠNG agent gửi về, để đi qua cùng bộ chuẩn hóa
với dữ liệu thật:
  - Windows: Sysmon EventID 1 (process create: Image, CommandLine, ParentImage...) như Wazuh agent thu.
  - Linux:   process_creation (name, executable, command_line, parent_name) như siem-procs / auditd.
Mỗi bài thử sinh:
  - 1 tiến trình shell chạy cả khối lệnh (cmd.exe /c ..., powershell.exe -Command ..., sh -c ...) — đúng cách
    Invoke-AtomicRedTeam thực thi;
  - 1 tiến trình con cho từng lệnh là chương trình thật (net.exe, reg.exe, whoami...), vì Sysmon / auditd cũng ghi
    riêng từng tiến trình. Lệnh nội bộ của shell (echo, cd, set...) và cmdlet PowerShell không tạo tiến trình.

Lưu ý trung thực: đây là telemetry DỰNG LẠI từ định nghĩa bài thử, không phải log ghi thật khi chạy. Dòng lệnh đúng
như kẻ tấn công gõ, nhưng thiếu phần hành vi sinh ra sau đó (tiến trình cháu, file, mạng). Đủ để AI viết rule theo
dòng lệnh / tên tiến trình — loại rule endpoint phổ biến nhất (Sigma process_creation).
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

T0 = datetime(2026, 2, 1, tzinfo=timezone.utc)
MAX_CMD = 2000                       # dòng lệnh dài hơn bị cắt (script PowerShell hàng trăm dòng)
# đường dẫn mặc định của môi trường thử (Invoke-AtomicRedTeam): rule dùng chung không được dựa vào chúng
ATOMIC_ROOT = {"windows": r"C:\AtomicRedTeam\atomics", "linux": "/opt/AtomicRedTeam/atomics"}
# Đoạn (giữa các dấu / \ khoảng trắng...) là dấu vết của môi trường thử: thư mục AtomicRedTeam / ExternalPayloads,
# file đặt theo mã kỹ thuật (T1003.008.txt), user / thư mục 'art', atomic.local, redcanaryco...
# Tên kỹ thuật của công cụ thử Stratus Red Team (aws.credential-access.ec2-get-password-data) cũng chỉ có trong lab.
ARTIFACT_RE = re.compile(r"^(?:.*atomic.*|.*externalpayloads.*|.*redcanary.*|art|art[-_.].*|.*[-_.]art(?:[-_.].*)?"
                         r"|t1\d{3}(?:[-_.].*)?|.*[-_.]t1\d{3}(?:[-_.].*)?|.*stratus.*"
                         r"|(?:aws|azure|gcp|k8s|eks|entra-id)\.[a-z]+(?:-[a-z]+)+\..*)$")
# Bài thử chạy qua công cụ giả lập tấn công cloud (Stratus Red Team: warmup / detonate CloudTrail, EC2...): tấn công nhắm
# vào API cloud, máy Linux chỉ là nơi gõ lệnh -> không phải mẫu tấn công endpoint; model chép `detonate`, `warmup`.
LAB_TOOLS = re.compile(r"\bstratus\b", re.I)
SHELLS = {"command_prompt": ("windows", r"C:\Windows\System32\cmd.exe"),
          "powershell": ("windows", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
          "sh": ("linux", "/bin/sh"), "bash": ("linux", "/bin/bash")}
_PLACEHOLDER = re.compile(r"#\{([^}]+)\}")
_CMD_BUILTIN = {"echo", "set", "cd", "chdir", "md", "mkdir", "rd", "rmdir", "del", "erase", "copy", "move", "ren", "rename",
                "type", "if", "for", "call", "goto", "exit", "pushd", "popd", "cls", "ver", "vol", "title", "pause", "rem",
                "setlocal", "endlocal", "start", "dir", "mklink", "assoc", "ftype", "path", "prompt", "color", "date", "time"}
_SH_BUILTIN = {"if", "then", "else", "elif", "fi", "for", "do", "done", "while", "until", "case", "esac", "export", "set",
               "unset", "cd", "echo", "printf", "source", ".", "local", "read", "return", "exit", "true", "false", "[",
               "[[", "test", "eval", "alias", "trap", "shift", "wait", "ulimit", "umask", "function", "{", "}", "declare",
               "history", "let", "break", "continue", "exec", "pwd", "type", "hash", "readonly", "typeset", "select"}
# chương trình Windows hay được gọi thẳng trong script PowerShell (còn lại là cmdlet, không tạo tiến trình)
_WIN_PROGRAMS = {"net", "net1", "reg", "sc", "schtasks", "wmic", "whoami", "rundll32", "regsvr32", "mshta", "certutil",
                 "bitsadmin", "cmd", "vssadmin", "bcdedit", "wevtutil", "netsh", "nltest", "dsquery", "cscript",
                 "wscript", "msiexec", "ipconfig", "systeminfo", "tasklist", "taskkill", "attrib", "icacls", "takeown",
                 "fsutil", "wbadmin", "cipher", "powershell", "pwsh", "curl", "ping", "nslookup", "arp", "route",
                 "netstat", "quser", "qwinsta", "query", "klist", "setspn", "cmdkey", "vaultcmd", "esentutl", "ntdsutil",
                 "diskshadow", "msbuild", "installutil", "regasm", "regsvcs", "odbcconf", "forfiles", "pcalua",
                 "control", "explorer", "hh", "mavinject", "procdump", "makecab", "expand", "extrac32", "findstr",
                 "where", "xcopy", "robocopy", "auditpol", "gpresult", "sdbinst", "cmstp", "csc", "ftp", "tar"}


def resolve(command: str, args: dict[str, Any], platform: str) -> str:
    """Thay #{tham_số} bằng giá trị mặc định (giá trị mặc định có thể lồng tham số khác)."""
    defaults = {k: str((v or {}).get("default", "")) for k, v in (args or {}).items()}
    for _ in range(5):
        new = _PLACEHOLDER.sub(lambda m: defaults.get(m.group(1), m.group(1)), command)
        if new == command:
            break
        command = new
    return command.replace("PathToAtomicsFolder", ATOMIC_ROOT[platform]).replace("$PathToAtomicsFolder", ATOMIC_ROOT[platform])


def command_lines(command: str, executor: str) -> list[str]:
    out = []
    for line in command.replace("\r", "").split("\n"):
        line = line.strip()
        if not line:
            continue
        low = line.lower()
        if (executor == "command_prompt" and (low.startswith("rem ") or low.startswith("::"))) or \
                (executor != "command_prompt" and line.startswith("#")):
            continue
        out.append(line)
    return out


def _first_token(segment: str) -> str:
    seg = segment.strip().lstrip("@").strip()
    if seg.startswith('"'):
        return seg[1:].split('"', 1)[0]
    return seg.split()[0] if seg.split() else ""


def _segments(line: str, executor: str) -> list[str]:
    """Tách 1 dòng thành các lệnh nối bằng | && & ; (mỗi lệnh có thể là 1 tiến trình)."""
    sep = r"\s*(?:\|\||&&|\||&)\s*" if executor == "command_prompt" else r"\s*(?:\|\||&&|\||;)\s*"
    return [s for s in re.split(sep, line) if s.strip()]


def child_process(segment: str, executor: str) -> tuple[str, str] | None:
    """(tên tiến trình, đường dẫn) nếu đoạn lệnh chạy một chương trình thật; None nếu là lệnh nội bộ / cmdlet."""
    tok = _first_token(segment)
    if not tok or tok.startswith(("$", "[", "(", "{", "-", "%", "'", "<", ">")) or "=" in tok.split("\\")[-1].split("/")[-1]:
        return None
    base = re.split(r"[\\/]", tok)[-1]
    low = base.lower()
    if executor in ("command_prompt", "powershell"):
        stem = low[:-4] if low.endswith(".exe") else low
        if executor == "command_prompt" and stem in _CMD_BUILTIN:
            return None
        if executor == "powershell" and not (low.endswith(".exe") or stem in _WIN_PROGRAMS):
            return None                                   # cmdlet (Get-Process...), hàm, biểu thức
        if not re.fullmatch(r"[a-z0-9_.\-]+", stem):
            return None
        name = stem + ".exe"
        path = tok if ("\\" in tok or ":" in tok) else rf"C:\Windows\System32\{name}"
        return name, path
    if low in _SH_BUILTIN or not re.fullmatch(r"[a-z0-9_.+\-]+", low):
        return None
    return base, tok if "/" in tok else f"/usr/bin/{base}"


_CMDLET = re.compile(r"\b([A-Z][a-z]+-[A-Z][A-Za-z]+)\b")


def main_program(procs: list[tuple[str, str, str]], lines: list[str], executor: str) -> str:
    """Chương trình chính của bài thử: tiến trình con đầu tiên (reg.exe, rundll32.exe, curl...); script PowerShell
    chỉ có cmdlet thì lấy cmdlet đầu tiên (powershell Set-ItemProperty); còn lại là chính shell.
    Dùng làm biến thể của kỹ thuật không có kỹ thuật con: các bài thử cùng chương trình có chung cấu trúc lệnh."""
    children = [re.split(r"[\\/]", image)[-1].lower() for role, image, _ in procs if role == "child"]
    if children:
        return children[0]
    if executor == "powershell":
        m = next((m for line in lines if (m := _CMDLET.search(line))), None)
        return f"powershell {m.group(1)}" if m else "powershell.exe"
    return {"command_prompt": "cmd.exe"}.get(executor, executor)


def shell_command_line(executor: str, lines: list[str]) -> str:
    if executor == "command_prompt":
        return '"cmd.exe" /c ' + " & ".join(lines)
    if executor == "powershell":
        return '"powershell.exe" -Command "& {' + "; ".join(lines) + '}"'
    return f"{executor} -c '" + "; ".join(lines) + "'"


def _windows_event(n: int, image: str, cmd: str, parent: str, parent_cmd: str) -> dict[str, Any]:
    return {"event_id": 1, "channel": "Microsoft-Windows-Sysmon/Operational", "provider": "Microsoft-Windows-Sysmon",
            "computer": "atomic-win", "record_id": n,
            "fields": {"Image": image, "CommandLine": cmd[:MAX_CMD], "ParentImage": parent,
                       "ParentCommandLine": parent_cmd[:MAX_CMD], "User": "ATOMIC-WIN\\analyst",
                       "ProcessId": str(4000 + n % 60000), "CurrentDirectory": "C:\\Users\\analyst\\"}}


def atomic_events(index: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """index: nội dung atomics/Indexes/index.yaml ({tactic: {technique_id: {technique, atomic_tests}}})."""
    techniques: dict[str, dict[str, Any]] = {}
    for tactic, techs in (index or {}).items():
        for tid, t in (techs or {}).items():
            entry = techniques.setdefault(tid, {"t": t, "tactics": set()})
            entry["tactics"].add(tactic)
    n, seen = 0, set()
    for tid, entry in sorted(techniques.items()):
        meta = entry["t"].get("technique") or {}
        tactics = sorted({p.get("phase_name") for p in meta.get("kill_chain_phases") or [] if p.get("phase_name")}
                         or entry["tactics"])
        for test in entry["t"].get("atomic_tests") or []:
            ex = test.get("executor") or {}
            executor = ex.get("name")
            if executor not in SHELLS or not ex.get("command"):
                continue
            platform, shell_path = SHELLS[executor]
            if platform not in (test.get("supported_platforms") or []):
                continue
            lines = command_lines(resolve(ex["command"], test.get("input_arguments") or {}, platform), executor)
            if not lines or any(LAB_TOOLS.search(line) for line in lines):
                continue
            label = {"dataset": "atomic-red-team", "class": "attack", "technique": tid, "technique_name": meta.get("name"),
                     "tactics": tactics, "test": test.get("name"), "guid": test.get("auto_generated_guid"),
                     "platform": platform, "executor": executor, "observable": True}
            shell_cmd = shell_command_line(executor, lines)
            procs = [("shell", shell_path, shell_cmd)]
            for line in lines:
                for seg in _segments(line, executor):
                    if (cp := child_process(seg, executor)):
                        procs.append(("child", cp[1], seg))
            label["program"] = main_program(procs, lines, executor)
            for role, image, cmd in procs:
                key = (platform, tid, role, cmd[:MAX_CMD].lower())
                if key in seen:
                    continue
                seen.add(key)
                n += 1
                ts = (T0 + timedelta(seconds=n)).isoformat()
                parent = shell_path if role == "child" else (r"C:\Windows\explorer.exe" if platform == "windows" else "/bin/bash")
                parent_cmd = shell_cmd if role == "child" else ("C:\\Windows\\explorer.exe" if platform == "windows" else "bash")
                lab = {**label, "role": role}
                if platform == "windows":
                    yield {"timestamp": ts, "agent_id": "dataset-atomic-win", "hostname": "atomic-win", "os": "windows",
                           "source": "eventlog", "event_type": "windows_event",
                           "data": _windows_event(n, image, cmd, parent, parent_cmd), "label": lab}
                else:
                    yield {"timestamp": ts, "agent_id": "dataset-atomic-linux", "hostname": "atomic-linux", "os": "linux",
                           "source": "process", "event_type": "process_creation",
                           "data": {"pid": 4000 + n % 60000, "ppid": 3999, "uid": 0, "name": re.split(r"[\\/]", image)[-1],
                                    "executable": image, "command_line": cmd[:MAX_CMD],
                                    "parent_name": re.split(r"[\\/]", parent)[-1]},
                           "label": lab}
