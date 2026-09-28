"""Chuẩn hóa (normalize) event thô từ agent/syslog về lược đồ chung kiểu ECS
(Elastic Common Schema rút gọn) để rule, ML và dashboard dùng chung tên trường:

    @timestamp, event.{category,type,action,outcome,code,dataset,module},
    agent.*, host.name, source.{ip,port}, destination.{ip,port}, user.name,
    process.{pid,name,executable,command_line,parent.name}, url.*, http.*,
    user_agent.original, network.*, dns.question.name, file.path, message ...

Event thô (do agent gửi):
    {"timestamp", "agent_id", "hostname", "os", "source", "event_type", "data": {...}}
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import unquote_plus, urlsplit

Doc = dict[str, Any]


# ---------------------------------------------------------------------------
# Tiện ích
# ---------------------------------------------------------------------------

def get(doc: Doc, path: str, default: Any = None) -> Any:
    """Lấy giá trị theo đường dẫn chấm: get(doc, "source.ip")."""
    cur: Any = doc
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur


def put(doc: Doc, path: str, value: Any) -> None:
    """Gán giá trị theo đường dẫn chấm, bỏ qua giá trị rỗng."""
    if value is None or value == "" or value == "-":
        return
    parts = path.split(".")
    cur = doc
    for part in parts[:-1]:
        cur = cur.setdefault(part, {})
    cur[parts[-1]] = value


def _int(v: Any) -> int | None:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def _iso(ts: datetime) -> str:
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc).isoformat()


def _clean_ip(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v).strip().strip("[]")
    if s.startswith("::ffff:"):
        s = s[7:]
    if s in ("", "-", "::1", "127.0.0.1", "0.0.0.0", "localhost"):
        return s if s in ("::1", "127.0.0.1") else None
    return s


def _basename(path: Any) -> str | None:
    if not path:
        return None
    return re.split(r"[\\/]", str(path))[-1] or None


def _url_decode(s: str) -> str:
    # giải mã 2 lần để bắt cả payload bị encode kép (%2527 -> %27 -> ')
    return unquote_plus(unquote_plus(s))


# ---------------------------------------------------------------------------
# Apache
# ---------------------------------------------------------------------------

_APACHE_ACCESS = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<request>(?:[^"\\]|\\.)*)" '
    r'(?P<status>\d{3}) (?P<size>\S+)(?: "(?P<referer>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?'
)
_APACHE_ERROR = re.compile(
    r'^\[(?P<time>[^\]]+)\] \[(?:(?P<module>[^:\]]+):)?(?P<level>[^\]]+)\]'
    r'(?: \[pid (?P<pid>\d+)(?::tid \d+)?\])?(?: \[client (?P<client>[^\]]+)\])? (?P<msg>.*)$'
)


def parse_apache_access(line: str, doc: Doc) -> None:
    m = _APACHE_ACCESS.match(line)
    put(doc, "event.module", "apache")
    put(doc, "event.category", "web")
    if not m:
        put(doc, "event.type", "unparsed")
        return
    try:
        put(doc, "@timestamp", _iso(datetime.strptime(m["time"], "%d/%b/%Y:%H:%M:%S %z")))
    except ValueError:
        pass
    put(doc, "source.ip", _clean_ip(m["ip"]))
    put(doc, "user.name", m["user"])
    parts = m["request"].split(" ")
    if len(parts) >= 2:
        method, url = parts[0], " ".join(parts[1:-1]) if len(parts) > 2 else parts[1]
        put(doc, "http.request.method", method)
        put(doc, "http.version", parts[-1].replace("HTTP/", "") if len(parts) > 2 else None)
    else:
        url = m["request"]
    put(doc, "url.original", url)
    decoded = _url_decode(url)
    put(doc, "url.decoded", decoded)
    split = urlsplit(url)
    put(doc, "url.path", split.path)
    put(doc, "url.query", split.query)
    ext = re.search(r"\.([A-Za-z0-9]{1,6})$", split.path or "")
    put(doc, "url.extension", ext.group(1).lower() if ext else None)
    status = _int(m["status"])
    put(doc, "http.response.status_code", status)
    put(doc, "http.response.bytes", _int(m["size"]))
    put(doc, "http.request.referrer", m["referer"])
    put(doc, "user_agent.original", m["ua"])
    put(doc, "event.type", "access")
    put(doc, "event.action", "http_request")
    if status is not None:
        put(doc, "event.outcome", "success" if status < 400 else "failure")


def parse_apache_error(line: str, doc: Doc) -> None:
    put(doc, "event.module", "apache")
    put(doc, "event.category", "web")
    put(doc, "event.type", "error")
    m = _APACHE_ERROR.match(line)
    if not m:
        return
    put(doc, "log.level", m["level"])
    put(doc, "process.pid", _int(m["pid"]))
    if m["client"]:
        ip, _, port = m["client"].rpartition(":")
        put(doc, "source.ip", _clean_ip(ip or m["client"]))
        put(doc, "source.port", _int(port))
    put(doc, "error.message", m["msg"])
    try:
        put(doc, "@timestamp", _iso(datetime.strptime(m["time"], "%a %b %d %H:%M:%S.%f %Y")))
    except ValueError:
        pass


# ---------------------------------------------------------------------------
# Syslog / Linux auth
# ---------------------------------------------------------------------------

_SYSLOG_PRI = re.compile(r"^<(?P<pri>\d{1,3})>(?:1 )?")
_SYSLOG_3164 = re.compile(
    r"^(?P<time>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) (?P<host>\S+) (?P<prog>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)$"
)
_SYSLOG_ISO = re.compile(
    r"^(?P<time>\d{4}-\d\d-\d\dT\S+) (?P<host>\S+) (?P<prog>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:? ?(?:- - )?(?P<msg>.*)$"
)

_SSH_FAILED = re.compile(r"Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_SSH_ACCEPTED = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_SSH_INVALID = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>\S+)(?: port (?P<port>\d+))?")
_PAM_FAIL = re.compile(r"authentication failure;.*?(?:rhost=(?P<ip>\S*))?(?:\s+user=(?P<user>\S+))?$")
_SUDO = re.compile(r"^\s*(?P<user>\S+) : (?:(?P<fail>.*?) ; )?TTY=(?P<tty>\S+) ; PWD=(?P<pwd>\S+) ; USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.*)$")
_USERADD = re.compile(r"new user: name=(?P<user>[^,\s]+)")
_IPTABLES = re.compile(r"(?:IN=(?P<in>\S*) )?.*?SRC=(?P<src>\S+) DST=(?P<dst>\S+).*?PROTO=(?P<proto>\S+)(?:.*?SPT=(?P<spt>\d+))?(?:.*?DPT=(?P<dpt>\d+))?")


def parse_syslog_header(line: str, doc: Doc) -> tuple[str | None, str]:
    """Tách header syslog, trả về (program, message)."""
    line = _SYSLOG_PRI.sub("", line, count=1)
    for rx in (_SYSLOG_3164, _SYSLOG_ISO):
        m = rx.match(line)
        if m:
            put(doc, "host.name", m["host"])
            put(doc, "process.name", m["prog"])
            put(doc, "process.pid", _int(m["pid"]))
            if rx is _SYSLOG_ISO:
                try:
                    put(doc, "@timestamp", _iso(datetime.fromisoformat(m["time"].replace("Z", "+00:00"))))
                except ValueError:
                    pass
            return m["prog"], m["msg"]
    return None, line


def parse_auth_message(prog: str | None, msg: str, doc: Doc) -> bool:
    """Parse thông điệp xác thực Linux (sshd, sudo, useradd, pam). True nếu nhận diện được."""
    prog = (prog or "").lower()
    if m := _SSH_FAILED.search(msg):
        _auth(doc, "ssh_login", "failure", m["user"], m["ip"], m["port"])
        put(doc, "user.invalid", bool(m["invalid"]))
        return True
    if m := _SSH_ACCEPTED.search(msg):
        _auth(doc, "ssh_login", "success", m["user"], m["ip"], m["port"])
        put(doc, "auth.method", m["method"])
        return True
    if m := _SSH_INVALID.search(msg):
        _auth(doc, "ssh_invalid_user", "failure", m["user"], m["ip"], m["port"])
        put(doc, "user.invalid", True)
        return True
    if prog == "sudo" and (m := _SUDO.match(msg)):
        put(doc, "event.category", "process")
        put(doc, "event.type", "start")
        put(doc, "event.action", "sudo")
        put(doc, "event.outcome", "failure" if m["fail"] else "success")
        put(doc, "user.name", m["user"])
        put(doc, "user.target.name", m["target"])
        put(doc, "process.command_line", m["cmd"])
        put(doc, "process.name", _basename(m["cmd"].split(" ")[0]))
        return True
    if m := _USERADD.search(msg):
        put(doc, "event.category", "iam")
        put(doc, "event.type", "creation")
        put(doc, "event.action", "user_created")
        put(doc, "user.target.name", m["user"])
        return True
    if "authentication failure" in msg and (m := _PAM_FAIL.search(msg)):
        _auth(doc, "pam_auth", "failure", m["user"], m["ip"], None)
        return True
    return False


def _auth(doc: Doc, action: str, outcome: str, user: str | None, ip: str | None, port: Any) -> None:
    put(doc, "event.category", "authentication")
    put(doc, "event.type", "start")
    put(doc, "event.action", action)
    put(doc, "event.outcome", outcome)
    put(doc, "user.name", user)
    put(doc, "source.ip", _clean_ip(ip))
    put(doc, "source.port", _int(port))


def parse_firewall(msg: str, doc: Doc) -> bool:
    """iptables/UFW (kernel log) hoặc pfSense/OPNsense filterlog (CSV)."""
    if "SRC=" in msg and "DST=" in msg:
        m = _IPTABLES.search(msg)
        if not m:
            return False
        put(doc, "event.module", "iptables")
        _net(doc, m["src"], m["spt"], m["dst"], m["dpt"], m["proto"])
        upper = msg.upper()
        action = "deny" if any(k in upper for k in ("BLOCK", "DROP", "REJECT", "DENY")) else "allow"
        put(doc, "event.action", action)
        put(doc, "event.outcome", "failure" if action == "deny" else "success")
        put(doc, "observer.ingress.interface", m["in"])
        return True
    parts = msg.split(",")
    if len(parts) > 21 and parts[8] == "4" and parts[6] in ("pass", "block", "reject"):
        put(doc, "event.module", "pfsense")
        _net(doc, parts[18], parts[20], parts[19], parts[21], parts[16])
        put(doc, "event.action", "allow" if parts[6] == "pass" else "deny")
        put(doc, "event.outcome", "success" if parts[6] == "pass" else "failure")
        put(doc, "network.direction", parts[7])
        put(doc, "observer.ingress.interface", parts[4])
        return True
    return False


def _net(doc: Doc, src: Any, spt: Any, dst: Any, dpt: Any, proto: Any) -> None:
    put(doc, "event.category", "network")
    put(doc, "event.type", "connection")
    put(doc, "source.ip", _clean_ip(src))
    put(doc, "source.port", _int(spt))
    put(doc, "destination.ip", _clean_ip(dst))
    put(doc, "destination.port", _int(dpt))
    put(doc, "network.transport", str(proto).lower() if proto else None)


def parse_syslog(line: str, doc: Doc) -> None:
    put(doc, "event.module", "syslog")
    prog, msg = parse_syslog_header(line, doc)
    put(doc, "message", msg)
    if parse_auth_message(prog, msg, doc):
        put(doc, "event.module", "auth")
        return
    if parse_firewall(msg, doc):
        return
    brace = msg.find("{")
    if brace >= 0 and (prog or "").lower() == "suricata":
        try:
            parse_suricata_obj(json.loads(msg[brace:]), doc)
            return
        except ValueError:
            pass
    put(doc, "event.category", "host")
    put(doc, "event.type", "info")


def parse_auth_file(line: str, doc: Doc) -> None:
    put(doc, "event.module", "auth")
    prog, msg = parse_syslog_header(line, doc)
    put(doc, "message", msg)
    if not parse_auth_message(prog, msg, doc):
        put(doc, "event.category", "host")
        put(doc, "event.type", "info")


# ---------------------------------------------------------------------------
# Suricata (eve.json)
# ---------------------------------------------------------------------------

def parse_suricata_obj(obj: Doc, doc: Doc) -> None:
    put(doc, "event.module", "suricata")
    et = obj.get("event_type")
    put(doc, "event.dataset", f"suricata.{et}")
    if ts := obj.get("timestamp"):
        try:
            put(doc, "@timestamp", _iso(datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f%z")))
        except ValueError:
            pass
    _net(doc, obj.get("src_ip"), obj.get("src_port"), obj.get("dest_ip"), obj.get("dest_port"), obj.get("proto"))
    if et == "alert":
        a = obj.get("alert", {})
        put(doc, "event.category", "intrusion_detection")
        put(doc, "event.type", "alert")
        put(doc, "event.action", a.get("action", "allowed"))
        put(doc, "suricata.signature", a.get("signature"))
        put(doc, "suricata.signature_id", a.get("signature_id"))
        put(doc, "suricata.category", a.get("category"))
        put(doc, "suricata.severity", a.get("severity"))
    elif et == "dns":
        put(doc, "dns.question.name", (obj.get("dns") or {}).get("rrname"))
    elif et == "http":
        h = obj.get("http", {})
        put(doc, "url.domain", h.get("hostname"))
        put(doc, "url.original", h.get("url"))
        put(doc, "user_agent.original", h.get("http_user_agent"))


def parse_suricata(line: str, doc: Doc) -> None:
    try:
        parse_suricata_obj(json.loads(line), doc)
    except ValueError:
        put(doc, "event.module", "suricata")
        put(doc, "event.type", "unparsed")


# ---------------------------------------------------------------------------
# Windows Event Log (Security / System / Sysmon / PowerShell / Defender)
# ---------------------------------------------------------------------------

_LOGON_TYPES = {"2": "interactive", "3": "network", "4": "batch", "5": "service",
                "7": "unlock", "8": "network_cleartext", "10": "remote_interactive", "11": "cached"}


def parse_windows(data: Doc, doc: Doc) -> None:
    f: Doc = data.get("fields") or {}
    eid = _int(data.get("event_id")) or 0
    channel = str(data.get("channel") or "")
    provider = str(data.get("provider") or "")
    put(doc, "event.module", "windows")
    put(doc, "event.code", eid)
    put(doc, "winlog.channel", channel)
    put(doc, "winlog.provider_name", provider)
    put(doc, "winlog.record_id", data.get("record_id"))
    put(doc, "host.name", data.get("computer"))
    put(doc, "winlog.event_data", {k: v for k, v in f.items() if v not in ("", "-")})

    sysmon = "Sysmon" in channel or "Sysmon" in provider
    if sysmon:
        put(doc, "event.module", "sysmon")
        _windows_sysmon(eid, f, doc)
        return
    if "PowerShell" in channel and eid == 4104:
        put(doc, "event.category", "process")
        put(doc, "event.type", "info")
        put(doc, "event.action", "powershell_script_block")
        put(doc, "powershell.script_block", f.get("ScriptBlockText"))
        put(doc, "process.name", "powershell.exe")
        return
    if "Defender" in channel and eid in (1116, 1117):
        put(doc, "event.category", "malware")
        put(doc, "event.type", "info")
        put(doc, "event.action", "malware_detected" if eid == 1116 else "malware_action_taken")
        put(doc, "threat.name", f.get("Threat Name"))
        put(doc, "file.path", f.get("Path"))
        return

    if eid in (4624, 4625):
        ok = eid == 4624
        put(doc, "event.category", "authentication")
        put(doc, "event.type", "start")
        put(doc, "event.action", "logon")
        put(doc, "event.outcome", "success" if ok else "failure")
        put(doc, "user.name", f.get("TargetUserName"))
        put(doc, "user.domain", f.get("TargetDomainName"))
        put(doc, "source.ip", _clean_ip(f.get("IpAddress")))
        put(doc, "source.port", _int(f.get("IpPort")))
        put(doc, "winlog.logon.type", _LOGON_TYPES.get(str(f.get("LogonType")), f.get("LogonType")))
        if not ok:
            put(doc, "winlog.logon.failure_status", f.get("Status"))
    elif eid == 4688:
        put(doc, "event.category", "process")
        put(doc, "event.type", "start")
        put(doc, "event.action", "process_created")
        put(doc, "process.executable", f.get("NewProcessName"))
        put(doc, "process.name", _basename(f.get("NewProcessName")))
        put(doc, "process.command_line", f.get("CommandLine"))
        put(doc, "process.pid", _int_hex(f.get("NewProcessId")))
        put(doc, "process.parent.executable", f.get("ParentProcessName"))
        put(doc, "process.parent.name", _basename(f.get("ParentProcessName")))
        put(doc, "user.name", f.get("SubjectUserName"))
    elif eid == 4720:
        _iam(doc, "user_created", "creation", f)
    elif eid in (4728, 4732, 4756):
        _iam(doc, "group_member_added", "change", f)
        put(doc, "group.name", f.get("TargetUserName"))
        put(doc, "user.target.name", f.get("MemberName") or f.get("MemberSid"))
    elif eid == 4740:
        _iam(doc, "account_locked", "change", f)
    elif eid == 1102 or (eid == 104 and channel == "System"):
        put(doc, "event.category", "configuration")
        put(doc, "event.type", "deletion")
        put(doc, "event.action", "audit_log_cleared")
        put(doc, "user.name", f.get("SubjectUserName"))
    elif eid == 7045:
        put(doc, "event.category", "configuration")
        put(doc, "event.type", "creation")
        put(doc, "event.action", "service_installed")
        put(doc, "service.name", f.get("ServiceName"))
        put(doc, "process.executable", f.get("ImagePath"))
        put(doc, "process.command_line", f.get("ImagePath"))
    elif eid == 4698:
        put(doc, "event.category", "configuration")
        put(doc, "event.type", "creation")
        put(doc, "event.action", "scheduled_task_created")
        put(doc, "user.name", f.get("SubjectUserName"))
    else:
        put(doc, "event.category", "host")
        put(doc, "event.type", "info")


def _iam(doc: Doc, action: str, typ: str, f: Doc) -> None:
    put(doc, "event.category", "iam")
    put(doc, "event.type", typ)
    put(doc, "event.action", action)
    put(doc, "user.name", f.get("SubjectUserName"))
    put(doc, "user.target.name", f.get("TargetUserName"))


def _int_hex(v: Any) -> int | None:
    if v is None:
        return None
    s = str(v).strip()
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    except ValueError:
        return None


def _windows_sysmon(eid: int, f: Doc, doc: Doc) -> None:
    if eid == 1:
        put(doc, "event.category", "process")
        put(doc, "event.type", "start")
        put(doc, "event.action", "process_created")
        put(doc, "process.executable", f.get("Image"))
        put(doc, "process.name", _basename(f.get("Image")))
        put(doc, "process.command_line", f.get("CommandLine"))
        put(doc, "process.pid", _int(f.get("ProcessId")))
        put(doc, "process.parent.executable", f.get("ParentImage"))
        put(doc, "process.parent.name", _basename(f.get("ParentImage")))
        put(doc, "process.parent.command_line", f.get("ParentCommandLine"))
        put(doc, "user.name", f.get("User"))
        for part in str(f.get("Hashes") or "").split(","):
            if "=" in part:
                algo, val = part.split("=", 1)
                put(doc, f"process.hash.{algo.strip().lower()}", val.strip().lower())
    elif eid == 3:
        _net(doc, f.get("SourceIp"), f.get("SourcePort"), f.get("DestinationIp"), f.get("DestinationPort"), f.get("Protocol"))
        put(doc, "event.action", "network_connection")
        put(doc, "process.executable", f.get("Image"))
        put(doc, "process.name", _basename(f.get("Image")))
        put(doc, "process.pid", _int(f.get("ProcessId")))
        put(doc, "destination.domain", f.get("DestinationHostname"))
    elif eid == 11:
        put(doc, "event.category", "file")
        put(doc, "event.type", "creation")
        put(doc, "event.action", "file_created")
        put(doc, "file.path", f.get("TargetFilename"))
        put(doc, "process.executable", f.get("Image"))
        put(doc, "process.name", _basename(f.get("Image")))
    elif eid in (12, 13, 14):
        put(doc, "event.category", "registry")
        put(doc, "event.type", "change")
        put(doc, "event.action", "registry_modified")
        put(doc, "registry.path", f.get("TargetObject"))
        put(doc, "registry.value", f.get("Details"))
        put(doc, "process.name", _basename(f.get("Image")))
    elif eid == 22:
        put(doc, "event.category", "network")
        put(doc, "event.type", "protocol")
        put(doc, "event.action", "dns_query")
        put(doc, "dns.question.name", f.get("QueryName"))
        put(doc, "process.name", _basename(f.get("Image")))
    elif eid == 10:
        put(doc, "event.category", "process")
        put(doc, "event.type", "access")
        put(doc, "event.action", "process_access")
        put(doc, "process.name", _basename(f.get("SourceImage")))
        put(doc, "process.target.name", _basename(f.get("TargetImage")))
        put(doc, "process.target.granted_access", f.get("GrantedAccess"))
    else:
        put(doc, "event.category", "host")
        put(doc, "event.type", "info")


# ---------------------------------------------------------------------------
# Linux process (agent) & mock
# ---------------------------------------------------------------------------

def parse_process(data: Doc, doc: Doc) -> None:
    put(doc, "event.module", "process")
    put(doc, "event.category", "process")
    put(doc, "event.type", "start")
    put(doc, "event.action", "process_created")
    put(doc, "process.pid", _int(data.get("pid")))
    put(doc, "process.parent.pid", _int(data.get("ppid")))
    put(doc, "process.name", data.get("name"))
    put(doc, "process.executable", data.get("executable"))
    put(doc, "process.command_line", data.get("command_line"))
    put(doc, "process.parent.name", data.get("parent_name"))
    put(doc, "user.id", data.get("uid"))


_FIM_TYPE = {"added": ("creation", "file_created"), "modified": ("change", "file_modified"),
             "deleted": ("deletion", "file_deleted")}


def parse_fim(data: Doc, doc: Doc) -> None:
    """Giám sát toàn vẹn file của agent: file được thêm / sửa / xóa kèm hash trước và sau."""
    path = str(data.get("path") or "")
    etype, action = _FIM_TYPE.get(str(data.get("action")), ("change", "file_modified"))
    put(doc, "event.module", "fim")
    put(doc, "event.category", "file")
    put(doc, "event.type", etype)
    put(doc, "event.action", action)
    put(doc, "file.path", path)
    name = _basename(path)
    put(doc, "file.name", name)
    if name and "." in name:
        put(doc, "file.extension", name.rsplit(".", 1)[1].lower())
    put(doc, "file.directory", path[: len(path) - len(name or "")].rstrip("/\\") or None)
    put(doc, "file.size", _int(data.get("size")))
    put(doc, "file.mode", data.get("mode"))
    put(doc, "file.mtime", data.get("mtime"))
    put(doc, "file.hash.sha256", data.get("sha256"))
    put(doc, "file.target_path", data.get("link_target"))
    put(doc, "fim.changes", data.get("changes"))
    put(doc, "fim.old.sha256", data.get("old_sha256"))
    put(doc, "fim.old.size", _int(data.get("old_size")))
    put(doc, "fim.old.mode", data.get("old_mode"))
    put(doc, "message", data.get("message"))


def parse_agent_audit(data: Doc, doc: Doc) -> None:
    """Sự kiện quản trị agent do chính manager phát ra (enroll, thu hồi, enroll trùng...)."""
    put(doc, "event.module", "siem-manager")
    put(doc, "event.category", "iam")
    put(doc, "event.type", "change")
    put(doc, "event.action", data.get("action"))
    put(doc, "event.outcome", data.get("outcome"))
    put(doc, "source.ip", _clean_ip(data.get("ip")))
    put(doc, "user.name", data.get("analyst"))
    put(doc, "siem.target_agent", data.get("target_agent"))
    put(doc, "message", f"{data.get('action')} {data.get('target_agent')}: {data.get('detail') or ''}".strip())


def parse_mock(data: Doc, doc: Doc) -> None:
    put(doc, "event.module", "mock")
    _auth(doc, "logon", "success" if data.get("success") else "failure",
          data.get("user"), data.get("src_ip"), None)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

_LINE_PARSERS: dict[str, Callable[[str, Doc], None]] = {
    "apache_access": parse_apache_access,
    "apache_error": parse_apache_error,
    "auth": parse_auth_file,
    "syslog": parse_syslog,
    "suricata": parse_suricata,
}


def normalize(raw: Doc) -> Doc:
    data: Doc = raw.get("data") or {}
    etype = str(raw.get("event_type") or "")
    source = str(raw.get("source") or "")
    now = datetime.now(timezone.utc).isoformat()

    doc: Doc = {
        "@timestamp": raw.get("timestamp") or now,
        "event": {"id": uuid.uuid4().hex, "ingested": now, "dataset": etype, "kind": "event"},
        "agent": {k: v for k, v in {
            "id": raw.get("agent_id"), "hostname": raw.get("hostname"),
            "os": raw.get("os"), "ip": raw.get("agent_ip")}.items() if v},
        "raw": data,
    }
    put(doc, "host.name", raw.get("hostname"))
    put(doc, "log.file.path", data.get("path"))
    line = data.get("message")

    try:
        if etype in _LINE_PARSERS and isinstance(line, str):
            put(doc, "message", line)
            _LINE_PARSERS[etype](line, doc)
        elif etype == "windows_event":
            parse_windows(data, doc)
        elif etype == "process_creation":
            parse_process(data, doc)
        elif etype == "agent_audit" and source == "manager":
            parse_agent_audit(data, doc)
        elif etype == "fim":
            parse_fim(data, doc)
        elif source == "mock":
            parse_mock(data, doc)
        else:
            put(doc, "message", line if isinstance(line, str) else json.dumps(data, ensure_ascii=False)[:2000])
    except Exception as e:  # noqa: BLE001 - parser lỗi không được làm rơi event
        put(doc, "error.message", f"normalize error: {e}")

    if source == "syslog":
        put(doc, "observer.ip", data.get("sender_ip"))
        if not get(doc, "host.name"):
            put(doc, "host.name", data.get("sender_ip"))
    doc["event"].setdefault("category", "host")
    return doc
