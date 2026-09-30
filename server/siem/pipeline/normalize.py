"""Chuẩn hóa (normalize) event thô về lược đồ chung kiểu ECS (Elastic Common Schema rút gọn)
để rule, ML và dashboard dùng chung tên trường:

    @timestamp, event.{category,type,action,outcome,code,dataset,module},
    agent.*, host.name, source.{ip,port}, destination.{ip,port}, user.name,
    process.{pid,name,executable,command_line,parent.name}, url.*, http.*,
    user_agent.original, network.*, dns.question.name, file.path, message ...

Event thô: {"timestamp", "agent_id", "hostname", "os", "source", "event_type", "data": {...}}
  - event_type wazuh / wazuh_alert: event của Wazuh manager (data = 1 dòng archives.json / alerts.json)
  - event_type syslog: dòng syslog do Vector nhận (firewall, Suricata...)
  - event_type console_auth: đăng nhập / quản lý tài khoản của SOC console (manager/auth.py)
  - apache_access, windows_event, process_creation...: định dạng nội bộ, dataset công khai
    (tools/convert_datasets.py) và unit test dùng; parser Wazuh cũng chuyển dòng log gốc qua các parser này
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


def parse_console(data: Doc, doc: Doc) -> None:
    """Đăng nhập / quản lý tài khoản của chính SOC console (manager/auth.py). Đăng nhập là event xác thực như SSH,
    nên hiện ở mục Phiên đăng nhập trên Grafana và rule brute-force (AUTH-001) áp dụng được cho console."""
    action, outcome = str(data.get("action") or ""), data.get("outcome") or "success"
    put(doc, "host.name", "soc-console")
    if action in ("login", "logout"):
        _auth(doc, f"console_{action}", outcome, data.get("user"), data.get("ip"), None)
        if action == "logout":
            put(doc, "event.type", "end")
    else:     # password_changed, user_created, user_updated
        put(doc, "event.category", "iam")
        put(doc, "event.type", "creation" if action == "user_created" else "change")
        put(doc, "event.action", f"console_{action}")
        put(doc, "event.outcome", outcome)
        put(doc, "user.name", data.get("user"))
        put(doc, "user.target.name", data.get("target"))
        put(doc, "source.ip", _clean_ip(data.get("ip")))
    put(doc, "event.module", "console")
    put(doc, "user.roles", data.get("role") or data.get("target_role"))
    put(doc, "event.reason", data.get("reason") or data.get("change"))
    put(doc, "message", f"console {action} {outcome}: {data.get('user')}"
                        + (f" -> {data['target']}" if data.get("target") else "")
                        + (f" ({data.get('reason') or data.get('change')})" if data.get("reason") or data.get("change") else ""))


def parse_mock(data: Doc, doc: Doc) -> None:
    put(doc, "event.module", "mock")
    _auth(doc, "logon", "success" if data.get("success") else "failure",
          data.get("user"), data.get("src_ip"), None)


# ---------------------------------------------------------------------------
# Wazuh (archives.json / alerts.json của wazuh-manager, Vector đưa vào Kafka)
# ---------------------------------------------------------------------------
# Event Wazuh: {"timestamp", "agent": {id, name, ip}, "full_log" (dòng log gốc), "location" (file / kênh nguồn),
#   "decoder": {name}, "data": {...trường đã giải mã...}, "rule": {...} (nếu khớp rule Wazuh), "syscheck": {...} (FIM)}.
# Dòng log gốc (Apache, auth.log, Suricata...) được đưa qua ĐÚNG parser đã có ở trên, nên rule của siem-xdr
# chạy y như trước. Windows: data.win (eventdata dạng camelCase) được đổi về dạng parse_windows đang đọc.

_WAZUH_TS = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?)\d*([+-]\d\d):?(\d\d)$")
_ACCESS_LOC = re.compile(r"access[._]log", re.I)
_ERROR_LOC = re.compile(r"error[._]log", re.I)
_AUTH_LOC = re.compile(r"/(auth\.log|secure)$")
# dòng do script của siem-xdr cài trên agent in ra (wazuh/agent/linux/)
_SIEM_PROC = re.compile(r"siem-proc: pid=(?P<pid>\d+) ppid=(?P<ppid>\d+) uid=(?P<uid>\d*) name=(?P<name>\S*) "
                        r"parent=(?P<parent>\S*) exe=(?P<exe>\S*) cmd=(?P<cmd>.*)$")
_SIEM_XDR = re.compile(r"siem-xdr: action=(?P<id>[0-9a-f]{8,64}) type=(?P<type>[a-z_]+) target=(?P<target>\S*) "
                       r"status=(?P<status>success|failed)(?: detail=(?P<detail>.*))?$")
_FIM_EVENTS = {"added": ("creation", "file_created"), "modified": ("change", "file_modified"),
               "deleted": ("deletion", "file_deleted")}


def _wazuh_ts(ts: Any) -> str | None:
    m = _WAZUH_TS.match(str(ts or ""))
    if not m:
        return None
    try:
        return _iso(datetime.fromisoformat(f"{m[1]}{m[2]}:{m[3]}"))
    except ValueError:
        return None


def parse_wazuh(ev: Doc, doc: Doc) -> None:
    ag = ev.get("agent") if isinstance(ev.get("agent"), dict) else {}
    if ev.get("id"):
        # id của Wazuh (duy nhất trên manager) -> đọc lại không tạo bản ghi trùng; archives và alerts cùng 1 event
        doc["event"]["id"] = f"wazuh-{ag.get('id', '000')}-{ev['id']}"
    doc["agent"] = {k: v for k, v in {"id": ag.get("id"), "name": ag.get("name"), "hostname": ag.get("name"),
                                      "ip": ag.get("ip"), "type": "wazuh"}.items() if v}
    put(doc, "host.name", ag.get("name"))
    put(doc, "@timestamp", _wazuh_ts(ev.get("timestamp")))
    loc = str(ev.get("location") or "")
    full = ev["full_log"] if isinstance(ev.get("full_log"), str) else ""
    decoder = str((ev.get("decoder") or {}).get("name") or "")
    data = ev["data"] if isinstance(ev.get("data"), dict) else {}
    wz: Doc = {"id": ev.get("id"), "location": loc, "decoder": decoder, "manager": (ev.get("manager") or {}).get("name")}
    rule = ev.get("rule")
    if isinstance(rule, dict):
        wz["rule"] = {k: rule[k] for k in ("id", "level", "description", "groups", "mitre", "firedtimes") if k in rule}
    doc["wazuh"] = {k: v for k, v in wz.items() if v not in (None, "")}
    if loc.startswith("/") or re.match(r"^[A-Za-z]:\\", loc):
        put(doc, "log.file.path", loc)
    put(doc, "event.module", "wazuh")

    if isinstance(ev.get("syscheck"), dict):
        _wazuh_fim(ev["syscheck"], doc)
    elif isinstance(data.get("win"), dict):
        _wazuh_windows(data["win"], doc, ag.get("name"))
    elif full and (m := _SIEM_XDR.search(full)):
        _wazuh_response(m, doc)
    elif full and (m := _SIEM_PROC.search(full)):
        parse_process({"pid": m["pid"], "ppid": m["ppid"], "uid": m["uid"], "name": m["name"], "executable": m["exe"],
                       "command_line": m["cmd"], "parent_name": m["parent"]}, doc)
    elif isinstance(data.get("audit"), dict) and _wazuh_audit(data["audit"], doc):
        pass
    elif isinstance(data.get("sca"), dict):
        _wazuh_sca(data["sca"], doc, full)
    elif loc == "rootcheck":
        put(doc, "event.module", "rootcheck")
        put(doc, "event.category", "intrusion_detection")
        put(doc, "event.type", "info")
        put(doc, "event.action", "rootcheck")
        put(doc, "message", full)
    elif full:
        put(doc, "message", full)
        if decoder == "web-accesslog" or _ACCESS_LOC.search(loc):
            parse_apache_access(full, doc)
        elif decoder.startswith("apache") or _ERROR_LOC.search(loc):
            parse_apache_error(full, doc)
        elif loc.endswith("eve.json"):
            parse_suricata(full, doc)
        elif _AUTH_LOC.search(loc):
            parse_auth_file(full, doc)
        else:
            parse_syslog(full, doc)
    else:
        put(doc, "message", (rule or {}).get("description") or json.dumps(data, ensure_ascii=False)[:2000])


def _wazuh_fim(sc: Doc, doc: Doc) -> None:
    typ, action = _FIM_EVENTS.get(str(sc.get("event")), ("change", "file_changed"))
    path = str(sc.get("path") or "")
    registry = path.upper().startswith("HKEY_")
    put(doc, "event.module", "fim")
    put(doc, "event.category", "registry" if registry else "file")
    put(doc, "event.type", typ)
    put(doc, "event.action", action.replace("file_", "registry_") if registry else action)
    if registry:
        put(doc, "registry.path", path)
        put(doc, "registry.value", sc.get("value_name"))
    else:
        put(doc, "file.path", path)
        put(doc, "file.name", _basename(path))
        put(doc, "file.size", _int(sc.get("size_after")))
        put(doc, "file.mode", sc.get("perm_after") if isinstance(sc.get("perm_after"), str) else None)
        put(doc, "file.owner", sc.get("uname_after"))
        put(doc, "file.hash.md5", sc.get("md5_after"))
        put(doc, "file.hash.sha256", sc.get("sha256_after"))
    put(doc, "file.changed_attributes", sc.get("changed_attributes"))
    who = sc.get("audit") if isinstance(sc.get("audit"), dict) else {}      # chế độ whodata: ai / tiến trình nào sửa
    put(doc, "user.name", (who.get("user") or {}).get("name"))
    proc = who.get("process") if isinstance(who.get("process"), dict) else {}
    put(doc, "process.executable", proc.get("name"))
    put(doc, "process.name", _basename(proc.get("name")))
    put(doc, "process.pid", _int(proc.get("id")))
    put(doc, "message", f"FIM {sc.get('event', 'changed')}: {path}")


def _wazuh_windows(win: Doc, doc: Doc, agent_name: Any) -> None:
    sysd = win.get("system") if isinstance(win.get("system"), dict) else {}
    ed = win.get("eventdata") if isinstance(win.get("eventdata"), dict) else {}
    fields = {k[:1].upper() + k[1:]: v for k, v in ed.items() if isinstance(k, str) and k}   # targetUserName -> TargetUserName
    parse_windows({"event_id": sysd.get("eventID"), "channel": sysd.get("channel"), "provider": sysd.get("providerName"),
                   "computer": sysd.get("computer"), "record_id": sysd.get("eventRecordID"), "fields": fields}, doc)
    put(doc, "winlog.computer_name", sysd.get("computer"))
    put(doc, "host.name", agent_name)   # tên agent (khớp assets.yml), không phải FQDN của computer
    if isinstance(sysd.get("message"), str):
        put(doc, "message", sysd["message"].strip('"'))


def _wazuh_audit(audit: Doc, doc: Doc) -> bool:
    """auditd (Linux thật, log_format audit): EXECVE / SYSCALL execve -> tiến trình mới.
    auditd không ghi tên tiến trình cha, nên rule cần process.parent.name (LNX-002) không bắt được từ nguồn này."""
    execve = audit.get("execve") if isinstance(audit.get("execve"), dict) else {}
    if not execve and str(audit.get("syscall")) not in ("59", "322"):
        return False
    args = [str(execve[f"a{i}"]) for i in range(len(execve)) if f"a{i}" in execve]
    exe = audit.get("exe")
    parse_process({"pid": audit.get("pid"), "ppid": audit.get("ppid"), "uid": audit.get("auid") or audit.get("uid"),
                   "name": audit.get("command") or _basename(exe), "executable": exe,
                   "command_line": " ".join(args) or None}, doc)
    put(doc, "event.module", "auditd")
    return True


def _wazuh_sca(sca: Doc, doc: Doc, full: str) -> None:
    chk = sca.get("check") if isinstance(sca.get("check"), dict) else {}
    put(doc, "event.module", "sca")
    put(doc, "event.category", "configuration")
    put(doc, "event.type", "info")
    put(doc, "event.action", f"sca_{sca.get('type') or 'check'}")
    put(doc, "sca.policy", sca.get("policy"))
    put(doc, "sca.check.id", chk.get("id"))
    put(doc, "sca.check.title", chk.get("title"))
    put(doc, "sca.check.result", chk.get("result"))
    put(doc, "message", chk.get("title") or full or sca.get("policy"))


def _wazuh_response(m: re.Match, doc: Doc) -> None:
    """Kết quả lệnh phản ứng do script siem-xdr trên agent ghi vào active-responses.log (SOAR đọc để cập nhật lệnh)."""
    put(doc, "event.module", "siem-xdr")
    put(doc, "event.category", "host")
    put(doc, "event.type", "info")
    put(doc, "event.action", "response_result")
    put(doc, "event.outcome", "success" if m["status"] == "success" else "failure")
    doc["siem"] = {"action": {k: v for k, v in {"id": m["id"], "type": m["type"], "target": m["target"],
                                                 "status": m["status"], "output": m["detail"]}.items() if v}}
    put(doc, "message", m.group(0))


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
        elif etype in ("wazuh", "wazuh_alert"):
            parse_wazuh(data, doc)
        elif etype == "console_auth":
            parse_console(data, doc)
        elif etype == "windows_event":
            parse_windows(data, doc)
        elif etype == "process_creation":
            parse_process(data, doc)
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
