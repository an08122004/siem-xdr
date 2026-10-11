"""Kiểm định tự động đề xuất của AI — hoàn toàn độc lập với LLM (không tin output của model).

Ngoại lệ (giảm cảnh báo) — rủi ro cao nhất vì có thể "làm mù" SIEM:
  cấu trúc, trường có thật, toán tử, regex an toàn, đủ hẹp (neo vào thực thể cụ thể),
  khớp phần lớn báo nhầm, KHÔNG khớp event nào của sự cố thật (case) và của BỘ MẪU VÀNG (dataset),
  replay dữ liệu thật để ước lượng số alert bị tắt, hiệu năng.
Rule mới:
  cấu trúc, trường có thật, regex an toàn, ID không trùng, bắt được mẫu nghi vấn ở TẬP KIỂM TRA
  (tách riêng với mẫu đưa cho LLM -> tránh học vẹt), báo nhầm trên tập bình thường, số alert/ngày khi
  replay dữ liệu thật, hiệu năng.
"""
from __future__ import annotations

import re
import time
from dataclasses import asdict, dataclass, replace
from datetime import datetime
from typing import Any
from urllib.parse import unquote_plus

from ..detection.rules import Rule, RuleEngine, RuleException, _eval, regex_risk
from ..pipeline.normalize import Doc, get
from .atomic import ARTIFACT_RE
from .golden import PublicDatasets
from .prompts import EXC_OPS, RULE_OPS

FIELD_RE = re.compile(r"^[a-z_@][a-z0-9_.@]*$")
SPECIFIC_OPS = {"eq", "in", "cidr", "startswith"}
GENERIC_PREFIXES = ("event.", "message", "log.", "tags")
_SEGMENT = re.compile(r"[^a-z0-9_.\-~]+")
SCOPE_FIELDS = {"event.category", "event.module", "event.action", "event.code", "event.dataset", "event.type"}
COMMAND_FIELDS = {"process.command_line", "process.parent.command_line"}
MIN_COMMAND_LITERAL = 4      # đoạn chữ ngắn hơn (vd "/c", "-e") khớp quá nhiều dòng lệnh hợp lệ
_BARE_WORD = re.compile(r"-{0,2}[A-Za-z][A-Za-z0-9_-]*")   # một từ / cmdlet / cờ đứng riêng
# chỉ là đuôi file (.inf, .dll, .ps1): chạy thật 8/10, `CommandLine|contains: '.inf'` qua kiểm định vì tập bình thường
# nhỏ không có lệnh cài driver / đường dẫn C:\Windows\inf nào
_EXTENSION = re.compile(r"\.[A-Za-z0-9]{1,5}")

# URL bình thường của một website bất kỳ. Tập bình thường CSIC chỉ có một ứng dụng (/tienda1/...), không có
# URL thư mục, trang tĩnh, API... nên rule kiểu `url endswith "/"` vẫn đạt 0 báo nhầm trên CSIC. Rule web
# khớp bất kỳ URL nào dưới đây là quá chung chung.
ORDINARY_URLS = [
    "/", "/index.html", "/images/", "/images/logo.png", "/css/site.css", "/js/app.min.js", "/favicon.ico",
    "/robots.txt", "/about-us", "/news/", "/blog/2024/05/hello-world/", "/login", "/account/settings",
    "/products?category=shoes&sort=price-asc&page=2", "/search?q=summer+sale", "/search?q=O%27Brien+%26+Sons",
    "/api/v1/users/42", "/api/v1/orders?status=open&limit=20", "/docs/guide.html", "/download?file=report-2024.pdf",
    "/cart/add?id=17&qty=1", "/?lang=en", "/contact?name=Anna&email=anna%40example.com&msg=Hi%2C+see+you+at+5",
    # thêm 8/10: trang quản trị / CMS / thư mục script có trên rất nhiều website thật, và câu tìm kiếm chứa từ khóa SQL
    # (chạy thử 8/10: rule "tài nguyên nhạy cảm" chứa /admin/, /scripts/ vẫn qua vì CSIC chỉ có một ứng dụng)
    "/admin/", "/admin/login?next=%2Fadmin%2F", "/wp-admin/", "/wp-login.php", "/scripts/app.js",
    "/scripts/vendor/jquery.min.js", "/static/css/main.css", "/user/profile?tab=security",
    "/search?q=union+square+hotels", "/search?q=select+comfort+mattress", "/docs/sql/union-select.html",
    "/forum/topic?id=812&title=Don%27t+drop+the+table", "/feed.xml", "/sitemap.xml", "/.well-known/security.txt",
]


def _ordinary_doc(u: str) -> Doc:
    path, _, query = u.partition("?")
    return {"event": {"category": "web", "module": "apache", "type": "access"},
            "http": {"request": {"method": "GET"}, "response": {"status_code": 200}},
            "url": {"original": u, "path": path, "query": query, "decoded": unquote_plus(u)}}


ORDINARY_DOCS = [_ordinary_doc(u) for u in ORDINARY_URLS]


def ordinary_hits(cond) -> list[str]:
    """URL bình thường mà điều kiện khớp (chỉ xét nếu điều kiện dùng trường url.*)."""
    return [get(d, "url.original") for d in ORDINARY_DOCS if cond.match(d)]


@dataclass
class Check:
    name: str
    ok: bool
    detail: str
    blocking: bool = True


@dataclass
class Validation:
    passed: bool
    risk: str
    checks: list[Check]
    metrics: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"passed": self.passed, "risk": self.risk, "checks": [asdict(c) for c in self.checks],
                "metrics": self.metrics}


# ---------------------------------------------------------------- tiện ích
_BAD_ESCAPE = set("cCeEgGhHiIjJkKlLmMoOpPqQRTVXyYz")   # chữ sau '\' mà re của Python không nhận là mã thoát


def fix_regex(pattern: Any) -> Any:
    """Model viết đường dẫn Windows thẳng vào regex (C:\\ProgramData\\Microsoft\\..., C:\\Users\\...): '\\P', '\\M' là mã
    thoát sai, '\\U' là mã thoát dở dang, còn '\\W', '\\S' biên dịch được nhưng sai nghĩa (ký tự không phải chữ...).
    Chỉ khi regex BIÊN DỊCH LỖI mới sửa: '\\' + chữ cái mà ngay sau là chữ cái nữa (\\Windows, \\Users, \\sam) hoặc chữ
    không phải mã thoát nào được hiểu là dấu '\\' thật của đường dẫn. Giữ mã regex thật: \\s+, \\d*, \\W đứng riêng, \\b."""
    if not isinstance(pattern, str):
        return pattern
    try:
        re.compile(pattern)
        return pattern
    except re.error:
        pass
    out, i = [], 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern):
            nxt = pattern[i + 1]
            after = pattern[i + 2] if i + 2 < len(pattern) else ""
            path_sep = nxt.isalpha() and nxt != "b" and (nxt in _BAD_ESCAPE or after.isalpha())
            out.append("\\\\" + nxt if path_sep else ch + nxt)
            i += 2
            continue
        out.append(ch)
        i += 1
    fixed = "".join(out)
    try:
        re.compile(fixed)
        return fixed
    except re.error:
        return pattern            # vẫn lỗi (vd bị cắt giữa chừng) -> để kiểm định báo sai cấu trúc


def build_condition(match: str, clauses: list[dict[str, Any]]) -> dict[str, Any]:
    leaves = []
    for c in clauses:
        op, val = str(c.get("op", "eq")), c.get("value")
        if op in ("in", "cidr") and not isinstance(val, list):
            val = [val]
        if op == "eq" and isinstance(val, list):
            op = "in"
        if isinstance(val, str):
            val = val.strip()
        if op == "regex":
            val = [fix_regex(v) for v in val] if isinstance(val, list) else fix_regex(val)
        leaves.append({"field": str(c.get("field", "")).strip(), "op": op, "value": val})
    return {"any" if match == "any" else "all": leaves}


def leaves_of(cond: Any, positive_only: bool = False) -> list[dict[str, Any]]:
    """Mọi lá {field, op, value} của cây điều kiện (rule Sigma biên dịch ra cây lồng all / any / not).
    positive_only: bỏ lá nằm dưới `not` (filter loại trừ không làm rule bắt thêm gì)."""
    if isinstance(cond, list):
        return [x for c in cond for x in leaves_of(c, positive_only)]
    if not isinstance(cond, dict):
        return []
    if "field" in cond:
        return [cond]
    if "not" in cond:
        return [] if positive_only else leaves_of(cond["not"])
    return [x for k in ("all", "any") for x in leaves_of(cond.get(k) or [], positive_only)]


def missing_fields(cond: Any, docs: list[Doc]) -> list[str]:
    """Trường mà việc thiếu nó trong dữ liệu làm một nhánh không bao giờ khớp. Nhánh OR chỉ tính khi MỌI lựa chọn
    đều thiếu (Sigma web: cs-uri-query -> url.query hoặc url.decoded; request không có query vẫn có url.decoded)."""
    if isinstance(cond, list):
        cond = {"all": cond}
    if "field" in cond:
        return [] if any(get(d, cond["field"]) is not None for d in docs) else [cond["field"]]
    if "not" in cond:
        return []
    if "any" in cond:
        parts = [missing_fields(c, docs) for c in cond["any"]]
        return [] if any(not m for m in parts) else sorted({f for m in parts for f in m})
    return sorted({f for c in cond.get("all") or [] for f in missing_fields(c, docs)})


def span_days(events: list[Doc]) -> float:
    ts = [e.get("@timestamp") for e in events if isinstance(e.get("@timestamp"), str)]
    if len(ts) < 2:
        return 1.0
    try:
        a = datetime.fromisoformat(min(ts).replace("Z", "+00:00"))
        b = datetime.fromisoformat(max(ts).replace("Z", "+00:00"))
    except ValueError:
        return 1.0
    return max((b - a).total_seconds() / 86400, 1 / 24)


def replay(rule: Rule, events: list[Doc]) -> tuple[int, float]:
    eng = RuleEngine([rule])
    t0 = time.perf_counter()
    n = sum(len(eng.process(e)) for e in events)
    return n, time.perf_counter() - t0


def scope_match(rule: Rule, doc: Doc) -> bool:
    """Rule có 'xem xét' loại event này không: chỉ đánh giá các mệnh đề phạm vi
    (event.category/module/action/code...), bỏ qua mệnh đề chi tiết."""
    def ev(node) -> bool:
        kind = node[0]
        if kind == "all":
            return all(ev(n) for n in node[1])
        if kind == "any":
            return any(ev(n) for n in node[1])
        if kind == "not":
            return True
        if node[1] not in SCOPE_FIELDS:
            return True
        return _eval(node, doc)
    conds = [rule.condition] if rule.condition else [c for c, _ in rule.steps]
    return any(ev(c.spec) for c in conds if c is not None)


def _regex_problems(clauses: list[dict[str, Any]]) -> list[str]:
    out = []
    for c in clauses:
        if c["op"] == "regex":
            for p in c["value"] if isinstance(c["value"], list) else [c["value"]]:
                if (why := regex_risk(str(p))):
                    out.append(f"{c['field']}: {why}")
    return out


def _app_specific(clauses: list[dict[str, Any]], app_tokens: set[str]) -> set[str]:
    """Giá trị trong rule chứa nguyên một đoạn đường dẫn / tên file của ứng dụng mẫu (vd tienda1, anadir.jsp)
    hoặc dấu vết môi trường thử của dataset endpoint (C:\\AtomicRedTeam, ExternalPayloads, T1003.008.txt, user art).
    So theo từng đoạn, không theo chuỗi con: `global.asa` không bị coi là gắn với thư mục `/global/`."""
    found = set()
    for c in clauses:
        for v in c["value"] if isinstance(c["value"], list) else [c["value"]]:
            segs = set(_SEGMENT.split(str(v).lower().replace("\\.", ".")))
            found |= (app_tokens & segs) | {s for s in segs if s and ARTIFACT_RE.match(s)}
    return found


try:                                   # cây cú pháp regex của chính thư viện re (Python 3.11+: re._parser)
    from re import _parser as _sre
except ImportError:                    # pragma: no cover
    import sre_parse as _sre           # type: ignore[no-redef]

_SRE = _sre.__dict__ if hasattr(_sre, "LITERAL") else {}
_C = getattr(_sre, "_constants", None) or _sre


def _min_literal(items) -> float:
    """Số ký tự CHẮC CHẮN phải xuất hiện để regex khớp (nhánh lựa chọn tính nhánh ngắn nhất; lớp ký tự lặp n lần tính 0,5n)."""
    total = 0.0
    for op, av in items:
        if op is _C.LITERAL:
            total += 1
        elif op is _C.SUBPATTERN:
            total += _min_literal(av[-1])
        elif op is _C.BRANCH:
            total += min((_min_literal(b) for b in av[1]), default=0)
        elif op in (_C.MAX_REPEAT, _C.MIN_REPEAT, getattr(_C, "POSSESSIVE_REPEAT", None)):
            lo, _, body = av
            inner = _min_literal(body)
            if not inner and body and body[0][0] is _C.IN:
                inner = 0.5
            total += lo * inner
    return total


def _bare_branches(items) -> bool:
    """Regex chỉ là một / vài TỪ TRƠN ghép bằng |: (?i)(startup|autostart), stop, Test-Path."""
    while len(items) == 1 and items[0][0] is _C.SUBPATTERN:
        items = list(items[0][1][-1])
    branches = [list(b) for b in items[0][1][1]] if len(items) == 1 and items[0][0] is _C.BRANCH else [list(items)]
    return all(b and all(op is _C.LITERAL and (chr(av).isalnum() or chr(av) in "-_") for op, av in b) for b in branches)


def regex_weakness(pattern: str) -> str | None:
    """Lý do regex trên dòng lệnh không đủ làm chữ ký, hoặc None."""
    try:
        tree = list(_sre.parse(pattern))
    except (re.error, AttributeError, TypeError):
        return None                        # regex lỗi do kiểm tra cấu trúc / an toàn báo
    if _bare_branches(tree):
        return "chỉ là từ trơn"
    if _sre_has_branch(tree):
        for b in _top_branches(tree):
            if _min_literal(b) < MIN_COMMAND_LITERAL:
                return "có nhánh quá ngắn"
    if _min_literal(tree) < MIN_COMMAND_LITERAL:
        return "quá ngắn"
    return None


def _top_branches(items):
    while len(items) == 1 and items[0][0] is _C.SUBPATTERN:
        items = list(items[0][1][-1])
    return [list(b) for b in items[0][1][1]] if len(items) == 1 and items[0][0] is _C.BRANCH else [items]


def _sre_has_branch(items) -> bool:
    return len(_top_branches(items)) > 1


_TEXT_OPS = ("contains", "startswith", "endswith", "eq", "in", "regex")
_PROGRAM_NAME = re.compile(r"[a-z0-9_][a-z0-9_\-.]{2,}")
PROGRAM_FIELDS = {"process.name", "process.executable", "process.parent.name", "process.parent.executable"}
# chương trình "vỏ": chạy đủ mọi lệnh, gắn với chúng không làm một từ trơn thành chữ ký
SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "pwsh", "powershell", "sh", "bash", "dash", "zsh", "ksh", "csh",
          "busybox", "env", "sudo", "su", "python", "python3", "python.exe", "perl", "conhost.exe", "explorer.exe",
          "svchost.exe", "services.exe", "wmiprvse.exe", "systemd", "cron", "crond", "sshd"}
# chương trình hệ thống / quản trị chạy hằng ngày: vế CHỈ có tên chương trình (không đối số nào) bắt mọi lần chạy hợp lệ.
# Chạy thật 11/10: `Image|endswith '/usr/bin/su'` (model), `Image|endswith '/nohup'` (vế SigmaHQ) qua kiểm định vì tập
# bình thường không có su / nohup. Không gồm Office / trình duyệt / eventvwr / fodhelper...: "con của winword.exe" hay
# "con của eventvwr.exe" là chữ ký thật.
COMMON_PROGRAMS = SHELLS | {
    # Windows
    "net.exe", "net1.exe", "reg.exe", "sc.exe", "schtasks.exe", "wmic.exe", "rundll32.exe", "regsvr32.exe", "msiexec.exe",
    "certutil.exe", "whoami.exe", "ipconfig.exe", "systeminfo.exe", "tasklist.exe", "taskkill.exe", "findstr.exe",
    "find.exe", "hostname.exe", "netsh.exe", "netstat.exe", "ping.exe", "nslookup.exe", "route.exe", "arp.exe",
    "cscript.exe", "wscript.exe", "hh.exe", "control.exe", "mmc.exe", "notepad.exe", "robocopy.exe", "xcopy.exe",
    "attrib.exe", "icacls.exe", "takeown.exe", "wevtutil.exe", "gpupdate.exe", "gpresult.exe", "dism.exe", "sfc.exe",
    "curl.exe", "tar.exe", "expand.exe", "where.exe", "timeout.exe", "chcp.com", "more.com", "sort.exe", "quser.exe",
    "query.exe", "klist.exe", "w32tm.exe", "bcdedit.exe", "vssadmin.exe", "wbadmin.exe", "auditpol.exe", "msinfo32.exe",
    "taskmgr.exe", "dllhost.exe", "werfault.exe", "consent.exe", "runtimebroker.exe", "taskhostw.exe", "openwith.exe",
    "smartscreen.exe", "searchprotocolhost.exe", "backgroundtaskhost.exe", "lsass.exe", "winlogon.exe", "userinit.exe",
    # Linux / Unix
    "ls", "cat", "cp", "mv", "rm", "mkdir", "rmdir", "touch", "chmod", "chown", "chgrp", "ln", "find", "grep", "egrep",
    "awk", "gawk", "sed", "cut", "sort", "uniq", "head", "tail", "less", "more", "tee", "xargs", "wc", "tr", "date",
    "sleep", "tar", "gzip", "gunzip", "zip", "unzip", "xz", "curl", "wget", "ssh", "scp", "sftp", "rsync", "systemctl",
    "service", "journalctl", "crontab", "at", "nohup", "nice", "timeout", "kill", "pkill", "killall", "ps", "top",
    "id", "whoami", "who", "w", "last", "uname", "hostname", "hostnamectl", "ip", "ifconfig", "ss", "netstat", "ping",
    "mount", "umount", "df", "du", "lsblk", "free", "useradd", "usermod", "userdel", "groupadd", "groupmod", "adduser",
    "deluser", "pw", "passwd", "chpasswd", "chsh", "chage", "visudo", "apt", "apt-get", "dpkg", "yum", "dnf", "rpm",
    "snap", "pip", "pip3", "git", "make", "gcc", "cc", "ld", "python2", "node", "java", "docker", "kubectl", "openssl",
    "dd", "stat", "file", "which", "whereis", "getent", "setfacl", "getfacl", "lsmod", "modprobe", "iptables", "ufw",
    "firewall-cmd", "logger", "echo", "printf", "base64", "mktemp", "readlink", "realpath", "basename", "dirname",
    "vi", "vim", "nano", "login", "agetty", "dbus-daemon", "systemd-run", "runuser", "flock", "update-alternatives",
}
# lớp bọc Invoke-AtomicTest: powershell.exe -Command "& {...}" — có cả trong log ghi thật của Splunk (bench 9/10: 9/26
# rule qua chứa '& {', '& {Get-ADComputer'); gắn rule với lớp bọc này là gắn với cách chạy bài thử, không phải tấn công
_LAB_WRAPPER = re.compile(r"&\s*\{")


def _weak_list(c: dict[str, Any]) -> list[str]:
    r"""Giá trị yếu của MỘT lá trên dòng lệnh: quá ngắn (contains "/c"), MỘT từ trơn (startup, stop, Test-Path), hoặc
    regex chỉ là từ trơn / có nhánh quá ngắn — (?i)(startup|autostart), .*\#2.*, \s&\s*\{ (chạy thật 7/10)."""
    if c.get("field") not in COMMAND_FIELDS or c.get("op") not in _TEXT_OPS:
        return []
    out = []
    for v in c["value"] if isinstance(c["value"], list) else [c["value"]]:
        s = str(v).strip()
        if c["op"] == "regex":
            if regex_weakness(s):
                out.append(str(v))
        elif len(s) < MIN_COMMAND_LITERAL or _BARE_WORD.fullmatch(s) or _EXTENSION.fullmatch(s):
            out.append(str(v))
    return out


def _program_anchor(node: Any) -> bool:
    """Lá (hoặc OR các lá) gắn với chương trình cụ thể không phải vỏ: Image|endswith '\\reg.exe' -> process.name."""
    if isinstance(node, dict) and "any" in node:
        return all(_program_anchor(c) for c in node["any"])
    if not (isinstance(node, dict) and node.get("field") in PROGRAM_FIELDS and node.get("op") in ("eq", "in", "endswith")):
        return False
    vals = [str(v).strip().lower() for v in (node["value"] if isinstance(node["value"], list) else [node["value"]])]
    if node["op"] == "endswith" and not all(v[:1] in "\\/" for v in vals):
        return False                       # đuôi '.exe', 'exe' không phải tên chương trình
    names = [re.split(r"[\\/]", v)[-1] for v in vals]
    return bool(names) and all(_PROGRAM_NAME.fullmatch(n) for n in names) and not any(n in SHELLS for n in names)


def _anchored(children: list[Any]) -> bool:
    """Vế AND đủ đặc trưng để cho phép từ trơn đi kèm: neo vào chương trình cụ thể (reg.exe + save), hoặc có một đoạn
    dòng lệnh mạnh (hklm\\sam + save), hoặc >= 2 đoạn dòng lệnh dài >= 4 ký tự cùng phải có (contains|all)."""
    if any(_program_anchor(c) for c in children):
        return True
    cmd = [c for c in children if isinstance(c, dict) and c.get("field") in COMMAND_FIELDS and c.get("op") in _TEXT_OPS]
    if any(not _weak_list(c) for c in cmd):
        return True
    long_ = [c for c in cmd if c["op"] != "regex" and all(
        len(str(v).strip()) >= MIN_COMMAND_LITERAL for v in (c["value"] if isinstance(c["value"], list) else [c["value"]]))]
    return len(long_) >= 2


def weak_values(cond: Any) -> list[str]:
    """Giá trị so khớp trên dòng lệnh không đủ làm chữ ký. Chạy thật 4-5/10: model 7B liên tục đưa từ đơn, tập lệnh
    bình thường vài chục lệnh không phủ nổi từ vựng đó. Rule Sigma gắn chương trình với đối số trong cùng selection
    (Image|endswith '\\ntdsutil.exe' + CommandLine|contains 'ifm'): trong vế AND đã neo như vậy thì từ ngắn được phép
    (vẫn phải >= 2 ký tự). Lá dưới `not` (filter) không xét. cond: cây điều kiện, hoặc danh sách lá (= OR)."""
    out: list[str] = []

    def walk(node: Any, anchored: bool) -> None:
        if isinstance(node, list):
            node = {"any": node}
        if not isinstance(node, dict) or "not" in node:
            return
        if "all" in node:
            ok = anchored or _anchored(node["all"])
            for c in node["all"]:
                walk(c, ok)
        elif "any" in node:
            for c in node["any"]:
                walk(c, anchored)
        elif anchored:
            if node.get("field") in COMMAND_FIELDS and node.get("op") in _TEXT_OPS and node["op"] != "regex":
                vals = node["value"] if isinstance(node["value"], list) else [node["value"]]
                out.extend(str(v) for v in vals if len(str(v).strip()) < 2)
        else:
            out.extend(_weak_list(node))

    walk(cond, False)
    return out


def _program_leaf_names(node: Any) -> list[str] | None:
    """Tên chương trình (chữ thường) mà lá — hoặc OR các lá — định danh chương trình nêu ra; None nếu không phải."""
    if isinstance(node, dict) and "any" in node:
        parts = [_program_leaf_names(c) for c in node["any"]]
        return None if any(p is None for p in parts) else [n for p in parts for n in p]
    if not (isinstance(node, dict) and node.get("field") in PROGRAM_FIELDS and node.get("op") in ("eq", "in", "endswith")):
        return None
    vals = node["value"] if isinstance(node["value"], list) else [node["value"]]
    return [re.split(r"[\\/]", str(v).strip().lower())[-1] for v in vals]


def common_program_only(cond: Any) -> list[str]:
    """Vế CHỈ định danh chương trình phổ biến (tiến trình và / hoặc cha), không đối số nào: `Image|endswith
    '/usr/bin/su'`, `ParentImage '\\explorer.exe' + Image '\\cmd.exe'` — khớp mọi lần chạy hợp lệ. Trả về các tên đó.
    Lá trong một AND có điều kiện khác (đối số, cha lạ) đã bị ràng buộc, không xét."""
    out: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, list):
            node = {"any": node}
        if not isinstance(node, dict) or "not" in node:
            return
        if "all" in node:
            kids = [c for c in node["all"] if not (isinstance(c, dict) and "not" in c)]
            if len(kids) == 1:
                walk(kids[0])
                return
            names = [_program_leaf_names(c) for c in kids]
            if kids and all(n is not None and COMMON_PROGRAMS & set(n) for n in names):
                out.extend(sorted({x for n in names for x in n if x in COMMON_PROGRAMS}))
        elif "any" in node:
            for c in node["any"]:
                walk(c)
        elif (names := _program_leaf_names(node)):
            out.extend(n for n in names if n in COMMON_PROGRAMS)

    walk(cond)
    return out


def lab_wrapper(cond: Any) -> list[str]:
    """Giá trị dòng lệnh chứa lớp bọc `& {` của Invoke-AtomicTest (powershell.exe -Command "& {...}")."""
    return [str(v) for c in leaves_of(cond, positive_only=True)
            if c.get("field") in COMMAND_FIELDS and c.get("op") in _TEXT_OPS
            for v in (c["value"] if isinstance(c["value"], list) else [c["value"]]) if _LAB_WRAPPER.search(str(v))]


def describe(doc: Doc) -> str:
    """Một dòng mô tả event bình thường để báo cho LLM / người duyệt: URL hoặc dòng lệnh."""
    return str(get(doc, "url.decoded") or get(doc, "process.command_line") or get(doc, "url.path")
               or get(doc, "process.name") or get(doc, "event.action") or "")


# ---------------------------------------------------------------- ngoại lệ
def validate_exception(rule: Rule, exc: dict[str, Any], fp: list[Doc], tp: list[Doc],
                       golden: PublicDatasets | None, replay_events: list[Doc]) -> Validation:
    checks: list[Check] = []
    metrics: dict[str, Any] = {}
    clauses = leaves_of(exc["condition"])

    bad_fields = [c["field"] for c in clauses if not FIELD_RE.match(c["field"])]
    bad_ops = [c["op"] for c in clauses if c["op"] not in EXC_OPS]
    try:
        ex = RuleException.from_dict(exc)
        ok = not bad_fields and not bad_ops
        checks.append(Check("cấu trúc", ok, "hợp lệ" if ok else f"trường sai: {bad_fields} / toán tử không cho phép: {bad_ops}"))
    except Exception as e:  # noqa: BLE001
        checks.append(Check("cấu trúc", False, f"không compile được: {e}"))
        return Validation(False, "cao", checks, metrics)

    missing = missing_fields(exc["condition"], fp)
    checks.append(Check("trường có thật", not missing, "mọi trường đều có trong mẫu báo nhầm" if not missing
                        else f"trường không có trong dữ liệu: {missing}"))
    rx = _regex_problems(clauses)
    checks.append(Check("regex an toàn", not rx, "ok" if not rx else "; ".join(rx)))

    specific = [c for c in clauses if c["op"] in SPECIFIC_OPS and not c["field"].startswith(GENERIC_PREFIXES)
                and c["value"] not in ("", "*", [], None)]
    narrow = bool(specific) and (next(iter(exc["condition"])) == "all" or len(specific) == len(clauses))
    checks.append(Check("đủ hẹp", narrow, "neo vào thực thể cụ thể: " + ", ".join(c["field"] for c in specific)
                        if narrow else "ngoại lệ quá rộng: cần ít nhất 1 mệnh đề eq/in/cidr/startswith trên trường "
                        "thực thể (IP, user, host, process, url...), không chỉ event.*"))

    fp_hit = sum(ex.match(d) for d in fp)
    metrics["fp_total"], metrics["fp_matched"] = len(fp), fp_hit
    cover = fp_hit / len(fp) if fp else 0
    checks.append(Check("khớp báo nhầm", cover >= 0.5, f"khớp {fp_hit}/{len(fp)} alert báo nhầm ({cover:.0%}, cần ≥ 50%)"))

    tp_hit = sum(ex.match(d) for d in tp)
    metrics["tp_total"], metrics["tp_matched"] = len(tp), tp_hit
    if tp:
        checks.append(Check("không tắt sự cố thật", tp_hit == 0,
                            f"khớp {tp_hit}/{len(tp)} event của case đã xác nhận thật" + (" — LOẠI" if tp_hit else "")))
    else:
        checks.append(Check("không tắt sự cố thật", True, "chưa có case thật nào của rule này để đối chứng", blocking=False))

    golden_pos = golden.positives_for(rule) if golden else []
    g_hit = sum(ex.match(x.doc) for x in golden_pos)
    metrics["golden_total"], metrics["golden_matched"] = len(golden_pos), g_hit
    if golden_pos:
        checks.append(Check("giữ bộ mẫu vàng", g_hit == 0,
                            f"rule đang bắt {len(golden_pos)} mẫu tấn công của dataset; ngoại lệ làm mất {g_hit}"))
    else:
        checks.append(Check("giữ bộ mẫu vàng", True, "dataset không có mẫu tấn công cho rule này", blocking=False))

    before, t_before = replay(rule, replay_events)
    after, t_after = replay(replace(rule, exceptions=rule.exceptions + [ex]), replay_events)
    ratio = (before - after) / before if before else 0.0
    metrics.update(replay_events=len(replay_events), replay_days=round(span_days(replay_events), 2),
                   alerts_before=before, alerts_after=after, suppressed_ratio=round(ratio, 3))
    checks.append(Check("replay dữ liệu thật", True,
                        f"{len(replay_events)} event: {before} alert -> {after} alert (tắt {ratio:.0%})", blocking=False))
    slow = t_after > 2 * t_before + 0.5
    checks.append(Check("hiệu năng", not slow, f"{t_before:.2f}s -> {t_after:.2f}s"))

    passed = all(c.ok for c in checks if c.blocking)
    risk = "cao" if (not tp and not golden_pos) or ratio > 0.8 else "thấp"
    return Validation(passed, risk, checks, metrics)


# ---------------------------------------------------------------- rule mới
def validate_new_rule(rule_dict: dict[str, Any], existing: list[Rule], suspicious_train: list[Doc],
                      suspicious_test: list[Doc], normal: list[Doc], replay_events: list[Doc],
                      max_alerts_per_day: float, app_tokens: set[str] | None = None,
                      normal_label: str = "event bình thường") -> Validation:
    checks: list[Check] = []
    metrics: dict[str, Any] = {}
    clauses = leaves_of(rule_dict["condition"])
    positive = leaves_of(rule_dict["condition"], positive_only=True)
    bad_fields = [c["field"] for c in clauses if not FIELD_RE.match(c["field"])]
    bad_ops = [c["op"] for c in clauses if c["op"] not in RULE_OPS]
    try:
        rule = Rule.from_dict(rule_dict)
        ok = not bad_fields and not bad_ops
        checks.append(Check("cấu trúc", ok, "hợp lệ" if ok else f"trường sai: {bad_fields} / toán tử sai: {bad_ops}"))
    except Exception as e:  # noqa: BLE001
        checks.append(Check("cấu trúc", False, f"không compile được: {e}"))
        return Validation(False, "cao", checks, metrics)

    dup = rule.id in {r.id for r in existing}
    checks.append(Check("ID không trùng", not dup, rule.id + (" đã tồn tại" if dup else "")))
    missing = missing_fields(rule_dict["condition"], suspicious_train + suspicious_test)
    checks.append(Check("trường có thật", not missing, "ok" if not missing else f"trường không có trong dữ liệu: {missing}"))
    rx = _regex_problems(clauses)
    checks.append(Check("regex an toàn", not rx, "ok" if not rx else "; ".join(rx)))
    if app_tokens is not None:     # rule học từ dataset: không được dựa vào ứng dụng mẫu / môi trường thử
        tied = sorted(_app_specific(positive, app_tokens)) + [f"lớp bọc {v!r}" for v in lab_wrapper(rule_dict["condition"])]
        checks.append(Check("dùng chung được", not tied, "không gắn với ứng dụng mẫu / môi trường thử của dataset"
                            if not tied else f"rule chỉ khớp dữ liệu của dataset (chứa {', '.join(tied[:5])})"))
    if (weak := weak_values(rule_dict["condition"])):
        checks.append(Check("đủ đặc trưng", False, f"đoạn dòng lệnh quá ngắn hoặc chỉ là một từ trơn, không phải chữ ký: {', '.join(weak[:5])}"))
    if (bare := common_program_only(rule_dict["condition"])):
        checks.append(Check("đủ đặc trưng", False, "vế chỉ có tên chương trình phổ biến, không đối số nào (khớp mọi lần "
                            f"chạy hợp lệ): {', '.join(sorted(set(bare))[:5])}"))

    test = suspicious_test or suspicious_train
    hit = sum(rule.condition.match(d) for d in test)
    recall = hit / len(test) if test else 0
    metrics.update(test_total=len(test), test_detected=hit, test_recall=round(recall, 3),
                   test_is_holdout=bool(suspicious_test))
    checks.append(Check("bắt mẫu nghi vấn", recall >= 0.3,
                        f"{hit}/{len(test)} mẫu {'ở tập kiểm tra (không đưa cho LLM)' if suspicious_test else ''} ({recall:.0%}, cần ≥ 30%)"))

    if normal:
        nh = sum(rule.condition.match(d) for d in normal)
        fpr = nh / len(normal)
        metrics.update(normal_total=len(normal), normal_hits=nh, fp_rate=round(fpr, 5))
        ex = next((describe(d) for d in normal if rule.condition.match(d)), "") if nh else ""
        checks.append(Check("báo nhầm trên dữ liệu bình thường", fpr <= 0.001,
                            f"{nh}/{len(normal)} {normal_label} bị bắt ({fpr:.2%}, tối đa 0,1%)"
                            + (f", vd: {ex[:120]}" if ex else "")))
    else:
        nh = 0
    if any(c["field"].startswith("url.") for c in positive):
        oh = ordinary_hits(rule.condition)
        metrics["ordinary_url_hits"] = len(oh)
        checks.append(Check("không khớp URL thông thường", not oh,
                            f"không khớp {len(ORDINARY_URLS)} URL mẫu của website bình thường" if not oh
                            else f"khớp URL bình thường: {', '.join(oh[:3])} — quá chung chung"))

    n, t = replay(rule, replay_events)
    per_day = n / span_days(replay_events) if replay_events else 0
    metrics.update(replay_events=len(replay_events), replay_alerts=n, alerts_per_day=round(per_day, 2))
    checks.append(Check("số alert khi replay", per_day <= max_alerts_per_day,
                        f"{n} alert trên {len(replay_events)} event thật (~{per_day:.1f}/ngày, tối đa {max_alerts_per_day:g})"))
    ref = Rule.from_dict({"id": "_ref", "title": "ref", "condition": {"field": "event.category", "op": "eq", "value": "web"}})
    _, t_ref = replay(ref, replay_events)
    slow = t > 5 * t_ref + 0.5
    checks.append(Check("hiệu năng", not slow, f"{t:.2f}s (tham chiếu {t_ref:.2f}s)"))

    covered_by = [r.id for r in existing if r.type == "match" and test and
                  sum(r.condition.match(d) for d in test) >= 0.8 * len(test)]
    checks.append(Check("trùng rule sẵn có", not covered_by, "không trùng" if not covered_by
                        else f"rule {covered_by} đã bắt phần lớn các mẫu này", blocking=False))

    passed = all(c.ok for c in checks if c.blocking)
    risk = "cao" if nh > 0 or per_day > max_alerts_per_day / 2 else "thấp"
    return Validation(passed, risk, checks, metrics)
