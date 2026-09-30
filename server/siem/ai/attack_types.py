"""Phân loại mẫu tấn công web trong dataset theo LOẠI tấn công — chỉ dùng để GOM NHÓM ứng viên cho AI.

Đây không phải bộ phát hiện: heuristic cố ý thô, chỉ để mỗi nhóm đưa cho LLM là cùng một kiểu tấn công
(trước đây gom theo url.path nên một nhóm lẫn SQLi, CRLF, file sao lưu... -> LLM không viết nổi 1 rule chung).
Rule thật vẫn do LLM viết và phải qua kiểm định (tập kiểm tra giữ riêng, tập bình thường).

Ngoài loại, mỗi mẫu còn có:
  - biến thể (variant): kiểu con trong cùng loại (vd SQLi tautology / thoát chuỗi; thư mục bị dò).
    Worker chọn mẫu trải đều theo biến thể và đưa thống kê biến thể của cả tập train cho LLM, để rule
    phủ các biến thể phổ biến thay vì chỉ chép vài chuỗi trong 8 mẫu.
  - payload (evidence): đoạn làm request bị nghi vấn. URL dài bị cắt khi đưa vào prompt, payload thì không.

Loại `transferable=False` là bất thường RIÊNG của ứng dụng trong dataset (tham số lạ, giá trị sai định dạng,
đường dẫn không tồn tại). Rule chữ ký viết cho các nhóm này chỉ khớp ứng dụng mẫu (/tienda1/...) nên không
giao cho AI; muốn bắt cần mô hình hành vi / allowlist theo từng ứng dụng.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import parse_qsl, unquote_plus

from ..pipeline.normalize import Doc, get

# Chuỗi giữ chỗ do bộ sinh dataset chèn vào (CSIC 2010 thay payload bằng 'INJECTED_PARAM').
# Rule chứa chúng không bắt được gì ngoài dataset -> kiểm định coi như gắn với ứng dụng mẫu.
DATASET_ARTIFACTS = {"injected_param"}


@dataclass(frozen=True)
class AttackType:
    key: str
    label: str            # tiếng Việt, hiện trên console / báo cáo
    prompt: str           # mô tả tiếng Anh đưa vào prompt
    transferable: bool = True


@dataclass(frozen=True)
class WebMatch:
    kind: str
    variant: str
    evidence: str
    short: str = ""       # payload cắt sát đoạn khớp (lượt bổ sung chỉ cần đúng chỗ đó)
    param: str = ""       # đúng cặp tham số=giá trị chứa đoạn khớp (vd modo='OR'a='a)


TYPES: dict[str, AttackType] = {t.key: t for t in [
    AttackType("ssi", "Server-Side Include injection", "Server-Side Include injection (<!--#exec ...>, <!--#include ...>)"),
    AttackType("crlf", "CRLF / chèn header", "CRLF injection / HTTP header injection (encoded CR/LF, injected Set-Cookie header)"),
    AttackType("xss", "Cross-Site Scripting", "Cross-site scripting (HTML tags, event handlers, javascript: URLs)"),
    AttackType("sqli", "SQL Injection",
               "SQL injection (boolean tautologies with or without quotes, a quote breaking out of a parameter value, "
               "SQL keywords, comments)"),
    AttackType("path-traversal", "Path traversal / LFI", "Path traversal / local file inclusion (../, system files)"),
    AttackType("cmd-injection", "Command injection", "OS command injection (shell metacharacters followed by commands)"),
    AttackType("encoding-evasion", "Mã hóa né tránh (kép / null byte)",
               "Encoding evasion: double URL encoding (%25xx), null bytes (%00), overlong UTF-8"),
    AttackType("oversized", "Tham số quá dài (tràn bộ đệm)", "Oversized parameter values (buffer overflow attempts)"),
    AttackType("backup-file", "Dò file sao lưu / mã nguồn",
               "Probing for backup, temporary or source files (.bak, .old, ~, .inc, .java ...)"),
    AttackType("sensitive-path", "Dò tài nguyên nhạy cảm / mặc định",
               "Probing for well-known default, sample, administrative or vendor resources of web servers "
               "(IIS/FrontPage, ColdFusion, Lotus Domino, CGI ...) that a normal site never links to"),
    AttackType("unknown-param", "Tham số lạ (riêng ứng dụng)", "", transferable=False),
    AttackType("invalid-value", "Giá trị sai định dạng (riêng ứng dụng)", "", transferable=False),
    AttackType("unknown-resource", "Đường dẫn không tồn tại (riêng ứng dụng)", "", transferable=False),
]}

_I = re.I
# (loại, [(biến thể, mẫu)]) — thứ tự quan trọng: mẫu đầu tiên khớp quyết định loại và biến thể
_SIGNATURES: list[tuple[str, list[tuple[str, re.Pattern]]]] = [
    ("ssi", [("ssi-directive", re.compile(r"<!--\s*#\s*(exec|include|echo|config|fsize|flastmod|printenv)", _I))]),
    ("crlf", [("crlf-set-cookie", re.compile(r"[\r\n]\s*set-cookie\s*:", _I)), ("cr-lf", re.compile(r"[\r\n]")),
              ("set-cookie", re.compile(r"set-cookie\s*:", _I))]),
    ("xss", [("html-tag", re.compile(r"<\s*/?\s*[a-z]", _I)), ("javascript-url", re.compile(r"javascript\s*:", _I)),
             ("event-handler", re.compile(r"\bon[a-z]+\s*=", _I)), ("alert", re.compile(r"alert\s*\(", _I)),
             ("dom", re.compile(r"document\.(cookie|location)", _I))]),
    # Dấu nháy đơn lẻ giữa chữ (tên riêng như D'estats, hoặc dataset chèn nháy ngẫu nhiên) KHÔNG tính là SQLi:
    # không viết được chữ ký chung cho nó mà không báo nhầm tên người / địa chỉ hợp lệ.
    ("sqli", [("tautology-quoted", re.compile(r"['\"]\s*(or|and)\s*['\"]?\w+['\"]?\s*(=|<|>|\blike\b)", _I)),
              ("tautology-numeric", re.compile(r"(and|or)\s+\d+\s*(=|<|>)\s*\d+|"
                                               r"\b(and|or)\s+['\"]?\w+['\"]?\s*(=|<|>|\blike\b)", _I)),
              ("keyword", re.compile(r"\b(union|select|insert|update|delete|drop|declare|exec)\s", _I)),
              ("function", re.compile(r"\b(sleep|benchmark|waitfor|char)\s*\(", _I)),
              ("comment", re.compile(r"--|/\*|'\s*#")),
              ("quote-breakout", re.compile(r"=\d*['\"]"))]),
    ("path-traversal", [("dot-dot-slash", re.compile(r"\.\.[/\\]")),
                        ("system-file", re.compile(r"/etc/(passwd|shadow|hosts)|(boot|win)\.ini", _I))]),
    ("cmd-injection", [("shell-separator", re.compile(r"[;|`]\s*[a-z/]", _I)), ("subshell", re.compile(r"\$\("))]),
]
_ENCODING: list[tuple[str, re.Pattern]] = [
    ("double-encoding", re.compile(r"%25[0-9a-f]{2}", _I)), ("null-byte", re.compile(r"%00")),
    ("overlong-utf8", re.compile(r"%c0%a[ef]", _I)), ("unicode-escape", re.compile(r"%u[0-9a-f]{4}", _I)),
]
_BACKUP = re.compile(r"(~|\.(bak|old|orig|save|sav|swp|swo|tmp|temp|copy|backup|inc|java|class|sql|dist|conf|cfg|"
                     r"ini|log|zip|tar|gz|tgz|rar|7z))$", _I)
_SENSITIVE = re.compile(r"/(_[a-z_]+|iis[a-z]+|msadc|scripts|cgi-bin|cgi|samples?|admin|administrator|manager|"
                        r"phpmyadmin|server-(status|info)|web-inf|meta-inf|\.git|\.svn|\.env|\.ht[a-z]+|cfide)(/|$)|"
                        r"\.(htr|nsf|idq|ida|printer|asa|cfm|pl|cgi|exe|dll|bat|cmd|sh)$", _I)


@dataclass
class WebProfile:
    """Hành vi BÌNH THƯỜNG của ứng dụng trong dataset: đường dẫn, tên tham số và độ dài giá trị đã thấy."""
    paths: set[str] = field(default_factory=set)
    params: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    max_len: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    @classmethod
    def build(cls, normal_docs: Iterable[Doc]) -> "WebProfile":
        p = cls()
        for d in normal_docs:
            path = get(d, "url.path") or "/"
            p.paths.add(path)
            for k, v in _params(get(d, "url.query") or ""):
                p.params[path].add(k)
                p.max_len[k] = max(p.max_len[k], len(v))
        return p

    def app_tokens(self) -> set[str]:
        """Đoạn đặc trưng của ứng dụng / dataset (vd tienda1, anadir.jsp, INJECTED_PARAM) — rule dùng chung không được chứa."""
        return {s.lower() for path in self.paths for s in path.split("/") if len(s) >= 4} | DATASET_ARTIFACTS


def _params(query: str) -> list[tuple[str, str]]:
    try:
        return parse_qsl(query, keep_blank_values=True)
    except ValueError:
        return []


def _around(text: str, m: re.Match, before: int = 25, after: int = 40) -> str:
    return text[max(0, m.start() - before):m.end() + after]


def _hit(kind: str, variant: str, text: str, m: re.Match, pairs: list[str]) -> WebMatch:
    """`pairs`: các cặp tham số=giá trị cùng dạng với `text` (đã giải mã hoặc còn thô)."""
    param = next((kv for kv in pairs if m.group(0) in kv), "")
    return WebMatch(kind, variant, _around(text, m), _around(text, m, 12, 20), param[:80])


def path_variant(path: str) -> str:
    """Thứ bị dò: thư mục đầu tiên (/_vti_bin/, /cfide/) hoặc phần mở rộng nếu là file ở gốc (extension .nsf)."""
    p = path.lower()
    segs = [s for s in p.split("/") if s]
    if len(segs) > 1 or (segs and p.endswith("/")):
        return f"/{segs[0]}/"
    last = segs[-1] if segs else ""
    return "extension ." + last.rsplit(".", 1)[-1] if "." in last else f"/{last}"


def inspect_web(doc: Doc, profile: WebProfile) -> WebMatch:
    raw = get(doc, "url.original") or ""
    path = get(doc, "url.path") or "/"
    decoded = get(doc, "url.decoded") or unquote_plus(raw)
    query = get(doc, "url.query") or ""
    params = _params(query)
    for kind, pats in _SIGNATURES:
        for variant, p in pats:
            if (m := p.search(decoded)):
                return _hit(kind, variant, decoded, m, [f"{k}={v}" for k, v in params])
    for variant, p in _ENCODING:
        if (m := p.search(raw)):
            return _hit("encoding-evasion", variant, raw, m, query.split("&"))
    if "\x00" in decoded:
        return WebMatch("encoding-evasion", "null-byte", decoded[:80])
    for k, v in params:
        if len(v) > max(2 * profile.max_len.get(k, 0), 100):
            return WebMatch("oversized", "long-value", f"{k}={v[:40]}… ({len(v)} ký tự)")
    if (m := _BACKUP.search(path)):
        return WebMatch("backup-file", m.group(0).lower(), path)
    if _SENSITIVE.search(path):
        return WebMatch("sensitive-path", path_variant(path), path)
    if profile.paths and path not in profile.paths:
        return WebMatch("unknown-resource", path, path)
    unknown = [k for k, _ in params if k not in profile.params.get(path, set())]
    if unknown:
        return WebMatch("unknown-param", path, ", ".join(unknown[:3]))
    return WebMatch("invalid-value", path, path)


def classify_web(doc: Doc, profile: WebProfile) -> str:
    return inspect_web(doc, profile).kind
