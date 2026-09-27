"""Phân loại mẫu tấn công web trong dataset theo LOẠI tấn công — chỉ dùng để GOM NHÓM ứng viên cho AI.

Đây không phải bộ phát hiện: heuristic cố ý thô, chỉ để mỗi nhóm đưa cho LLM là cùng một kiểu tấn công
(trước đây gom theo url.path nên một nhóm lẫn SQLi, CRLF, file sao lưu... -> LLM không viết nổi 1 rule chung).
Rule thật vẫn do LLM viết và phải qua kiểm định (tập kiểm tra giữ riêng, tập bình thường).

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


@dataclass(frozen=True)
class AttackType:
    key: str
    label: str            # tiếng Việt, hiện trên console / báo cáo
    prompt: str           # mô tả tiếng Anh đưa vào prompt
    transferable: bool = True


TYPES: dict[str, AttackType] = {t.key: t for t in [
    AttackType("ssi", "Server-Side Include injection", "Server-Side Include injection (<!--#exec ...>, <!--#include ...>)"),
    AttackType("crlf", "CRLF / chèn header", "CRLF injection / HTTP header injection (encoded CR/LF, injected Set-Cookie header)"),
    AttackType("xss", "Cross-Site Scripting", "Cross-site scripting (HTML tags, event handlers, javascript: URLs)"),
    AttackType("sqli", "SQL Injection", "SQL injection (quotes, boolean tautologies, SQL keywords, comments)"),
    AttackType("path-traversal", "Path traversal / LFI", "Path traversal / local file inclusion (../, system files)"),
    AttackType("cmd-injection", "Command injection", "OS command injection (shell metacharacters followed by commands)"),
    AttackType("encoding-evasion", "Mã hóa né tránh (kép / null byte)",
               "Encoding evasion: double URL encoding (%25xx), null bytes (%00), overlong UTF-8"),
    AttackType("oversized", "Tham số quá dài (tràn bộ đệm)", "Oversized parameter values (buffer overflow attempts)"),
    AttackType("backup-file", "Dò file sao lưu / mã nguồn",
               "Probing for backup, temporary or source files (.bak, .old, ~, .inc, .java ...)"),
    AttackType("sensitive-path", "Dò tài nguyên nhạy cảm / mặc định",
               "Probing for default, administrative or sensitive server resources"),
    AttackType("unknown-param", "Tham số lạ (riêng ứng dụng)", "", transferable=False),
    AttackType("invalid-value", "Giá trị sai định dạng (riêng ứng dụng)", "", transferable=False),
    AttackType("unknown-resource", "Đường dẫn không tồn tại (riêng ứng dụng)", "", transferable=False),
]}

_I = re.I
_SIGNATURES: list[tuple[str, list[re.Pattern]]] = [
    ("ssi", [re.compile(r"<!--\s*#\s*(exec|include|echo|config|fsize|flastmod|printenv)", _I)]),
    ("crlf", [re.compile(r"[\r\n]"), re.compile(r"set-cookie\s*:", _I)]),
    ("xss", [re.compile(r"<\s*/?\s*[a-z]", _I), re.compile(r"javascript\s*:", _I), re.compile(r"\bon[a-z]+\s*=", _I),
             re.compile(r"alert\s*\(", _I), re.compile(r"document\.(cookie|location)", _I)]),
    ("sqli", [re.compile(r"'"), re.compile(r"\b(union|select|insert|update|delete|drop|declare|exec)\s", _I),
              re.compile(r"(and|or)\s+['\"]?\w+['\"]?\s*(=|<|>|\blike\b)", _I), re.compile(r"--|/\*|#\s*$"),
              re.compile(r"\b(sleep|benchmark|waitfor|char)\s*\(", _I)]),
    ("path-traversal", [re.compile(r"\.\.[/\\]"), re.compile(r"/etc/(passwd|shadow|hosts)", _I),
                        re.compile(r"(boot|win)\.ini", _I)]),
    ("cmd-injection", [re.compile(r"[;|`]\s*[a-z/]", _I), re.compile(r"\$\(")]),
]
_ENCODING_RAW = re.compile(r"%25[0-9a-f]{2}|%00|%c0%a[ef]|%u[0-9a-f]{4}", _I)
_BACKUP = re.compile(r"(~|\.(bak|old|orig|save|sav|swp|swo|tmp|temp|copy|backup|inc|java|class|sql|dist|conf|cfg|"
                     r"ini|log|zip|tar|gz|tgz|rar|7z))$", _I)
_SENSITIVE = re.compile(r"/(_[a-z_]+|iis[a-z]+|msadc|scripts|cgi-bin|cgi|samples?|admin|administrator|manager|"
                        r"phpmyadmin|server-(status|info)|web-inf|meta-inf|\.git|\.svn|\.env|\.ht[a-z]+)(/|$)|"
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
        """Đoạn đường dẫn đặc trưng của ứng dụng dataset (vd tienda1, publico) — rule dùng chung không được chứa."""
        return {s.lower() for path in self.paths for s in path.split("/") if len(s) >= 4}


def _params(query: str) -> list[tuple[str, str]]:
    try:
        return parse_qsl(query, keep_blank_values=True)
    except ValueError:
        return []


def classify_web(doc: Doc, profile: WebProfile) -> str:
    raw = get(doc, "url.original") or ""
    path = get(doc, "url.path") or "/"
    decoded = get(doc, "url.decoded") or unquote_plus(raw)
    for key, pats in _SIGNATURES:
        if any(p.search(decoded) for p in pats):
            return key
    if _ENCODING_RAW.search(raw) or "\x00" in decoded:
        return "encoding-evasion"
    params = _params(get(doc, "url.query") or "")
    if any(len(v) > max(2 * profile.max_len.get(k, 0), 100) for k, v in params):
        return "oversized"
    if _BACKUP.search(path):
        return "backup-file"
    if _SENSITIVE.search(path):
        return "sensitive-path"
    if profile.paths and path not in profile.paths:
        return "unknown-resource"
    if any(k not in profile.params.get(path, set()) for k, _ in params):
        return "unknown-param"
    return "invalid-value"
