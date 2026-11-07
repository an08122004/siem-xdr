"""Dịch cây điều kiện Sigma (`sigma.compile_rule`) sang rule Wazuh XML (R66-R71).

Ngữ nghĩa giữ như `detection.rules.Condition`: mọi phép so chuỗi không phân biệt hoa thường, `regex` cũng vậy trừ khi
`case_sensitive: true`, `neq` / `not_contains` là lá âm. Cách dịch:
  - cây -> dạng tuyển chuẩn (DNF); mỗi vế thành một <rule> anh em (R69), tối đa sigma.MAX_TERMS vế;
  - trong một vế, mỗi trường Wazuh có đúng MỘT phần tử pcre2 `(?i)^(?=...)(?!...)`: điều kiện dương là lookahead, phủ định là
    negative lookahead (không phụ thuộc chuyện Wazuh có cho hai <field> trùng tên hay không);
  - `any` toàn lá dương trên cùng trường Wazuh được gộp thành một lookahead dạng alternation (R-P7);
  - mọi giá trị đi qua `wazuh_fields.escape_literal` (hoặc, với regex, thay ký tự điều khiển bằng `\\xHH`), rồi escape XML.
Lệch đã biết với cây Python: trường VẮNG thì Python coi `not_contains` / `neq` là đúng, còn Wazuh không khớp rule (cổng đo và báo).
"""
from __future__ import annotations

import re
from typing import NamedTuple
from xml.sax.saxutils import escape

from ..detection.rules import regex_risk
from ..wazuh_fields import escape_literal
from .sigma import MAX_TERMS, SigmaError

EMITTER_VERSION = "2"      # 2: dấu `\` trong trường Windows khớp cả dạng đơn lẫn nhân đôi (eventchannel)
LEVEL = {"low": 5, "medium": 7, "high": 10, "critical": 10}      # R70: không thắng rule gốc level 11-12 cùng cha
_WEB_PARENTS = "31100,31101,31103,31104,31105,31106,31108,31120,31121,31122,31123"
PARENTS: dict[str, dict] = {
    # 61603 + các rule gốc level 0 có con và móc vào sysmon_event1 (Wazuh 4.14.8, 0800-sysmon_id_1.xml: 92025 reg.exe, 92028 powershell script,
    # 92042 netsh, 92069 WmiPrvSE): chúng nuốt event trước các anh em dưới 61603, nên rule sinh ra phải móc cả vào đó
    "windows": {"if_sid": "61603,92025,92028,92042,92069"},
    "linux": {"if_sid": "102000"},
    "web": {"if_sid": _WEB_PARENTS, "location": r"^\("},
}

# ECS -> (tên Wazuh, kiểu). Kiểu: "" so thẳng; "base" tên tiến trình = phần cuối đường dẫn; "url" thẻ <url> chịu mã hóa
# phần trăm; "ua" thẻ <regex> lấy chuỗi ngoặc kép cuối dòng. Tên không phải `a.b` là thẻ tĩnh, còn lại là <field name=>.
_URL = {k: ("url", "url") for k in ("url.original", "url.path", "url.query", "url.decoded")}
FIELDS: dict[str, dict[str, tuple[str, str]]] = {
    "windows": {"process.executable": ("win.eventdata.image", ""), "process.command_line": ("win.eventdata.commandLine", ""),
                "process.name": ("win.eventdata.image", "base"), "process.parent.executable": ("win.eventdata.parentImage", ""),
                "process.parent.name": ("win.eventdata.parentImage", "base"),
                "process.parent.command_line": ("win.eventdata.parentCommandLine", ""),
                "user.name": ("win.eventdata.user", ""),
                "winlog.event_data.CurrentDirectory": ("win.eventdata.currentDirectory", "")},
    "linux": {"process.executable": ("exe", ""), "process.command_line": ("cmd", ""), "process.name": ("name", ""),
              "process.parent.name": ("parent", "")},
    "web": {**_URL, "http.request.method": ("protocol", ""), "http.response.status_code": ("id", ""),
            "user_agent.original": ("regex", "ua")},
}
_STATIC = {"url", "protocol", "id", "regex"}
_NEG = {"neq": "eq", "not_contains": "contains", "not_endswith": "endswith"}     # lá âm -> phép dương tương ứng
_OPS = {"eq", "in", "contains", "startswith", "endswith", "regex"} | set(_NEG)
_BAD_XML = re.compile("[\x00-\x1f\x7f\ud800-\udfff￾￿]")      # kể cả \r\n: parser XML chuẩn hóa CRLF


class Emitted(NamedTuple):
    xml: str
    ids: list[int]


# ----------------------------------------------------------------------------- mẫu pcre2
def _vals(leaf: dict) -> list[str]:
    v = leaf["value"]
    return [str(x) for x in v] if isinstance(v, list) else [str(v)]


def _url_lit(value: str) -> str:
    """Khớp `value` dù URL còn mã hóa phần trăm (UTF-8) hay đã giải mã; khoảng trắng còn có thể là `+`."""
    def one(c: str) -> str:
        if c.isascii() and c.isalnum():
            return c
        pct = "".join(f"%{b:02X}" for b in c.encode("utf-8", "replace"))
        return "(?:" + "|".join([escape_literal(c), pct] + ([r"\+"] if c == " " else [])) + ")"
    return "".join(one(c) for c in value)


def _win_lit(value: str) -> str:
    """Eventchannel của Wazuh NHÂN ĐÔI mọi dấu gạch chéo ngược trong win.eventdata.*: khớp cả một lẫn hai dấu (đo trên Wazuh 4.14.8, Task 21)."""
    return escape_literal(value).replace(r"\x5c", r"(?:\x5c){1,2}")


def _has_literal_backslash(rx: str) -> bool:
    i = 0
    while i < len(rx):
        if rx[i] == "\\":
            if rx[i + 1:i + 2] == "\\":
                return True
            i += 1
        i += 1
    return False


def _body(leaf: dict) -> str:
    if "alts" in leaf:
        return "(?:" + "|".join(_body(a) for a in leaf["alts"]) + ")"
    op, vals = _NEG.get(leaf["op"], leaf["op"]), _vals(leaf)
    if op == "regex":
        rs = [f"(?-i:{v})" if leaf.get("case_sensitive") else v for v in vals]
        return r"[\s\S]*?(?:" + "|".join(rs) + ")"
    lit = _url_lit if leaf.get("url") else _win_lit if leaf.get("win") else escape_literal
    alt = "(?:" + "|".join(lit(v) for v in vals) + ")"
    return {"contains": r"[\s\S]*?" + alt, "startswith": alt, "endswith": r"[\s\S]*?" + alt + r"\z",
            "eq": alt + r"\z", "in": alt + r"\z"}[op]


def pattern(pos: list[dict], neg: list[dict]) -> str:
    """Mẫu pcre2 cho MỘT trường Wazuh trong MỘT vế: lá dương là lookahead, lá âm (và `neq` / `not_contains`) là negative lookahead."""
    flip = [x for x in pos if x.get("op") in _NEG]
    pos, neg = [x for x in pos if x.get("op") not in _NEG] + [x for x in neg if x.get("op") in _NEG], \
        [x for x in neg if x.get("op") not in _NEG] + flip
    out = "(?i)^" + "".join(f"(?={_body(x)})" for x in pos) + "".join(f"(?!{_body(x)})" for x in neg)
    return _BAD_XML.sub(lambda m: f"\\x{ord(m.group()):02x}" if ord(m.group()) < 256 else f"\\x{{{ord(m.group()):x}}}", out)


def _ua_pattern(pos: list[dict], neg: list[dict]) -> str:
    """User-Agent là chuỗi ngoặc kép CUỐI dòng log apache (như 104005); chỉ một điều kiện `contains` dương."""
    if neg or len(pos) != 1:
        raise SigmaError("User-Agent chỉ dịch được đúng một điều kiện contains dương")
    vals = [v for leaf in pos[0].get("alts") or [pos[0]] for v in _vals(leaf)]
    return '(?i)"[^"]{0,300}?(?:' + "|".join(escape_literal(v) for v in vals) + ')[^"]{0,300}"\\s*$'


# ----------------------------------------------------------------------------- cây -> DNF
def _map_leaf(leaf: dict, domain: str) -> dict:
    f, op = leaf.get("field"), leaf.get("op", "eq")
    if f not in FIELDS[domain]:
        raise SigmaError(f"trường {f} không có trong log Wazuh của {domain}")
    if op not in _OPS:
        raise SigmaError(f"phép so {op} không dịch được sang rule Wazuh")
    w, mode = FIELDS[domain][f]
    out = {**leaf, "op": op, "w": w, "mode": mode, "url": mode == "url", "win": domain == "windows"}
    if mode == "base":                      # tên tiến trình = phần sau dấu `\` cuối của đường dẫn đầy đủ
        if op not in ("eq", "neq", "in", "endswith"):
            raise SigmaError(f"phép so {op} trên {f} không dịch được (chỉ eq / in / endswith)")
        out["value"] = [("" if op == "endswith" else "\\") + v for v in _vals(leaf)]
        out["op"] = "not_endswith" if op == "neq" else "endswith"
    if op == "regex":                       # giá trị từ LLM / SigmaHQ: phải tự cân ngoặc (không thoát được `(?:…)`) và không ReDoS
        for v in _vals(leaf):
            try:
                re.compile(v)
            except re.error as e:
                raise SigmaError(f"regex không hợp lệ ({e}): {v[:80]}") from None
            # shortcut: regex có dấu \\ chữ trên eventchannel bị từ chối (Wazuh nhân đôi dấu, không sửa được regex tùy ý), khi cần thì tự viết lại \\ thành \\{1,2}
            if domain == "windows" and _has_literal_backslash(v):
                raise SigmaError("regex có dấu \\ chưa hỗ trợ trên eventchannel")
            if (why := regex_risk(v)):
                raise SigmaError(f"{why}: {v[:80]}")
    if mode == "ua" and op != "contains":
        raise SigmaError("User-Agent chỉ dịch được phép contains")
    return out


def _prep(node: dict, domain: str) -> dict:
    if "all" in node:
        return {"all": [_prep(c, domain) for c in node["all"]]}
    if "not" in node:
        return {"not": _prep(node["not"], domain)}
    if "any" in node:
        kids = [_prep(c, domain) for c in node["any"]]
        if (kids and all("w" in k and k.get("op") not in _NEG for k in kids)
                and len({(k["w"], k.get("url", k["alts"][0]["url"] if "alts" in k else False)) for k in kids}) == 1):
            # R-P7: một trường, toàn lá dương -> một alternation (any lồng nhau được làm phẳng)
            return {"alts": [a for k in kids for a in k.get("alts", [k])], "w": kids[0]["w"], "mode": kids[0]["mode"]}
        return {"any": kids}
    if "field" in node:
        return _map_leaf(node, domain)
    raise SigmaError(f"nút điều kiện không hợp lệ: {str(node)[:80]}")


def _dnf(node: dict, neg: bool = False) -> list[list[tuple[dict, bool]]]:
    if "not" in node:
        return _dnf(node["not"], not neg)
    if "all" in node or "any" in node:
        kind = "all" if "all" in node else "any"
        parts = [_dnf(c, neg) for c in node[kind]]
        if (kind == "all") != neg:          # and (hoặc or bị phủ định): tích các vế
            out: list = [[]]
            for p in parts:
                out = [a + b for a in out for b in p]
                if len(out) > MAX_TERMS:
                    raise SigmaError(f"rule có hơn {MAX_TERMS} vế sau khi khai triển")
            return out
        out = [t for p in parts for t in p]
        if len(out) > MAX_TERMS:
            raise SigmaError(f"rule có hơn {MAX_TERMS} vế sau khi khai triển")
        return out
    # cực tính nằm ở danh sách pos/neg, nên đổi lá âm về phép dương tương ứng (pattern() tự lật phép âm nếu gọi trực tiếp)
    return [[({**node, "op": _NEG.get(node.get("op"), node.get("op"))} if "op" in node else node,
              (node.get("op") not in _NEG) != neg)]]


# ----------------------------------------------------------------------------- XML
def _clean(s: str, limit: int) -> str:
    """Bỏ ký tự điều khiển, gộp khoảng trắng, cắt TRƯỚC khi escape (như wazuh_fields.exception_rule)."""
    return " ".join("".join(c for c in str(s) if c.isprintable() or c.isspace()).split())[:limit]


def _element(w: str, mode: str, pos: list[dict], neg: list[dict]) -> str:
    p = escape(_ua_pattern(pos, neg) if mode == "ua" else pattern(pos, neg))
    if w in _STATIC:
        return f'<{w} type="pcre2">{p}</{w}>'
    return f'<field name="{w}" type="pcre2">{p}</field>'


def emit(tree: dict, *, domain: str, first_id: int, level: int, code: str, title: str, techniques: list[str],
         groups: list[str], shadow_since: str | None, info: dict[str, str] | None = None) -> Emitted:
    if domain not in PARENTS:
        raise SigmaError(f"lĩnh vực {domain} chưa có rule Wazuh")
    if shadow_since is not None and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", shadow_since):
        raise SigmaError(f"shadow_since phải là YYYY-MM-DD: {shadow_since!r}")
    terms = _dnf(_prep(tree, domain))
    if not terms:
        raise SigmaError("rule không có vế nào")
    parent = PARENTS[domain]
    gs = [g for g in (re.sub(r"[^A-Za-z0-9_.\-]", "", x) for x in groups) if g] + (["shadow"] if shadow_since else [])
    extra = [f'<info type="text">{re.sub(r"[^A-Za-z0-9_]", "", str(k))}={escape(_clean(v, 300))}</info>'
             for k, v in (info or {}).items() if re.sub(r"[^A-Za-z0-9_]", "", str(k))]
    if shadow_since:
        extra.insert(0, f'<info type="text">shadow_since={shadow_since}</info>')
    mitre = [t for t in techniques if re.fullmatch(r"T\d{4}(\.\d{3})?", t)]
    desc = f"{_clean(code, 40)} {_clean(title, 200)}"
    rules, ids = [], []
    for k, term in enumerate(terms):
        by: dict[str, dict] = {}
        for item, positive in term:
            g = by.setdefault(item["w"], {"mode": item["mode"], "pos": [], "neg": []})
            g["pos" if positive else "neg"].append(item)
        if not any(g["pos"] for g in by.values()):
            raise SigmaError("vế chỉ có điều kiện phủ định")
        lines = [f"<if_sid>{parent['if_sid']}</if_sid>"]
        if "location" in parent:
            lines.append(f'<location type="pcre2">{escape(parent["location"])}</location>')
        lines += [_element(w, g["mode"], g["pos"], g["neg"]) for w, g in by.items()]
        d = desc + (f" (vế {k + 1}/{len(terms)})" if len(terms) > 1 else "")
        lines.append(f"<description>{escape(d)}</description>")
        if mitre:
            lines.append("<mitre>" + "".join(f"<id>{t}</id>" for t in mitre) + "</mitre>")
        lines += extra + [f"<group>{','.join(gs)},</group>"]
        ids.append(first_id + k)
        rules.append(f'  <rule id="{first_id + k}" level="{int(level)}">\n' +
                     "".join(f"    {x}\n" for x in lines) + "  </rule>\n")
    return Emitted("".join(rules), ids)


def unshadow(xml: str) -> str:
    """Bật chính thức (R71): bỏ nhóm `shadow` và dòng `shadow_since`, giữ nguyên phần còn lại."""
    xml = re.sub(r'[ \t]*<info type="text">shadow_since=[^<]*</info>\r?\n?', "", xml)
    return re.sub(r"<group>([^<]*)</group>",
                  lambda m: "<group>" + ",".join(g for g in m.group(1).split(",") if g != "shadow") + "</group>", xml)
