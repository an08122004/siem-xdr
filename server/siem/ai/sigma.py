"""Rule Sigma do AI viết <-> rule engine của soc-platform.

AI viết rule mới ở định dạng Sigma (YAML) — định dạng model đã gặp hàng nghìn lần qua SigmaHQ — thay vì DSL riêng
của SIEM (danh sách mệnh đề {field, op, value} trong JSON). Chạy thử 4-7/10 với DSL: model 7-9B chép nguyên lệnh,
đưa từ đơn, viết regex đường dẫn Windows sai (phải thoát '\\' hai lần trong JSON) và không ghép được chương trình
với đối số (DSL chỉ cho OR các mệnh đề đơn). Sigma có sẵn các thứ đó: `Image|endswith` + `CommandLine|contains|all`
trong cùng selection, giá trị trong nháy đơn giữ nguyên dấu '\\'.

Module này:
  parse(text)               lấy 1 rule Sigma từ câu trả lời của model (khối ```yaml), kiểm tra cấu trúc
  compile_rule(rule, domain) biên dịch detection thành cây điều kiện của rule engine ({all|any|not} + lá),
                            ánh xạ tên trường Sigma (Image, CommandLine, cs-uri-query...) sang trường đã chuẩn hóa
  atoms / split / assemble  tách rule thành các vế độc lập (dạng tuyển chuẩn theo selection) để đo từng vế, bỏ vế
                            báo nhầm, rồi ghép các vế giữ lại thành rule Sigma cuối
  render / dump             YAML Sigma để người duyệt đọc và lưu kèm rule đã biên dịch
Chỉ hỗ trợ tập con Sigma cho rule 1 event: không có aggregation (| count), near, tìm từ khóa không gắn trường.
"""
from __future__ import annotations

import fnmatch
import re
import uuid
from datetime import date
from typing import Any, Callable

import yaml


class SigmaError(ValueError):
    """Rule Sigma không dùng được. Thông điệp viết bằng tiếng Anh vì được đưa lại cho LLM ở lượt sau."""


# ----------------------------------------------------------------------------- nguồn log và trường
LOGSOURCE = {
    "windows": {"category": "process_creation", "product": "windows"},
    "linux": {"category": "process_creation", "product": "linux"},
    "web": {"category": "webserver"},
    "other": {"product": "siem-xdr"},              # giá trị đã nằm trong rule AI đã duyệt: giữ tên cũ
}
# trường Sigma có trong log của SIEM theo lĩnh vực -> mô tả (đưa vào prompt)
FIELDS = {
    "windows": {"Image": "full path of the program", "CommandLine": "full command line",
                "ParentImage": "full path of the program that started it",
                "ParentCommandLine": "command line of the parent", "User": "account (DOMAIN\\user)",
                "CurrentDirectory": "working directory"},
    "linux": {"Image": "path of the program", "CommandLine": "full command line",
              "ParentImage": "path of the program that started it", "ParentCommandLine": "command line of the parent",
              "User": "account"},
    "web": {"cs-method": "HTTP method", "cs-uri-stem": "URL path",
            "cs-uri-query": "query string; every value is compared with both the raw (percent-encoded) and the "
                            "URL-decoded query",
            "c-useragent": "User-Agent header", "sc-status": "HTTP status code"},
}
_PROC = {"Image": "process.executable", "CommandLine": "process.command_line",
         "ParentImage": "process.parent.executable", "ParentCommandLine": "process.parent.command_line",
         "User": "user.name", "CurrentDirectory": "winlog.event_data.CurrentDirectory"}
_PROC_NAME = {"Image": "process.name", "ParentImage": "process.parent.name"}
# trường web -> (trường so cả giá trị / phần đầu, trường so chuỗi con / phần cuối / regex). url.query còn mã hóa
# phần trăm, url.decoded là cả URL đã giải mã: model viết payload đã giải mã (' or 'a'='a) hay còn mã hóa (%27)
# đều khớp — chạy thử 27/9: model so payload đã giải mã với url.query thô nên rule SQLi / SSI hỏng.
_WEB = {
    "cs-uri-query": (["url.query"], ["url.query", "url.decoded"]),
    "cs-uri-stem": (["url.path"], ["url.path", "url.decoded"]),
    "cs-uri": (["url.original"], ["url.original", "url.decoded"]),
    "cs-method": (["http.request.method"], ["http.request.method"]),
    "sc-status": (["http.response.status_code"], ["http.response.status_code"]),
    "c-useragent": (["user_agent.original"], ["user_agent.original"]),
    "cs-user-agent": (["user_agent.original"], ["user_agent.original"]),
    "cs-referer": (["http.request.referrer"], ["http.request.referrer"]),
    "c-ip": (["source.ip"], ["source.ip"]),
}
_ECS_FIELD = re.compile(r"^[a-z_@][a-z0-9_.@]*$")

_MODS = {"contains", "startswith", "endswith", "all", "re", "i", "m", "s", "windash", "cidr", "exists",
         "gt", "gte", "lt", "lte", "cased"}
_STRING_MODS = ("contains", "startswith", "endswith")
_MERGEABLE = {"contains", "startswith", "endswith", "regex", "eq", "in", "cidr"}


# ----------------------------------------------------------------------------- YAML
class _Dumper(yaml.SafeDumper):
    def increase_indent(self, flow: bool = False, indentless: bool = False):  # danh sách thụt lề như SigmaHQ
        return super().increase_indent(flow, False)

    def ignore_aliases(self, data: Any) -> bool:                               # không sinh &id001 / *id001
        return True


_PLAIN = re.compile(r"^[A-Za-z0-9_.\-]+(\|[A-Za-z0-9]+)*$")
_QUOTE = re.compile(r"[\\*?'\"#:{}\[\],&!|>%@`]")


def _str(dumper: yaml.SafeDumper, s: str):
    if "\n" in s:
        style = "|"
    elif _PLAIN.fullmatch(s):
        style = None
    elif _QUOTE.search(s) or s != s.strip() or not s:
        style = "'"                                       # giá trị Sigma: nháy đơn, '\' giữ nguyên
    else:
        style = None
    return dumper.represent_scalar("tag:yaml.org,2002:str", s, style=style)


_Dumper.add_representer(str, _str)


def dump(obj: Any) -> str:
    """YAML dễ đọc: chuỗi nhiều dòng dạng khối '|', giá trị có '\\' / ký tự đặc biệt trong nháy đơn."""
    return yaml.dump(obj, Dumper=_Dumper, sort_keys=False, allow_unicode=True, width=200, indent=2)


_FENCE = re.compile(r"```[ \t]*(?:ya?ml|sigma)?[ \t]*\n(.*?)(?:```|\Z)", re.S | re.I)
_DQ_BACKSLASH = re.compile(r'"([^"\n]*\\[^"\n]*)"')
_COND_LINE = re.compile(r"^(\s*condition:[ \t]*)([^'\"\n|>].*)$", re.M)
# `description: ... (ví dụ: svchost)` — giá trị không nháy chứa ': ' là YAML sai
_COLON_VALUE = re.compile(r"^(\s*(?:-\s+)?[A-Za-z_][\w\-|.]*:[ \t]+)([^'\"\n|>&*!%@`{\[][^\n]*?:\s[^\n]*)$", re.M)


class _Loader(yaml.SafeLoader):
    """Khóa lặp trong cùng selection (`CommandLine|contains: a` rồi `CommandLine|contains: b`): YAML giữ cái cuối và
    bỏ lặng lẽ các cái trước, trong khi ý model là phải có đủ (AND) -> gộp thành `CommandLine|contains|all: [a, b]`."""


def _mapping(loader: yaml.SafeLoader, node: yaml.MappingNode) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    out: dict[Any, Any] = {}
    for k_node, v_node in node.value:
        k = loader.construct_object(k_node, deep=True)
        v = loader.construct_object(v_node, deep=True)
        if k in out and isinstance(k, str) and "|" in k:
            vals = (out.pop(k) if isinstance(out[k], list) else [out.pop(k)]) + (v if isinstance(v, list) else [v])
            k = k if k.lower().endswith("|all") else k + "|all"
            prev = out.get(k)
            out[k] = (prev if isinstance(prev, list) else [prev] if prev is not None else []) + vals
        else:
            out[k] = v
    return out


_Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def _repairs(body: str) -> list[str]:
    r"""Các bản sửa YAML thử lần lượt: đường dẫn Windows trong nháy kép ("C:\Windows" là mã thoát sai của YAML) đổi sang
    nháy đơn; dòng condition chứa biểu thức trên trường (`not (CommandLine|contains: 'x')`, có ': ') đặt trong nháy."""
    dq = _DQ_BACKSLASH.sub(lambda mm: "'" + mm.group(1).replace("'", "''") + "'", body)
    q = lambda mm: mm.group(1) + "'" + mm.group(2).rstrip().replace("'", "''") + "'"
    quote = lambda b: _COLON_VALUE.sub(q, _COND_LINE.sub(q, b))
    return [dq, quote(body), quote(dq)]


def _fallback_condition(det: dict[str, Any], err: SigmaError) -> str | None:
    """Condition không đọc được (model viết biểu thức trên trường, tên selection không tồn tại...): thay bằng OR mọi
    selection, trừ filter (filter thì `and not`). Vế nào sai sẽ bị loại khi đo từng vế."""
    if "aggregations" in str(err) or "not supported" in str(err):
        return None                          # rule ngưỡng / `2 of`: nghĩa khác hẳn, báo lại cho model thay vì tự đổi
    names = _names(det)
    sel = [n for n in names if not n.lower().startswith(("filter", "_"))]
    flt = [n for n in names if n.lower().startswith("filter")]
    if not sel:
        return None
    cond = " or ".join(sel)
    return f"({cond}) and not ({' or '.join(flt)})" if flt else cond


def parse(text: str) -> dict[str, Any]:
    """Rule Sigma trong câu trả lời của model. {"no_rule": lý do} nếu model kết luận không cần rule."""
    m = _FENCE.search(text or "")
    body = (m.group(1) if m else text or "").replace("\t", "    ")
    try:
        doc = yaml.load(body, Loader=_Loader)  # noqa: S506 - _Loader kế thừa SafeLoader
    except yaml.YAMLError as first:
        for fixed in _repairs(body):
            try:
                doc = yaml.load(fixed, Loader=_Loader)  # noqa: S506
                break
            except yaml.YAMLError:
                continue
        else:
            raise SigmaError(f"invalid YAML: {str(first).splitlines()[0][:160]}") from None
    if isinstance(doc, list) and doc and isinstance(doc[0], dict):
        doc = doc[0]
    if not isinstance(doc, dict):
        raise SigmaError("expected one Sigma rule (a YAML mapping with title, logsource, detection)")
    if "detection" not in doc and doc.get("no_rule"):
        return {"no_rule": str(doc["no_rule"])[:500]}
    det = _detection(doc)
    try:
        _parse_condition(det["condition"], _names(det))
    except SigmaError as e:
        cond = _fallback_condition(det, e)
        if cond is None:
            raise
        # chạy thật 8/10: `condition: selection and not (CommandLine|contains|all: 'btool')` -> YAML hỏng cả 2 lần hỏi
        doc["detection"] = {**det, "condition": cond}
        doc["_condition_fixed"] = f"{str(det['condition'])[:200]} -> {cond} ({e})"
    return doc


def _detection(rule: dict[str, Any]) -> dict[str, Any]:
    det = rule.get("detection")
    if not isinstance(det, dict) or "condition" not in det:
        raise SigmaError("the rule needs a detection mapping with named selections and a condition")
    names = _names(det)
    if not names:
        raise SigmaError("detection has no selection")
    for n in names:
        body = det[n]
        if isinstance(body, dict) and body:
            continue
        if isinstance(body, list) and body and (all(isinstance(b, dict) and b for b in body)
                                                or all(isinstance(b, (str, int, float)) for b in body)):
            continue                                   # danh sách map (OR) hoặc danh sách từ khóa
        raise SigmaError(f"selection {n!r} must map field names to values, e.g. CommandLine|contains: '...'")
    return det


def _names(det: dict[str, Any]) -> list[str]:
    return [str(k) for k in det if k not in ("condition", "timeframe")]


# ----------------------------------------------------------------------------- điều kiện (condition)
_TOK = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*.\-]+)")


def _tokens(text: str) -> list[str]:
    if re.search(r"\|\s*(count|near|min|max|avg|sum)\b", text, re.I):
        raise SigmaError("aggregations in the condition (| count, near) are not supported: write a single-event rule")
    if "|" in text or ":" in text:
        raise SigmaError("field expressions are not allowed in the condition: put them in a selection (e.g. "
                         "filter_x) and reference it by name")
    out, pos = [], 0
    text = text.strip()
    while pos < len(text):
        m = _TOK.match(text, pos)
        if not m:
            raise SigmaError(f"cannot read the condition near {text[pos:pos + 20]!r}")
        out.append(m.group(1))
        pos = m.end()
        while pos < len(text) and text[pos].isspace():
            pos += 1
    return out


def _parse_condition(text: Any, names: list[str]) -> tuple:
    """Cây cú pháp: ('ref', tên) | ('and', [..]) | ('or', [..]) | ('not', x). `1 of x*` / `all of them` được
    khai triển thành or / and các selection khớp mẫu. Ưu tiên: not > and > or."""
    if isinstance(text, list):                      # Sigma cho phép danh sách điều kiện = OR
        text = " or ".join(f"({t})" for t in text)
    toks = _tokens(str(text))
    pos = 0

    def peek(k: int = 0) -> str | None:
        return toks[pos + k].lower() if pos + k < len(toks) else None

    def take() -> str:
        nonlocal pos
        if pos >= len(toks):
            raise SigmaError("the condition ends unexpectedly")
        pos += 1
        return toks[pos - 1]

    def expr() -> tuple:
        parts = [term()]
        while peek() == "or":
            take()
            parts.append(term())
        return parts[0] if len(parts) == 1 else ("or", parts)

    def term() -> tuple:
        parts = [factor()]
        while peek() == "and":
            take()
            parts.append(factor())
        return parts[0] if len(parts) == 1 else ("and", parts)

    def factor() -> tuple:
        t = peek()
        if t == "not":
            take()
            return ("not", factor())
        if t == "(":
            take()
            node = expr()
            if take() != ")":
                raise SigmaError("unbalanced parentheses in the condition")
            return node
        if t in ("1", "any", "all") and peek(1) == "of":
            quant, _ = take().lower(), take()
            pat = take()
            pool = [n for n in names if not n.startswith("_")] if pat.lower() == "them" else \
                [n for n in names if fnmatch.fnmatchcase(n, pat)]
            if not pool:
                raise SigmaError(f"no selection matches {pat!r} in the condition")
            refs = [("ref", n) for n in pool]
            return refs[0] if len(refs) == 1 else ("and" if quant == "all" else "or", refs)
        if t is not None and peek(1) == "of":
            raise SigmaError(f"'{take()} of' is not supported: use '1 of' or 'all of'")
        name = take()
        if name in ("(", ")") or name.lower() in ("and", "or", "not"):
            raise SigmaError(f"unexpected {name!r} in the condition")
        if name not in names:
            raise SigmaError(f"the condition refers to {name!r}, which is not a selection in detection")
        return ("ref", name)

    node = expr()
    if pos != len(toks):
        raise SigmaError(f"unexpected {toks[pos]!r} in the condition")
    return node


def _ast_text(node: tuple, top: bool = True) -> str:
    kind = node[0]
    if kind == "ref":
        return node[1]
    if kind == "not":
        return "not " + _ast_text(node[1], False)
    s = f" {kind} ".join(_ast_text(c, False) for c in node[1])
    return s if top else f"({s})"


# ----------------------------------------------------------------------------- biên dịch sang rule engine
_NEVER, _ALWAYS = object(), object()      # vế không bao giờ / luôn luôn đúng (trường không có trong log...)


def _leaf(field: str, op: str, value: Any) -> dict[str, Any]:
    return {"field": field, "op": op, "value": value}


def _any(children: list) -> Any:
    out: list = []
    for c in children:
        if c is _NEVER:
            continue
        if c is _ALWAYS:
            return _ALWAYS
        out.extend(c["any"] if isinstance(c, dict) and set(c) == {"any"} else [c])
    if not out:
        return _NEVER
    merged: list = []
    for c in out:                                          # gộp lá cùng trường + toán tử thành danh sách giá trị
        if "field" in c and c["op"] in _MERGEABLE:
            op = "in" if c["op"] == "eq" else c["op"]
            prev = next((m for m in merged if "field" in m and m["field"] == c["field"]
                         and ("in" if m["op"] == "eq" else m["op"]) == op), None)
            if prev is not None:
                vals = prev["value"] if isinstance(prev["value"], list) else [prev["value"]]
                add = c["value"] if isinstance(c["value"], list) else [c["value"]]
                prev.update(op=op, value=vals + [v for v in add if v not in vals])
                continue
        merged.append(dict(c))
    return merged[0] if len(merged) == 1 else {"any": merged}


def _all(children: list) -> Any:
    out: list = []
    for c in children:
        if c is _NEVER:
            return _NEVER
        if c is _ALWAYS:
            continue
        out.extend(c["all"] if isinstance(c, dict) and set(c) == {"all"} else [c])
    if not out:
        return _ALWAYS
    return out[0] if len(out) == 1 else {"all": out}


def _not(child: Any) -> Any:
    if child is _NEVER:
        return _ALWAYS
    if child is _ALWAYS:
        return _NEVER
    return {"not": child}


def _glob(value: str, mod: str | None) -> tuple[str, Any]:
    """Giá trị Sigma (wildcard * ?, '\\' thoát * ? \\) + modifier chuỗi -> (toán tử, giá trị) của rule engine."""
    toks: list[tuple[str, str]] = []
    buf: list[str] = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            buf.append(value[i + 1])
            i += 2
            continue
        if ch in "*?":
            if buf:
                toks.append(("lit", "".join(buf)))
                buf = []
            if not (ch == "*" and toks and toks[-1] == ("*", "")):
                toks.append((ch, ""))
            i += 1
            continue
        buf.append(ch)
        i += 1
    if buf:
        toks.append(("lit", "".join(buf)))
    if mod in ("contains", "endswith") and toks[:1] != [("*", "")]:
        toks.insert(0, ("*", ""))
    if mod in ("contains", "startswith") and toks[-1:] != [("*", "")]:
        toks.append(("*", ""))
    lead, trail = toks[:1] == [("*", "")], toks[-1:] == [("*", "")] and len(toks) > 1
    core = toks[1 if lead else 0: len(toks) - (1 if trail else 0)]
    if not core or all(t[0] == "*" for t in core):
        if not toks:                                   # CommandLine: '' -> trường rỗng
            return "eq", ""
        return "exists", True                          # '*' -> trường có giá trị bất kỳ
    if len(core) == 1 and core[0][0] == "lit":
        op = "contains" if lead and trail else "endswith" if lead else "startswith" if trail else "eq"
        return op, core[0][1]
    rx = "".join(re.escape(t[1]) if t[0] == "lit" else (".*" if t[0] == "*" else ".") for t in core)
    return "regex", ("" if lead else "^") + rx + ("" if trail else "$")


def _windash(value: str) -> list[str]:
    """`-foo` cũng khớp `/foo` (và gạch ngang dài) — cờ dòng lệnh Windows viết kiểu nào cũng được."""
    for i, ch in enumerate(value):
        if ch in "-/" and (i == 0 or value[i - 1] in " \t\"'"):
            return [value[:i] + d + value[i + 1:] for d in ("-", "/", "\u2013")]
    return [value]


def _value_ops(v: Any, mods: list[str], key: str) -> list[tuple[str, Any]]:
    """Một giá trị Sigma -> các (toán tử, giá trị) thay thế nhau (OR)."""
    if isinstance(v, (dict, list)):
        raise SigmaError(f"{key}: values must be strings or numbers, not nested lists or maps")
    if "exists" in mods:
        return [("exists", bool(v))]
    if v is None:
        return [("exists", False)]
    if "re" in mods:
        if any(m in mods for m in _STRING_MODS):
            raise SigmaError(f"{key}: re cannot be combined with contains / startswith / endswith")
        from .validate import fix_regex          # nhập muộn: validate -> prompts -> sigma
        flags = "".join(f for f in "ims" if f in mods)
        return [("regex", (f"(?{flags})" if flags else "") + str(fix_regex(str(v))))]
    if "cidr" in mods:
        return [("cidr", str(v))]
    cmp = [m for m in mods if m in ("gt", "gte", "lt", "lte")]
    if cmp:
        return [(cmp[0], v)]
    if isinstance(v, bool) or not isinstance(v, str):
        return [("eq", v)]
    mod = next((m for m in mods if m in _STRING_MODS), None)
    variants = _windash(v) if "windash" in mods else [v]
    return [_glob(s, mod) for s in variants]


def _canon(name: str, table: dict[str, Any]) -> str | None:
    low = name.lower()
    return next((k for k in table if k.lower() == low), None)


def _map(name: str, op: str, val: Any, domain: str, notes: set[str]) -> Any:
    """(trường Sigma, toán tử, giá trị) -> lá của rule engine; _NEVER nếu log không có trường đó."""
    if domain in ("windows", "linux"):
        canon = _canon(name, _PROC)
        if canon is None or canon not in FIELDS[domain]:
            notes.add(f"field {name} is not recorded in these logs (available: {', '.join(FIELDS[domain])})")
            return _NEVER
        if canon in _PROC_NAME and isinstance(val, str):
            # Image|endswith: '\reg.exe' -> process.name: log Linux có khi chỉ ghi tên chương trình (cat), không có đường dẫn
            if op == "endswith" and val[:1] in "\\/" and not re.search(r"[\\/]", val[1:]):
                return _leaf(_PROC_NAME[canon], "eq", val[1:])
            if op == "eq" and not re.search(r"[\\/]", val):
                return _leaf(_PROC_NAME[canon], "eq", val)
        return _leaf(_PROC[canon], op, val)
    if domain == "web":
        canon = _canon(name, _WEB)
        if canon is None:
            notes.add(f"field {name} is not recorded in these logs (available: {', '.join(FIELDS['web'])})")
            return _NEVER
        exact, sub = _WEB[canon]
        fields = sub if op in ("contains", "endswith", "regex") else exact
        return _any([_leaf(f, op, val) for f in fields])
    if not _ECS_FIELD.match(name):
        raise SigmaError(f"field {name!r} does not exist: use the dotted field names shown in the samples")
    return _leaf(name, op, val)


def _field(key: str, value: Any, domain: str, notes: set[str]) -> Any:
    name, *mods = [p.strip() for p in str(key).split("|")]
    mods = [m.lower() for m in mods if m]
    bad = [m for m in mods if m not in _MODS]
    if bad:
        raise SigmaError(f"modifier {bad[0]!r} is not supported: use contains, startswith, endswith, all, re, windash "
                         "or cidr")
    values = value if isinstance(value, list) else [value]
    if not values:
        raise SigmaError(f"{key}: empty list of values")
    per_value = [_any([_map(name, op, v2, domain, notes) for op, v2 in _value_ops(v, mods, key)]) for v in values]
    return _all(per_value) if "all" in mods else _any(per_value)


_KEYWORD_FIELDS = {"web": ["url.original", "url.decoded", "user_agent.original"],
                   "windows": ["process.command_line"], "linux": ["process.command_line"]}


def _keywords(values: list[Any], domain: str, all_: bool = False) -> Any:
    """Từ khóa không gắn trường (SigmaHQ hay dùng cho web: `- u0027`): tìm trong URL / User-Agent, hoặc dòng lệnh."""
    fields = _KEYWORD_FIELDS.get(domain)
    if not fields:
        raise SigmaError("keyword searches without a field are not supported here: name the field")
    per = []
    for v in values:
        op, val = _glob(str(v), "contains")
        per.append(_any([_leaf(f, op, val) for f in fields]))
    return _all(per) if all_ else _any(per)


def _selection(body: Any, domain: str, notes: set[str]) -> Any:
    if isinstance(body, list):
        if body and not isinstance(body[0], dict):
            return _keywords(body, domain)
        return _any([_selection(b, domain, notes) for b in body])
    parts = []
    for k, v in body.items():
        if str(k).startswith("|"):                     # keywords: {'|all': [...]}
            vals = v if isinstance(v, list) else [v]
            parts.append(_keywords(vals, domain, all_="all" in str(k).lower()))
        else:
            parts.append(_field(k, v, domain, notes))
    return _all(parts)


def _build(node: tuple, sel: Callable[[str], Any]) -> Any:
    kind = node[0]
    if kind == "ref":
        return sel(node[1])
    if kind == "not":
        return _not(_build(node[1], sel))
    parts = [_build(c, sel) for c in node[1]]
    return _all(parts) if kind == "and" else _any(parts)


def compile_rule(rule: dict[str, Any], domain: str) -> tuple[dict[str, Any], list[str]]:
    """Detection Sigma -> (cây điều kiện của rule engine, ghi chú). domain: windows | linux | web | other."""
    det = _detection(rule)
    names = _names(det)
    ast = _parse_condition(det["condition"], names)
    notes: set[str] = set()
    cache: dict[str, Any] = {}

    def sel(n: str) -> Any:
        if n not in cache:
            cache[n] = _selection(det[n], domain, notes)
        return cache[n]

    node = _build(ast, sel)
    if node is _NEVER:
        raise SigmaError("the rule can never match: " + ("; ".join(sorted(notes)) or "every branch is impossible"))
    if node is _ALWAYS:
        raise SigmaError("the condition matches every event")
    return node, sorted(notes)


# ----------------------------------------------------------------------------- tách / ghép vế
MAX_TERMS = 32


def _dnf(node: tuple, neg: bool = False) -> list[frozenset[tuple[str, bool]]]:
    kind = node[0]
    if kind == "ref":
        return [frozenset({(node[1], not neg)})]
    if kind == "not":
        return _dnf(node[1], not neg)
    parts = [_dnf(c, neg) for c in node[1]]
    if (kind == "and") == neg:                     # or (hoặc and bị phủ định)
        return [t for p in parts for t in p]
    out = [frozenset()]
    for p in parts:
        out = [a | b for a in out for b in p]
        if len(out) > MAX_TERMS:
            raise OverflowError
    return out


def _atom(det: dict[str, Any], pos: list[str] | None, neg: list[str], condition: str = "",
          parent: dict | None = None, split: tuple | None = None) -> dict[str, Any]:
    return {"detection": det, "pos": pos, "neg": neg, "condition": condition, "parent": parent, "split": split}


def atom_condition(a: dict[str, Any]) -> str:
    if a["pos"] is None:
        return a["condition"]
    return " and ".join(a["pos"] + [f"not {n}" for n in a["neg"]])


def atom_rule(a: dict[str, Any]) -> dict[str, Any]:
    """Vế dưới dạng rule Sigma (chỉ phần detection) để biên dịch / đưa lại cho LLM."""
    return {"detection": {**a["detection"], "condition": atom_condition(a)}}


def atoms(rule: dict[str, Any]) -> list[dict[str, Any]]:
    """Các vế độc lập của rule: mỗi vế = AND của các selection (có thể kèm `not filter`), rule = OR các vế.
    Vd `1 of selection_* and not filter` -> (selection_a and not filter), (selection_b and not filter)."""
    det = _detection(rule)
    names = _names(det)
    ast = _parse_condition(det["condition"], names)
    try:
        terms = _dnf(ast)
    except OverflowError:                           # điều kiện quá phức tạp -> giữ nguyên cả rule làm 1 vế
        used = sorted({n for n in names if re.search(rf"(?<![\w*.\-]){re.escape(n)}(?![\w*.\-])", _ast_text(ast))})
        return [_atom({n: det[n] for n in used}, None, [], _ast_text(ast))]
    out, seen = [], set()
    for t in terms:
        pos = sorted(n for n, p in t if p)
        neg = sorted(n for n, p in t if not p)
        if not pos or set(pos) & set(neg) or (key := (tuple(pos), tuple(neg))) in seen:
            continue
        seen.add(key)
        out.append(_atom({n: det[n] for n in pos + neg}, pos, neg))
    if not out:
        raise SigmaError("the condition has no selection outside 'not'")
    return out


def split(a: dict[str, Any]) -> list[dict[str, Any]]:
    """Tách một vế bị loại thành các vế nhỏ hơn để cứu phần tốt: selection là danh sách map -> mỗi map một vế;
    không thì danh sách giá trị OR dài nhất -> mỗi giá trị một vế. Không tách được -> []."""
    if a["pos"] is None:
        return []
    det = a["detection"]
    for n in a["pos"]:
        body = det[n]
        if isinstance(body, list) and len(body) > 1:
            return [_atom({**det, n: b if isinstance(b, dict) else [b]}, a["pos"], a["neg"], parent=a,
                          split=(n, None, b)) for b in body]
    best = None
    for n in a["pos"]:
        body = det[n]
        if isinstance(body, dict):
            for k, v in body.items():
                if isinstance(v, list) and len(v) > 1 and "all" not in str(k).lower().split("|")[1:] \
                        and (best is None or len(v) > best[0]):
                    best = (len(v), n, k)
    if best is None:
        return []
    _, n, k = best
    return [_atom({**det, n: {**det[n], k: v}}, a["pos"], a["neg"], parent=a, split=(n, k, v)) for v in det[n][k]]


def relax(a: dict[str, Any]) -> list[dict[str, Any]]:
    """Nới một vế KHÔNG khớp mẫu train nào, cho các lỗi model hay mắc (chạy thật 8/10): danh sách LỰA CHỌN đặt dưới
    `|all` (SQLi: 10 dấu hiệu thành bắt buộc có đủ cả 10); `all of selection_*` thay cho `1 of` (8 selection phải khớp
    cùng lúc); filter loại luôn cả tấn công (`not sc-status: 200`). Trả về: vế bỏ filter; từng selection đứng riêng;
    vế đổi `|all` đầu tiên thành OR. Vế nới vẫn qua mọi kiểm tra như vế gốc (rộng quá thì bị tập bình thường chặn rồi
    được tách nhỏ)."""
    if a["pos"] is None:
        return []
    det, out = a["detection"], []
    if a["neg"]:
        out.append(_atom({n: det[n] for n in a["pos"]}, a["pos"], []))
    if len(a["pos"]) > 1:
        out += [_atom({n: det[n], **{f: det[f] for f in a["neg"]}}, [n], a["neg"]) for n in a["pos"]]
    for n in a["pos"]:
        body = det[n]
        if not isinstance(body, dict):
            continue
        for k, v in body.items():
            parts = str(k).split("|")
            if any(p.lower() == "all" for p in parts[1:]) and isinstance(v, list) and len(v) > 1:
                nk = "|".join(p for p in parts if p.lower() != "all")
                if nk in body:
                    continue
                out.append(_atom({**det, n: {(nk if kk == k else kk): vv for kk, vv in body.items()}}, a["pos"], a["neg"]))
                return out
    return out


def generalize(a: dict[str, Any]) -> list[dict[str, Any]]:
    """Các bản TỔNG QUÁT hơn của một vế đã đạt: bỏ filter; bỏ một selection khỏi vế AND; bỏ một trường khỏi selection.
    Chạy thật 8/10 (T1087.002): model gắn AdFind.exe với đúng đối số của bài thử train (`-sc admincountdmp`) và thêm
    filter loại mọi tiến trình powershell / cmd -> 0% bài thử chưa thấy, trong khi bản DSL `process.name = adfind.exe`
    bắt 88%. Bên gọi chỉ nhận bản tổng quát nếu vẫn sạch (không khớp mẫu bình thường, đủ đặc trưng) và vẫn bắt mọi
    mẫu train cũ: `reg.exe` đứng riêng vẫn bị tập bình thường chặn, `AdFind.exe` thì không."""
    if a["pos"] is None:
        return []
    det, out = a["detection"], []
    if a["neg"]:
        out.append(_atom({n: det[n] for n in a["pos"]}, a["pos"], []))
    if len(a["pos"]) > 1:
        for n in a["pos"]:
            rest = [m for m in a["pos"] if m != n]
            out.append(_atom({**{m: det[m] for m in rest}, **{f: det[f] for f in a["neg"]}}, rest, a["neg"]))
    for n in a["pos"]:
        body = det[n]
        if isinstance(body, dict) and len(body) > 1:
            out += [_atom({**det, n: {kk: vv for kk, vv in body.items() if kk != k}}, a["pos"], a["neg"])
                    for k in body]
    return out


def _merge(kept: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Các vế tách từ cùng một vế cha được ghép lại thành danh sách giá trị cho dễ đọc (nghĩa không đổi)."""
    out: list[dict[str, Any]] = []
    groups: dict[tuple, list[dict[str, Any]]] = {}
    for a in kept:
        if a["split"] is None:
            out.append(a)
            continue
        key = (id(a["parent"]), a["split"][0], a["split"][1])
        if key not in groups:
            groups[key] = []
            out.append({"_group": key})
        groups[key].append(a)
    res = []
    for a in out:
        if "_group" not in a:
            res.append(a)
            continue
        members = groups[a["_group"]]
        if len(members) == 1:
            res.append(members[0])
            continue
        parent, (n, k, _) = members[0]["parent"], members[0]["split"]
        pieces = [m["split"][2] for m in members]
        body = pieces if k is None else {**parent["detection"][n], k: pieces}
        res.append(_atom({**parent["detection"], n: body}, parent["pos"], parent["neg"]))
    return res


def assemble(kept: list[dict[str, Any]]) -> dict[str, Any]:
    """Ghép các vế giữ lại thành detection Sigma: selection được đặt hậu tố _1, _2... để không trùng tên."""
    merged = _merge(kept)
    det: dict[str, Any] = {}
    parts = []
    multi = len(merged) > 1
    for i, a in enumerate(merged, 1):
        ren = {n: (f"{n}_{i}" if multi else n) for n in a["detection"]}
        for n, nn in ren.items():
            det[nn] = a["detection"][n]
        cond = atom_condition(a)
        for n in sorted(ren, key=len, reverse=True):
            cond = re.sub(rf"(?<![\w*.\-]){re.escape(n)}(?![\w*.\-])", ren[n], cond)
        parts.append(f"({cond})" if multi and re.search(r"\s(and|or)\s", cond) else cond)
    det["condition"] = " or ".join(parts)
    return det


def detection_yaml(a: dict[str, Any]) -> str:
    return dump(atom_rule(a)["detection"])


# ----------------------------------------------------------------------------- xuất rule
_TECH = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.I)
_TACTIC = re.compile(r"^attack\.([a-z][a-z\-]+)$", re.I)


def attack_tags(tags: Any) -> tuple[list[str], str]:
    """(kỹ thuật ATT&CK T1003.002..., tactic đầu tiên) từ tag Sigma attack.*."""
    techs, tactic = [], ""
    for t in tags if isinstance(tags, list) else []:
        if (m := _TECH.match(str(t).strip())):
            techs.append(m.group(1).upper())
        elif (m := _TACTIC.match(str(t).strip())) and not tactic:
            tactic = m.group(1).lower()
    return list(dict.fromkeys(techs)), tactic


def render(rule: dict[str, Any], *, title: str, description: str, level: str, techniques: list[str], tactic: str,
           logsource: dict[str, str], author: str, derived: list[dict[str, Any]] | None = None) -> str:
    """Rule Sigma hoàn chỉnh (YAML) cho người duyệt / xuất ra SIEM khác: siêu dữ liệu chuẩn hóa, detection giữ nguyên.
    derived: rule SigmaHQ có vế được dùng -> `related` (type derived) và tác giả gốc, theo giấy phép DRL 1.1."""
    tags = ([f"attack.{tactic}"] if tactic else []) + [f"attack.{t.lower()}" for t in techniques]
    fps = [str(x)[:200] for x in rule.get("falsepositives") or [] if isinstance(x, (str, int, float))][:5]
    derived = [d for d in derived or [] if d.get("id")]
    if derived:
        authors = sorted({str(d.get("author") or "SigmaHQ").strip() for d in derived})
        author = f"{author}; dựa trên rule SigmaHQ (DRL 1.1) của {', '.join(authors)[:300]}"
    doc = {"title": title, "id": str(uuid.uuid4()), "status": "experimental", "description": description,
           **({"related": [{"id": d["id"], "type": "derived"} for d in derived]} if derived else {}),
           "author": author, "date": date.today().isoformat(), "tags": tags, "logsource": logsource,
           "detection": rule["detection"], "falsepositives": fps or ["Unknown"], "level": level}
    return dump(doc)


def reference(r: dict[str, Any]) -> str:
    """Rule SigmaHQ tham khảo (RAG) ở dạng YAML gọn: tiêu đề, tag, nguồn log, detection."""
    head = dump({"title": r.get("title"), "tags": r.get("tags") or [], "logsource": r.get("logsource") or {}})
    det = str(r.get("detection") or "").rstrip()
    return head + "detection:\n" + "\n".join("    " + line for line in det.splitlines())
