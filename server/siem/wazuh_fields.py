"""Ánh xạ trường ECS -> trường Wazuh và sinh rule ngoại lệ (level 0) cho rules-dynamic/exceptions.xml.

Giá trị do analyst nhập, nên KHÔNG BAO GIỜ được chèn nguyên văn: mỗi ký tự ngoài [A-Za-z0-9_-/:@] thành `\\xHH`
(chữ `.` thành `\\.`), nên mẫu pcre2 chỉ khớp đúng chuỗi đó và không còn ký tự nào cần escape XML (`&`, `<`, `"`...).
"""
from __future__ import annotations

import ipaddress
import re
from xml.sax.saxutils import escape

# trường tĩnh của rule Wazuh có thẻ riêng; còn lại là <field name="..."> động
STATIC = {"srcip", "dstip", "dstuser", "url"}
_MAP = {"source.ip": "srcip", "destination.ip": "dstip", "user.name": "dstuser", "url.original": "url",
        "file.path": "file"}
_SAFE = re.compile(r"[A-Za-z0-9_\-/:@]")


def to_wazuh(ecs_field: str, decoder: str | None) -> str:
    """Không có ánh xạ thì KeyError. Dòng lệnh: siem-procs là `cmd`, Windows eventchannel là win.eventdata.commandLine."""
    if ecs_field == "process.command_line":
        return "cmd" if decoder == "siem-procs" else "win.eventdata.commandLine"
    return _MAP[ecs_field]


def literal(value: str) -> str:
    """Mẫu pcre2 khớp đúng `value`, neo hai đầu (`\\z`, không phải `$` vì `$` còn khớp trước dấu xuống dòng cuối)."""
    out = "".join(c if _SAFE.match(c) else r"\." if c == "." else f"\\x{ord(c):02x}" if ord(c) < 128 else c
                  for c in value)
    return f"^{out}\\z"


def _condition(c: dict) -> str:
    name, value = to_wazuh(c["field"], c.get("decoder")), str(c["value"])
    if not value:
        raise ValueError(f"điều kiện {c['field']} có giá trị rỗng")
    if name in ("srcip", "dstip"):                      # thẻ IP của Wazuh nhận cả CIDR / regex: chỉ cho đúng 1 địa chỉ
        try:
            return f"<{name}>{ipaddress.ip_address(value)}</{name}>"
        except ValueError:
            raise ValueError(f"{c['field']} phải là một địa chỉ IP, không phải {value!r}") from None
    if name in STATIC:
        return f'<{name} type="pcre2">{literal(value)}</{name}>'
    return f'<field name="{name}" type="pcre2">{literal(value)}</field>'


def exception_rule(parent_id: int, conditions: list[dict], new_id: int, reason: str) -> str:
    """Một <rule level="0"> con của rule `parent_id`. Không có điều kiện thì lỗi: ngoại lệ không được tắt cả rule."""
    if not conditions:
        raise ValueError("ngoại lệ phải có ít nhất một điều kiện (không được tắt cả rule)")
    clean = "".join(c for c in reason if c.isprintable() or c.isspace())      # bỏ NUL và ký tự điều khiển
    desc = escape(" ".join(f"Ngoại lệ: {clean}".split())[:300])                # cắt TRƯỚC khi escape
    body = "\n".join("    " + _condition(c) for c in conditions)
    return (f'  <rule id="{int(new_id)}" level="0">\n    <if_sid>{int(parent_id)}</if_sid>\n{body}\n'
            f"    <description>{desc}</description>\n    <group>siem,exception,</group>\n  </rule>")
