"""Danh sách ngoại lệ đã duyệt -> rules-dynamic/exceptions.xml (rule level 0) qua wazuh_rules.write_dynamic.

Sổ cái exceptions.json nằm cạnh file XML (Wazuh chỉ nạp *.xml): giữ điều kiện gốc, người duyệt và bộ đếm id nên id ổn
định qua mỗi lần ghi lại toàn file, id đã gỡ không bao giờ dùng lại. Ghi XML trước (write_dynamic tự khôi phục file cũ
nếu Wazuh nạp lỗi), chỉ khi đó mới ghi sổ cái.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from . import wazuh_rules
from .wazuh_fields import exception_rule
from .wazuh_rules import DYNAMIC_DIR, WazuhRuleError

FILE, REGISTRY = "exceptions.xml", "exceptions.json"
FIRST, LAST = wazuh_rules.ID_RANGES["rules-dynamic/exceptions.xml"]


def _registry(root: Path) -> dict:
    p = root / REGISTRY
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {"next": FIRST, "items": []}


def items(root: Path | None = None) -> list[dict]:
    return _registry(root or DYNAMIC_DIR)["items"]


def _commit(reg: dict, api, root: Path) -> None:
    xml = "\n".join(exception_rule(i["parent"], i["conditions"], i["id"], i["reason"]) for i in reg["items"])
    wazuh_rules.write_dynamic(FILE, f'<group name="siem,exception,">\n{xml}\n</group>\n', api, root)
    tmp = root / (REGISTRY + ".tmp")
    tmp.write_text(json.dumps(reg, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(root / REGISTRY)


def add(rule: str, conditions: list[dict], reason: str, by: str, api, root: Path | None = None) -> dict:
    """ValueError nếu đầu vào sai (API trả 400), WazuhRuleError nếu Wazuh không nạp được (file cũ còn nguyên)."""
    root = root or DYNAMIC_DIR
    m = re.fullmatch(r"(?:WZH-)?(\d+)", rule.strip())
    if not m:
        raise ValueError(f"mã rule cha không hợp lệ: {rule!r} (dạng WZH-31103)")
    fields = [c.get("field") for c in conditions]
    if len(set(fields)) != len(fields):
        raise ValueError("mỗi trường chỉ được nêu một lần trong một ngoại lệ")
    reg = _registry(root)
    if reg["next"] > LAST:
        raise WazuhRuleError(f"hết id ngoại lệ ({FIRST}-{LAST})")
    item = {"id": reg["next"], "parent": int(m.group(1)), "rule": rule.strip(), "conditions": conditions,
            "reason": reason, "by": by}
    exception_rule(item["parent"], conditions, item["id"], reason)       # kiểm tra đầu vào trước khi đụng tới file
    _commit({"next": reg["next"] + 1, "items": reg["items"] + [item]}, api, root)
    return item


def remove(eid: int, api, root: Path | None = None) -> bool:
    root = root or DYNAMIC_DIR
    reg = _registry(root)
    left = [i for i in reg["items"] if i["id"] != eid]
    if len(left) == len(reg["items"]):
        return False
    _commit(reg | {"items": left}, api, root)
    return True
