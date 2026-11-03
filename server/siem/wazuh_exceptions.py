"""Ngoại lệ đã duyệt -> rules-dynamic/exceptions.xml (rule level 0) qua wazuh_rules.write_dynamic.

Quy trình (giống ngoại lệ AI ở ai/deploy.py: làm giảm cảnh báo thì cần 2 người KHÁC NHAU):
  add      -> trạng thái `pending`, người tạo là người duyệt thứ nhất; chưa vào XML.
  approve  -> người KHÁC duyệt; đủ 2 người thì `active` và mới được ghi vào exceptions.xml.
  remove   -> bật lại phát hiện (hướng an toàn) nên 1 người đủ; mục chuyển `removed`, giữ lại làm lịch sử.

Sổ cái exceptions.json (cạnh file XML; Wazuh chỉ nạp *.xml) là nguồn sự thật, được ghi TRƯỚC khi đụng tới XML: rule
level 0 đang tắt phát hiện không bao giờ tồn tại mà thiếu mục trong sổ cái. XML lỗi thì mục bị đánh dấu `failed`
(hoặc trả về trạng thái cũ khi gỡ). Bộ đếm id chỉ tăng: id đã dùng (kể cả gỡ / lỗi) KHÔNG bao giờ được giải phóng; dải
110000-110999 có 1000 id, từ 90% trở đi cảnh báo.
Manager chạy 1 tiến trình uvicorn (docker-compose.yml, không có --workers) nên khóa luồng là đủ; đổi sang nhiều worker
thì phải thêm khóa file.

## Kiểm thật (hoãn)  # Docker tắt, chưa chạy trên Wazuh thật
 (a) logtest: sự kiện khớp đồng thời 31106 gốc (rule con mã 200 của 31103) và một ngoại lệ con của 31103 -> rule nào
     thắng. Nếu ngoại lệ thua thì thêm `<if_sid>` gồm cha + các rule con cháu.
 (b) rule con mức 0 thắng trên 31103 có che luôn rule tấn công SQLi con của 31103 cho nguồn đó không (tắt cả nhánh).
 (c) `type="pcre2"` được nhận trên `<url>` / `<dstuser>`, và `\\xHH` / `\\z` đi qua bộ đọc XML nguyên vẹn.
Chưa làm: recheck với mẫu tấn công vàng (cần logtest).
"""
from __future__ import annotations

import json
import logging
import re
import threading
from datetime import datetime, timezone
from pathlib import Path

from . import wazuh_rules
from .wazuh_fields import exception_rule
from .wazuh_rules import DYNAMIC_DIR, WazuhRuleError

log = logging.getLogger("wazuh_exceptions")
FILE, REGISTRY = "exceptions.xml", "exceptions.json"
FIRST, LAST = wazuh_rules.ID_RANGES["rules-dynamic/exceptions.xml"]
REQUIRED = 2
_lock = threading.Lock()


class Duplicate(ValueError):
    """Đã có ngoại lệ (đang chờ hoặc đang áp dụng) cùng rule cha và điều kiện."""


class NotFound(LookupError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _load(root: Path) -> dict:
    p = root / REGISTRY
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {"next": FIRST, "items": []}


def _save(reg: dict, root: Path) -> None:
    tmp = root / (REGISTRY + ".tmp")
    tmp.write_text(json.dumps(reg, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(root / REGISTRY)


def items(root: Path | None = None) -> list[dict]:
    return _load(root or DYNAMIC_DIR)["items"]


def used(root: Path | None = None) -> int:
    return _load(root or DYNAMIC_DIR)["next"] - FIRST


def _render(reg: dict, api, root: Path) -> None:
    xml = "\n".join(exception_rule(i["parent"], i["conditions"], i["id"], i["reason"])
                    for i in reg["items"] if i["status"] == "active")
    wazuh_rules.write_dynamic(FILE, f'<group name="siem,exception,">\n{xml}\n</group>\n', api, root)


def _check_parent(api, pid: int) -> None:
    if FIRST <= pid <= LAST:
        raise ValueError("rule cha không được là một ngoại lệ")
    rule = api.rule(pid)                          # WazuhUnavailable nếu không hỏi được API: từ chối
    if rule is None:
        raise ValueError(f"Wazuh không có rule {pid}")
    if int(rule.get("level", 0)) == 0:
        raise ValueError(f"rule {pid} đã ở level 0, không cần ngoại lệ")


def _key(parent: int, conditions: list[dict]) -> tuple:
    return parent, tuple(sorted((c["field"], c.get("decoder") or "", str(c["value"])) for c in conditions))


def _get(reg: dict, eid: int) -> dict:
    for i in reg["items"]:
        if i["id"] == eid:
            return i
    raise NotFound(eid)


def add(rule: str, conditions: list[dict], reason: str, by: str, api, root: Path | None = None) -> dict:
    """ValueError: đầu vào sai (400); Duplicate: trùng (409); WazuhUnavailable: không hỏi được Wazuh (503)."""
    root = root or DYNAMIC_DIR
    m = re.fullmatch(r"(?:WZH-)?(\d+)", rule.strip())
    if not m:
        raise ValueError(f"mã rule cha không hợp lệ: {rule!r} (dạng WZH-31103)")
    parent = int(m.group(1))
    if len({c.get("field") for c in conditions}) != len(conditions):
        raise ValueError("mỗi trường chỉ được nêu một lần trong một ngoại lệ")
    exception_rule(parent, conditions, FIRST, reason)             # kiểm tra điều kiện / giá trị trước khi đụng tới file
    _check_parent(api, parent)
    with _lock:
        reg = _load(root)
        if any(i["status"] in ("pending", "active") and _key(i["parent"], i["conditions"]) == _key(parent, conditions)
               for i in reg["items"]):
            raise Duplicate("đã có ngoại lệ giống hệt (đang chờ duyệt hoặc đang áp dụng)")
        if reg["next"] > LAST:
            raise WazuhRuleError(f"hết id ngoại lệ ({FIRST}-{LAST}), id đã dùng không được giải phóng")
        item = {"id": reg["next"], "parent": parent, "rule": rule.strip(), "conditions": conditions, "reason": reason,
                "status": "pending", "created_by": by, "created_at": _now(), "approvals": [{"by": by, "at": _now()}]}
        reg["next"] += 1
        reg["items"].append(item)
        _save(reg, root)                                           # pending chưa vào XML nên chỉ cần sổ cái
    if reg["next"] - FIRST >= 0.9 * (LAST - FIRST + 1):
        log.warning("đã dùng %d/%d id ngoại lệ", reg["next"] - FIRST, LAST - FIRST + 1)
    return item


def approve(eid: int, by: str, api, root: Path | None = None) -> dict:
    root = root or DYNAMIC_DIR
    with _lock:
        reg = _load(root)
        item = _get(reg, eid)
        if item["status"] != "pending":
            raise WazuhRuleError(f"ngoại lệ đang ở trạng thái {item['status']}, không duyệt được")
        if any(a["by"].lower() == by.lower() for a in item["approvals"]):
            raise ValueError("mỗi người chỉ duyệt một lần, cần người duyệt khác")
        item["approvals"].append({"by": by, "at": _now()})
        if len({a["by"].lower() for a in item["approvals"]}) >= REQUIRED:
            item.update(status="active", activated_at=_now())
            _save(reg, root)                                       # sổ cái trước, XML sau
            try:
                _render(reg, api, root)
            except WazuhRuleError as e:
                item.update(status="failed", error=str(e))
                _save(reg, root)
                raise
        else:
            _save(reg, root)
        return item


def remove(eid: int, by: str, reason: str, api, root: Path | None = None) -> dict:
    root = root or DYNAMIC_DIR
    with _lock:
        reg = _load(root)
        item = _get(reg, eid)
        if item["status"] in ("removed", "failed"):
            raise NotFound(eid)
        was = item["status"]
        item.update(status="removed", removed_by=by, removed_at=_now(), removed_reason=reason)
        _save(reg, root)
        if was == "active":
            try:
                _render(reg, api, root)
            except WazuhRuleError:
                for k in ("removed_by", "removed_at", "removed_reason"):
                    item.pop(k, None)
                item["status"] = was                               # XML vẫn còn rule này: sổ cái phải nói đúng
                _save(reg, root)
                raise
        return item
