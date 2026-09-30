"""Cầu nối cảnh báo của ruleset Wazuh -> alert của siem-xdr.

siem-xdr tự phát hiện bằng rule YAML của mình (server/rules) trên MỌI event lấy từ archives.json. Ruleset Wazuh
(hơn 3.000 rule) phần lớn trùng việc với rule tự viết (tấn công web, SSH, đăng nhập Windows...), nên KHÔNG chuyển
hết sang, tránh mỗi sự cố thành 2 alert. Chỉ lấy:
  - các nhóm rule mà siem-xdr không có rule tương đương (mặc định: FIM `syscheck`, `rootcheck`...),
    từ level WAZUH_ALERT_MIN_LEVEL trở lên. SCA (đánh giá CIS) không nằm trong mặc định: đó là tư thế cấu hình;

  - mọi cảnh báo có level >= WAZUH_ALERT_ANY_LEVEL (Wazuh coi là rất nghiêm trọng), bất kể nhóm.
Level Wazuh (0-15) -> severity: <7 low, 7-9 medium, 10-11 high, >=12 critical.
"""
from __future__ import annotations

from .. import settings
from ..pipeline.normalize import Doc, get
from . import alerts as alert_builder


def severity_for(level: int) -> str:
    if level >= 12:
        return "critical"
    if level >= 10:
        return "high"
    if level >= 7:
        return "medium"
    return "low"


def should_bridge(rule: dict, groups: set[str] | None = None, min_level: int | None = None,
                  any_level: int | None = None) -> bool:
    groups = settings.WAZUH_ALERT_GROUPS if groups is None else groups
    min_level = settings.WAZUH_ALERT_MIN_LEVEL if min_level is None else min_level
    any_level = settings.WAZUH_ALERT_ANY_LEVEL if any_level is None else any_level
    try:
        level = int(rule.get("level") or 0)
    except (TypeError, ValueError):
        return False
    if level >= any_level:
        return True
    return level >= min_level and bool(groups & {str(g) for g in rule.get("groups") or []})


def to_alert(doc: Doc) -> Doc | None:
    rule = get(doc, "wazuh.rule")
    if not isinstance(rule, dict) or not rule.get("id") or not should_bridge(rule):
        return None
    return alert_builder.from_wazuh(doc, severity_for(int(rule.get("level") or 0)))
