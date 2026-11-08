"""Cầu nối cảnh báo của ruleset Wazuh -> alert của siem-xdr.

Phát hiện chạy hoàn toàn trong wazuh-analysisd (R65): rule gốc + rule dự án (wazuh/manager/rules, rules-dynamic).
Cầu nối chuyển rule dự án (id >= 100000), mọi cảnh báo từ level WAZUH_ALERT_MIN_LEVEL (WAZUH_ALERT_GROUPS rỗng = mọi
nhóm) và mọi cảnh báo từ WAZUH_ALERT_ANY_LEVEL; nhóm WAZUH_ALERT_EXCLUDE_GROUPS (mặc định sca: tư thế cấu hình) không
bao giờ chuyển. WAZUH_STOCK_SHADOW=true thì rule gốc ngoài WAZUH_ALERT_ACTIVE_GROUPS và dưới ANY_LEVEL là alert BÓNG
(is_shadow_stock, R38); alert bóng không bị chống trùng.
Level Wazuh (0-15) -> severity: <7 low, 7-9 medium, 10-11 high, >=12 critical.
"""
from __future__ import annotations

from .. import settings
from ..pipeline.normalize import Doc, get
from . import alerts as alert_builder

LOCAL_RULE_MIN_ID = 100000          # rule Wazuh tự viết (wazuh/manager/rules/0100-platform.xml): luôn chuyển, không coi là chung


def severity_for(level: int) -> str:
    if level >= 12:
        return "critical"
    if level >= 10:
        return "high"
    if level >= 7:
        return "medium"
    return "low"


def should_bridge(rule: dict, groups: set[str] | None = None, min_level: int | None = None,
                  any_level: int | None = None, exclude_groups: set[str] | None = None) -> bool:
    groups = settings.WAZUH_ALERT_GROUPS if groups is None else groups
    exclude = settings.WAZUH_ALERT_EXCLUDE_GROUPS if exclude_groups is None else exclude_groups
    min_level = settings.WAZUH_ALERT_MIN_LEVEL if min_level is None else min_level
    any_level = settings.WAZUH_ALERT_ANY_LEVEL if any_level is None else any_level
    try:
        level = int(rule.get("level") or 0)
    except (TypeError, ValueError):
        return False
    if _is_local(rule):
        return True
    # CỐ Ý loại sca ở mọi level (R22): SCA là tư thế cấu hình, không phải phát hiện; đừng "sửa" cho level cao đi qua
    if exclude & {str(g) for g in rule.get("groups") or []}:
        return False
    if level >= any_level:
        return True
    # groups rỗng = mọi nhóm (ruleset Wazuh là nguồn phát hiện duy nhất)
    return level >= min_level and (not groups or bool(groups & {str(g) for g in rule.get("groups") or []}))


def _is_local(rule: dict) -> bool:
    try:
        return int(rule.get("id") or 0) >= LOCAL_RULE_MIN_ID
    except (TypeError, ValueError):
        return False


class Suppressor:
    """Chống trùng: cùng khóa trong `window` giây chỉ cho qua lần đầu. Khóa quá hạn bị xóa mỗi lần gọi nên bộ nhớ
    chỉ giữ các khóa trong cửa sổ. `now` do người gọi đưa vào (analyzer dùng time.monotonic)."""

    def __init__(self, window: float | None = None) -> None:
        self.window = settings.WAZUH_ALERT_SUPPRESS if window is None else window
        self._seen: dict[tuple, float] = {}

    def seen(self, key: tuple, now: float) -> bool:
        self._seen = {k: t for k, t in self._seen.items() if now - t < self.window}
        if key in self._seen:
            return True
        self._seen[key] = now
        return False


def suppress_key(doc: Doc) -> tuple:
    # agent 000 dùng chung cho mọi thiết bị syslog: thiếu source.ip thì agent.id (syslog-<ip>) vẫn tách được nguồn
    agent = get(doc, "agent.id")
    # file.path: syscheck 550/554 trên các file KHÁC nhau của một agent là các thay đổi riêng (như main: mỗi thay đổi một alert)
    # process.pid: hai tiến trình độc hại khác nhau trên cùng agent là hai alert (mỗi cái một lệnh kill), không được gộp
    return (f"WZH-{get(doc, 'wazuh.rule.id')}", get(doc, "source.ip") or agent, agent, get(doc, "file.path"),
            get(doc, "process.pid"))


def is_shadow_stock(rule: dict, active_groups: set[str] | None = None, any_level: int | None = None) -> bool:
    """Rule gốc của Wazuh ngoài danh sách nhóm cũ và dưới level any: chạy bóng (chỉ đo, SOAR bỏ qua).
    Từ R65 mặc định tắt (WAZUH_STOCK_SHADOW=false): rule gốc đủ level là alert thật."""
    if not settings.WAZUH_STOCK_SHADOW:
        return False
    active = settings.WAZUH_ALERT_ACTIVE_GROUPS if active_groups is None else active_groups
    any_level = settings.WAZUH_ALERT_ANY_LEVEL if any_level is None else any_level
    if _is_local(rule):
        return False
    try:
        if int(rule.get("level") or 0) >= any_level:
            return False
    except (TypeError, ValueError):
        return False
    return not (active & {str(g) for g in rule.get("groups") or []})


def to_alert(doc: Doc) -> Doc | None:
    rule = get(doc, "wazuh.rule")
    if not isinstance(rule, dict) or not rule.get("id") or not should_bridge(rule):
        return None
    alert = alert_builder.from_wazuh(doc, severity_for(int(rule.get("level") or 0)))
    if is_shadow_stock(rule):
        alert["alert"]["shadow"] = True
        alert["rule"]["mode"] = "shadow"
    return alert
