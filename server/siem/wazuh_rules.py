"""Đọc file rule Wazuh (XML) và ghi file rule ĐỘNG (AI, ngoại lệ) an toàn, nạp lại không cần khởi động lại.

Rule của repo nằm ở wazuh/manager/rules (mount chỉ đọc). Hai file do console ghi (ai.xml, exceptions.xml) nằm ở volume
`wazuh_dynamic_rules` (manager: /app/wazuh-rules, wazuh-manager: /var/ossec/etc/rules-dynamic).
Wazuh trả HTTP 200 cả khi nạp lại hỏng và âm thầm bỏ rule trùng id / sai if_sid, nên reload() đọc thân JSON.
"""
from __future__ import annotations

import logging
import os
import xml.etree.ElementTree as ET
from pathlib import Path

from . import settings
from .soar.wazuh import WazuhAPI, WazuhError

log = logging.getLogger("wazuh_rules")

DYNAMIC_DIR = Path("/app/wazuh-rules")
RELOAD_OK = "Ruleset reload request sent successfully."

# Dải id theo file (lint ở Task 4 đọc bảng này). 0190-tuning.xml không có dải: chỉ overwrite="yes" trên id < 100000.
ID_RANGES: dict[str, tuple[int, int]] = {
    "0100-platform.xml": (100000, 100999), "0101-auth.xml": (101000, 101999), "0102-linux.xml": (102000, 102499), "0851-linux-audit.xml": (102500, 102999),
    "0103-network.xml": (103000, 103999), "0104-web.xml": (104000, 104999), "0105-windows.xml": (105000, 105999),
    "0106-fim.xml": (106000, 106999), "0107-ti.xml": (107000, 107999), "0108-sigmahq.xml": (108000, 108999),
    "rules-dynamic/ai.xml": (109000, 109999), "rules-dynamic/exceptions.xml": (110000, 110999),
}
TUNING_FILE = "0190-tuning.xml"


class WazuhRuleError(ValueError):
    pass


def _split(text: str | None) -> list[str]:
    return [x.strip() for x in (text or "").split(",") if x.strip()]


def parse(xml_text: str) -> list[dict]:
    """File rule Wazuh không có thẻ gốc duy nhất -> bọc <root> rồi parse. Trả về mỗi rule một dict."""
    try:
        root = ET.fromstring(f"<root>{xml_text}</root>")
    except ET.ParseError as e:
        raise WazuhRuleError(f"XML sai cú pháp: {e}") from e
    rules = []
    for grp in root.iter("group"):
        for r in grp.findall("rule"):
            try:
                rid, level = int(r.get("id", "")), int(r.get("level", ""))
            except ValueError:
                raise WazuhRuleError(f"rule thiếu hoặc sai id/level: {r.attrib}") from None
            rules.append({
                "id": rid, "level": level,
                "description": (r.findtext("description") or "").strip(),
                "groups": _split(grp.get("name")) + [g for e in r.findall("group") for g in _split(e.text)],
                "mitre": [i.text.strip() for i in r.findall("mitre/id") if i.text],
                "info": [i.text.strip() for i in r.findall("info") if i.text],
                "overwrite": r.get("overwrite") == "yes",
                "if_sid": [int(s) for e in r.findall("if_sid") for s in _split(e.text) if s.isdigit()],
            })
    return rules


class WazuhApi(WazuhAPI):
    """WazuhAPI của SOAR (đăng nhập, JWT, request) + các lời gọi quản lý rule, đăng nhập bằng user `siem-rules`."""

    @classmethod
    def from_settings(cls) -> "WazuhApi":
        return cls(settings.WAZUH_API_URL, settings.WAZUH_RULES_API_USER, settings.WAZUH_RULES_API_PASSWORD,
                   settings.WAZUH_API_CA)

    def reload(self) -> None:
        """PUT /manager/analysisd/reload. Lỗi nếu error != 0, có failed_items, hoặc msg khác lời báo thành công."""
        try:
            res = self.request("PUT", "/manager/analysisd/reload")
        except WazuhError as e:
            raise WazuhRuleError(f"gọi Wazuh API lỗi: {e}") from e
        data = res.get("data") or {}
        problems = [str((f.get("error") or {}).get("message") or f) for f in data.get("failed_items") or []]
        problems += [str(i.get("msg")) for i in data.get("affected_items") or [] if i.get("msg") != RELOAD_OK]
        if res.get("error") or problems:
            raise WazuhRuleError("Wazuh không nạp được ruleset: " + ("; ".join(problems) or str(res.get("message"))))

    def logtest(self, event: str, log_format: str, location: str, token: str | None = None) -> dict:
        body = {"event": event, "log_format": log_format, "location": location}
        if token:
            body["token"] = token
        return self.request("PUT", "/logtest", body).get("data", {})

    def rules(self, offset: int = 0, limit: int = 500) -> dict:
        return self.request("GET", f"/rules?offset={offset}&limit={limit}")


def _replace(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + ".tmp")     # đuôi .tmp: Wazuh nạp mọi *.xml trong rule_dir
    tmp.write_text(text, encoding="utf-8")
    os.chmod(tmp, 0o644)                          # user wazuh (khác uid) phải đọc được
    os.replace(tmp, path)


def write_dynamic(name: str, xml_text: str, api, root: Path = DYNAMIC_DIR) -> None:
    """Kiểm tra -> ghi file tạm -> đổi tên nguyên tử -> api.reload(). Lỗi thì khôi phục file cũ, nạp lại, raise."""
    rng = ID_RANGES.get(f"rules-dynamic/{name}")
    if rng is None:
        raise WazuhRuleError(f"không phải file rule động: {name}")
    for r in parse(xml_text):
        if not rng[0] <= r["id"] <= rng[1]:
            raise WazuhRuleError(f"rule {r['id']} ngoài dải {rng[0]}-{rng[1]} của {name}")
    path = root / name
    old = path.read_text(encoding="utf-8") if path.exists() else None
    _replace(path, xml_text)
    try:
        api.reload()
    except WazuhRuleError as e:
        if old is None:
            path.unlink(missing_ok=True)
        else:
            _replace(path, old)
        try:
            api.reload()
        except WazuhRuleError as e2:
            log.error("nạp lại sau khi khôi phục %s cũng lỗi: %s", name, e2)
        raise e
