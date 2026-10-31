"""Lint rule XML của repo (wazuh/manager/rules/*.xml) so với ca test (wazuh/manager/tests/cases).

    python tools/wazuh_rule_lint.py

Mỗi dòng: `file:rule_id: thông điệp`; cảnh báo có tiền tố `WARNING: `. Thoát mã 1 khi có LỖI, cảnh báo thì mã 0.
"""
from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from siem.detection.rules import regex_risk  # noqa: E402
from siem.wazuh_rules import ID_RANGES, TUNING_FILE, WazuhRuleError, parse  # noqa: E402
from wazuh_rule_test import CASES_DIR, load_cases  # noqa: E402

RULES_DIR = ROOT / "wazuh/manager/rules"
CODE = re.compile(r"^[A-Z]{2,4}-\d{3}\b")
# Phần tử chứa mẫu regex/chuỗi khớp. srcip/dstip là so khớp IP, không kiểm.
PATTERN_TAGS = ("regex", "match", "field", "url", "id", "status", "data", "extra_data", "program_name", "hostname",
                "user", "action", "system_name")
NON_CONDITION = {"if_sid", "if_group", "description", "group", "mitre", "info"}
BARE_WORD = re.compile(r"[\w.-]+")


def _raw(text: str) -> dict[int, ET.Element]:
    root = ET.fromstring(f"<root>{text}</root>")
    return {int(r.get("id")): r for r in root.iter("rule")}


def check(files: dict[str, str], cases: list[dict]) -> list[str]:
    """Trả về mỗi dòng một vấn đề; cảnh báo bắt đầu bằng `WARNING: `, còn lại là lỗi."""
    out: list[str] = []
    pos = {c["rule"] for c in cases if "rule" in c}
    neg = {i for c in cases for i in (c.get("none") or [])}
    seen: dict[int, str] = {}
    for name, text in sorted(files.items()):
        tuning = name == TUNING_FILE
        rng = ID_RANGES.get(name)

        def err(rid, msg, warn=False, name=name):
            out.append(f"{'WARNING: ' if warn else ''}{name}:{rid}: {msg}")

        if rng is None and not tuning:
            err("-", "file không có trong ID_RANGES (wazuh_rules.py)")
        try:
            rules, raw = parse(text), _raw(text)
        except (WazuhRuleError, ET.ParseError) as e:
            err("-", f"không đọc được: {e}")
            continue
        for r in rules:
            rid, el = r["id"], raw[r["id"]]
            if rid in seen:
                err(rid, f"id trùng với {seen[rid]}")
            seen[rid] = name
            if tuning:
                if not r["overwrite"] or rid >= 100000:
                    err(rid, 'file tuning chỉ chứa rule overwrite="yes" trên id < 100000')
            else:
                if r["overwrite"]:
                    err(rid, 'overwrite="yes" chỉ được dùng trong ' + TUNING_FILE)
                if rid < 100000:
                    err(rid, "id < 100000 là dải của Wazuh gốc")
                elif rng and not rng[0] <= rid <= rng[1]:
                    err(rid, f"id ngoài dải {rng[0]}-{rng[1]} của file")
                if not CODE.match(r["description"]):
                    err(rid, "description thiếu mã ở đầu (vd WEB-010 )")
                if not r["mitre"]:
                    err(rid, "thiếu <mitre>")
                if rid not in pos:
                    err(rid, "thiếu ca test dương (rule: id)")
                if rid not in neg:
                    err(rid, "thiếu ca test âm (none: [id])")
            if "siem" not in r["groups"]:
                err(rid, "thiếu nhóm siem")
            if r["level"] == 0 and all(c.tag in NON_CONDITION for c in el):
                err(rid, "rule level 0 không có điều kiện nào ngoài if_sid/if_group (nuốt cả họ rule)")
            # regex_risk là heuristic của Python re; PCRE2/OS_Regex của Wazuh khác nên bỏ qua lỗi "không hợp lệ".
            for c in el:
                if c.tag in PATTERN_TAGS and c.text:
                    why = regex_risk(c.text.strip())
                    if why and "không hợp lệ" not in why:
                        err(rid, f"<{c.tag}>: {why}")
                if c.tag == "field" and c.text:
                    v = c.text.strip()
                    if BARE_WORD.fullmatch(v):
                        err(rid, f'<field name="{c.get("name")}"> là một từ trần, khớp chuỗi con; thêm ^ hoặc $', True)
            if el.get("frequency") and el.find("if_matched_group") is not None:
                err(rid, "frequency + if_matched_group chưa được tái hiện ở spike S4; phải có ca dương đạt", True)
    return out


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")      # console Windows cp1252
    files = {f.name: f.read_text(encoding="utf-8") for f in sorted(RULES_DIR.glob("*.xml"))}
    problems = check(files, load_cases(CASES_DIR))
    for p in problems:
        print(p)
    errors = [p for p in problems if not p.startswith("WARNING: ")]
    print(f"{len(files)} file, {len(errors)} lỗi, {len(problems) - len(errors)} cảnh báo")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
