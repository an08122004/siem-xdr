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
from siem.wazuh_rules import ID_RANGES, TUNING_FILE  # noqa: E402
from wazuh_rule_test import CASES_DIR, load_cases  # noqa: E402

RULES_DIR = ROOT / "wazuh/manager/rules"
CODE = re.compile(r"^[A-Z]{2,4}-\d{3}\b")
# Phần tử chứa mẫu regex/chuỗi khớp. srcip/dstip là so khớp IP, không kiểm.
PATTERN_TAGS = ("regex", "match", "field", "url", "id", "status", "data", "extra_data", "program_name", "hostname",
                "user", "action", "system_name")
NON_CONDITION = {"if_sid", "if_group", "description", "group", "mitre", "info", "options"}
BARE_WORD = re.compile(r"[\w.-]+")


def _split(text):
    return [x.strip() for x in (text or "").split(",") if x.strip()]


def check(files: dict[str, str], cases: list[dict]) -> list[str]:
    """Trả về mỗi dòng một vấn đề; cảnh báo bắt đầu bằng `WARNING: `, còn lại là lỗi. Không bao giờ ném ngoại lệ vì rule hỏng."""
    out: list[str] = []
    pos = {c["rule"] for c in cases if "rule" in c}
    neg = {i for c in cases for i in (c.get("none") or [])}
    seen: dict[int, str] = {}
    for name, text in sorted(files.items()):
        tuning = name == TUNING_FILE
        dynamic = name.startswith("rules-dynamic/")      # console sinh lúc chạy: không đòi ca test
        rng = ID_RANGES.get(name)

        def err(rid, msg, warn=False, name=name):
            out.append(f"{'WARNING: ' if warn else ''}{name}:{rid}: {msg}")

        if rng is None and not tuning:
            err("-", "file không có trong ID_RANGES (wazuh_rules.py)")
        try:
            root = ET.fromstring(f"<root>{text}</root>")
        except ET.ParseError as e:
            err("-", f"XML sai cú pháp: {e}")
            continue
        # Đọc XML phản chiếu wazuh_rules.parse (nhóm hiệu lực, overwrite, level), không gọi nó vì cần phần tử thô và không được ném lỗi.
        parent = {c: p for p in root.iter() for c in p}
        for el in root.iter("rule"):
            outer, p = [], parent.get(el)
            while p is not None:
                if p.tag == "group":
                    outer += _split(p.get("name"))
                p = parent.get(p)
            groups = outer + [g for e in el.findall("group") for g in _split(e.text)]
            try:
                rid = int(el.get("id", ""))
            except ValueError:
                rid = None
                err("?", f"id thiếu hoặc không hợp lệ: {el.get('id')!r}")
            try:
                level = int(el.get("level", ""))
            except ValueError:
                level = None
                err(rid or "?", f"level thiếu hoặc không hợp lệ: {el.get('level')!r}")
            lab = rid if rid is not None else "?"
            if parent.get(el) is None or parent[el].tag != "group":
                err(lab, "rule nằm ngoài <group> (Wazuh từ chối file)")
            desc = (el.findtext("description") or "").strip()
            overwrite = el.get("overwrite") == "yes"
            if rid is not None:
                if rid in seen:
                    err(rid, f"id trùng với {seen[rid]}")
                seen[rid] = name
                if tuning:
                    if not overwrite or rid >= 100000:
                        err(rid, 'file tuning chỉ chứa rule overwrite="yes" trên id < 100000')
                else:
                    if rid < 100000:
                        err(rid, "id < 100000 là dải của Wazuh gốc")
                    elif rng and not rng[0] <= rid <= rng[1]:
                        err(rid, f"id ngoài dải {rng[0]}-{rng[1]} của file")
                    if not (dynamic or tuning):
                        if rid not in pos:
                            err(rid, "thiếu ca test dương (rule: id)")
                        if rid not in neg:
                            err(rid, "thiếu ca test âm (none: [id])")
            if overwrite and not tuning:
                err(lab, 'overwrite="yes" chỉ được dùng trong ' + TUNING_FILE)
            if not tuning:
                if not CODE.match(desc):
                    err(lab, "description thiếu mã ở đầu (vd WEB-010 )")
                if not any((i.text or "").strip() for i in el.findall("mitre/id")):
                    err(lab, "thiếu <mitre>")
                if "siem" not in groups:       # rule gốc bị ghi đè (tuning) không phải "rule riêng"
                    err(lab, "thiếu nhóm siem")
            if level == 0 and all(c.tag in NON_CONDITION for c in el):
                err(lab, "rule level 0 không có điều kiện nào ngoài if_sid/if_group (nuốt cả họ rule)")
            # regex_risk là heuristic của Python re; PCRE2/OS_Regex của Wazuh khác nên bỏ qua lỗi "không hợp lệ".
            for c in el:
                if c.tag in ("regex", "field") and not tuning and c.get("type") != "pcre2":
                    err(lab, f'<{c.tag}> phải có type="pcre2" (mặc định là OS_Regex)')
                if c.tag in PATTERN_TAGS and c.text:
                    why = regex_risk(c.text.strip())
                    if why and "không hợp lệ" not in why:
                        err(lab, f"<{c.tag}>: {why}")
                if c.tag == "field" and c.text and BARE_WORD.fullmatch(c.text.strip()):
                    err(lab, f'<field name="{c.get("name")}"> là một từ trần, khớp chuỗi con; thêm ^ hoặc $', True)
            if el.get("frequency") and el.find("if_matched_group") is not None:
                err(lab, "frequency + if_matched_group chưa được tái hiện ở spike S4; phải có ca dương đạt", True)
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
