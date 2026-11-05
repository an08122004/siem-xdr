"""Kiểm: mọi alert THẬT của rule gốc Wazuh nằm dưới rule cha mà rule dự án móc vào đều có ca `rule: <id>` ghim.

    python tools/wazuh_stock_reach.py <thư mục (hoặc file) rule gốc> [--rules wazuh/manager/rules] [--cases wazuh/manager/tests/cases]
    CI: docker cp wazuh-rules-ci:/var/ossec/ruleset/rules stock-rules && python tools/wazuh_stock_reach.py stock-rules

Vì sao: rule anh em thắng nhau theo level, rule thắng cắt cả cây con của rule còn lại; rule dự án móc dưới cha gốc có thể lặng lẽ
chặn một rule gốc con đang là alert thật. Alert thật = level >= 12, hoặc >= 7 trong nhóm syscheck / rootcheck / vulnerability-detector / virustotal / yara.
shortcut: chỉ theo if_sid / if_matched_sid (không theo if_group / if_matched_group), rule gốc bị overwrite lấy bản dự án; đủ cho cây hiện tại, nâng cấp khi rule dự án móc bằng if_group.
Thoát mã 1 khi còn rule chưa ghim.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
REAL_GROUPS = {"syscheck", "rootcheck", "vulnerability-detector", "virustotal", "yara"}
RULE = re.compile(r"<rule\b([^>]*)>(.*?)</rule>", re.S)


def parse(text: str) -> dict[int, dict]:
    """{id: {level, parents, groups}} từ nội dung XML (không cần XML hợp lệ: file gốc có nhiều thẻ <group> gốc)."""
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    out = {}
    for attrs, body in RULE.findall(text):
        rid, lvl = re.search(r'\bid="(\d+)"', attrs), re.search(r'\blevel="(\d+)"', attrs)
        if not (rid and lvl):
            continue
        parents = {int(p) for tag in ("if_sid", "if_matched_sid") for m in re.findall(rf"<{tag}>([^<]*)</{tag}>", body)
                   for p in re.split(r"[,\s]+", m.strip()) if p}
        groups = {g.strip() for m in re.findall(r"<group>([^<]*)</group>", body) for g in m.split(",") if g.strip()}
        out[int(rid.group(1))] = {"level": int(lvl.group(1)), "parents": parents, "groups": groups}
    return out


def load(path: Path) -> dict[int, dict]:
    files = sorted(path.rglob("*.xml")) if path.is_dir() else [path]
    rules = {}
    for f in files:
        rules.update(parse(f.read_text(encoding="utf-8", errors="replace")))
    return rules


def is_real(r: dict) -> bool:
    return r["level"] >= 12 or (r["level"] >= 7 and bool(r["groups"] & REAL_GROUPS))


def unpinned(stock: dict, project: dict, pinned: set[int]) -> dict[int, set[int]]:
    """{id rule gốc alert thật chưa ghim: các rule cha gốc mà rule dự án móc vào ở trên nó}."""
    hooked = {p for r in project.values() for p in r["parents"]} & stock.keys()
    children: dict[int, set[int]] = {}
    for rid, r in stock.items():
        for p in r["parents"]:
            children.setdefault(p, set()).add(rid)
    found: dict[int, set[int]] = {}
    for top in hooked:
        todo, seen = [top], {top}
        while todo:
            for c in children.get(todo.pop(), ()):
                if c not in seen:
                    seen.add(c)
                    todo.append(c)
                    if c not in project and c not in pinned and is_real(stock[c]):
                        found.setdefault(c, set()).add(top)
    return found


def pinned_ids(cases_dir: Path) -> set[int]:
    ids = set()
    for f in sorted(cases_dir.glob("*.yml")):
        for c in yaml.safe_load(f.read_text(encoding="utf-8")) or []:
            r = c.get("rule")
            ids.update(int(x) for x in (r if isinstance(r, list) else [r]) if x is not None)
    return ids


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("stock", type=Path, help="thư mục (hoặc file) rule gốc, vd /var/ossec/ruleset/rules chép ra từ container")
    ap.add_argument("--rules", type=Path, default=ROOT / "wazuh/manager/rules")
    ap.add_argument("--cases", type=Path, default=ROOT / "wazuh/manager/tests/cases")
    a = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")       # console Windows mặc định cp1252
    stock, project = load(a.stock), load(a.rules)
    gốc = set(stock)
    stock.update({i: r for i, r in project.items() if i in gốc})      # overwrite="yes": bản dự án thay bản gốc
    project = {i: r for i, r in project.items() if i not in gốc}
    if not stock:
        print(f"không đọc được rule gốc ở {a.stock}", file=sys.stderr)
        return 2
    bad = unpinned(stock, project, pinned_ids(a.cases))
    for rid in sorted(bad):
        print(f"{rid}: level {stock[rid]['level']}, dưới cha gốc bị rule dự án móc ({', '.join(map(str, sorted(bad[rid])))}), chưa có ca `rule: {rid}`")
    print(f"{len(bad)} rule gốc alert thật chưa ghim")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
