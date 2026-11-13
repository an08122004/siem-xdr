"""Kiểm: mọi alert THẬT của rule gốc Wazuh nằm dưới rule cha mà rule dự án móc vào đều tới được: có ca `rule: <id>` ghim, hoặc có bảo đảm cấu trúc.

    python tools/wazuh_stock_reach.py <thư mục (hoặc file) rule gốc> [--rules wazuh/manager/rules] [--cases wazuh/manager/tests/cases]
    CI: docker cp wazuh-rules-ci:/var/ossec/ruleset/rules stock-rules && python tools/wazuh_stock_reach.py stock-rules

Vì sao: rule anh em thắng nhau theo level, rule thắng cắt cả cây con của rule còn lại; rule dự án móc dưới cha gốc có thể lặng lẽ
chặn một rule gốc con đang là alert thật. Alert thật = level >= 12, hoặc >= 7 trong nhóm syscheck / rootcheck / vulnerability-detector / virustotal / yara.
Cây gồm if_sid / if_matched_sid VÀ if_group (if_matched_group KHÔNG phải cạnh cây: chỉ là tra cứu tương quan event cũ, vị trí trong cây do if_sid / if_group quyết định; rule gốc 40501 chỉ có if_matched_group + if_group adduser) (rule có if_group g là con của MỌI rule mang nhóm g: nhóm trong thẻ <group> của rule hoặc thẻ <group name> bao ngoài).
Rule gốc bị overwrite lấy bản dự án (vẫn giữ file gốc). Với mỗi alert thật dưới cha bị móc, chấp nhận MỘT trong hai:
  (a) ca `rule: <id>` ghim; hoặc
  (b) bảo đảm cấu trúc: mọi rule dự án móc cùng cha thua rule gốc con trực tiếp của cha đó trên đường tới nó: level thấp hơn, hoặc bằng level và file rule gốc xếp TRƯỚC file rule dự án (theo tên;
      chặt hơn lệnh R63 "<=" ở chỗ cho level thấp hơn qua dù file xếp sau, vì level cao thắng bất kể thứ tự nạp: đã đo ở RULES.md 9.6).
Kiểm thêm: mọi id cha gốc mà rule dự án nêu trong if_sid phải có trong rule gốc, và file của nó xếp trước file rule dự án (Wazuh bỏ rule có cha chưa nạp).
Thoát mã 1 khi còn rule không có (a) lẫn (b), hoặc cha gốc sai.
shortcut: (b) so với con trực tiếp của cha bị móc (không xét thứ tự nạp thật giữa thư mục ruleset và etc/rules, chỉ so tên file); nâng cấp khi có rule gốc cùng tên file.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
REAL_GROUPS = {"syscheck", "rootcheck", "vulnerability-detector", "virustotal", "yara"}
TOKEN = re.compile(r"(<rule\b([^>]*)>(.*?)</rule>)|<group\s+name=\"([^\"]*)\"[^>]*>|(</group>)", re.S)


# Rule gốc tương quan (if_matched_group) mà harness không tái hiện được (RULES.md 9.6 S4) nên không ghim được; chỉ liệt kê tường minh, id mới vẫn bị bắt.
# 40112: thành công sau chuỗi thất bại, hòa level 12 với 101002 (AUTH-002, nạp trước, cùng ý nghĩa). 40501: thêm user sau 4 "attacks", con của rule nhóm adduser (60109...) dưới 60103.
UNPINNABLE = {40112: "tương quan if_matched_group, trùng ý nghĩa với 101002", 40501: "tương quan frequency + if_matched_group, không tái hiện được"}


def _ids(body: str, *tags: str) -> set[str]:
    return {p for tag in tags for m in re.findall(rf"<{tag}>([^<]*)</{tag}>", body) for p in re.split(r"[,\s]+", m.strip()) if p}


def parse(text: str, file: str = "") -> dict[int, dict]:
    """{id: {level, parents, if_groups, groups, file}} từ nội dung XML (không cần XML hợp lệ: file gốc có nhiều thẻ <group> gốc).
    groups = nhóm trong rule + nhóm của mọi thẻ <group name> bao ngoài; parents = if_sid / if_matched_sid; if_groups = if_group."""
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    out, outer = {}, []
    for m in TOKEN.finditer(text):
        if m.group(5):
            outer and outer.pop()
        elif m.group(4) is not None:
            outer.append({g.strip() for g in m.group(4).split(",") if g.strip()})
        else:
            attrs, body = m.group(2), m.group(3)
            rid, lvl = re.search(r'\bid="(\d+)"', attrs), re.search(r'\blevel="(\d+)"', attrs)
            if not (rid and lvl):
                continue
            inner = {g.strip() for x in re.findall(r"<group>([^<]*)</group>", body) for g in x.split(",") if g.strip()}
            out[int(rid.group(1))] = {
                "level": int(lvl.group(1)), "file": file, "groups": inner.union(*outer),
                "parents": {int(p) for p in _ids(body, "if_sid", "if_matched_sid") if p.isdigit()},
                "if_groups": _ids(body, "if_group")}
    return out


def load(path: Path) -> dict[int, dict]:
    files = sorted(path.rglob("*.xml")) if path.is_dir() else [path]
    rules = {}
    for f in files:
        rules.update(parse(f.read_text(encoding="utf-8", errors="replace"), f.name))
    return rules


def is_real(r: dict, min_level: int = 12) -> bool:
    return r["level"] >= min_level or (r["level"] >= 7 and bool(r["groups"] & REAL_GROUPS))


def _parents(r: dict, carriers: dict[str, set[int]], known) -> set[tuple[int, bool]]:
    """{(id cha, qua nhóm?)} của một rule trong tập rule gốc `known`: if_sid + mọi rule mang nhóm trong if_group."""
    return ({(p, False) for p in r["parents"] if p in known}
            | {(p, True) for g in r["if_groups"] for p in carriers.get(g, ())})


def _beats_or_ties_first(s: dict, h: dict) -> bool:
    """Rule gốc `s` không thua rule dự án `h` cùng cha: level cao hơn, hoặc bằng level và nạp trước (file gốc xếp trước theo tên)."""
    return h["level"] < s["level"] or (h["level"] == s["level"] and s["file"] < h["file"])


def analyse(stock: dict, project: dict, pinned: set[int], min_level: int = 12) -> dict[int, dict]:
    """{id rule gốc alert thật dưới cha bị móc: {tops, group, pinned, guaranteed, why}}. Chỉ trả rule gốc KHÔNG thuộc project."""
    carriers: dict[str, set[int]] = {}
    for rid, r in stock.items():
        for g in r["groups"]:
            carriers.setdefault(g, set()).add(rid)
    children: dict[int, set[tuple[int, bool]]] = {}
    for rid, r in stock.items():
        for p, g in _parents(r, carriers, stock):
            if p != rid:
                children.setdefault(p, set()).add((rid, g))
    rivals: dict[int, list[int]] = {}           # cha gốc -> rule dự án móc vào nó
    for pid, r in project.items():
        for p, _ in _parents(r, carriers, stock):
            rivals.setdefault(p, []).append(pid)
    found: dict[int, dict] = {}
    for top, hooks in rivals.items():
        for c1, g1 in children.get(top, ()):
            todo, seen = [(c1, g1)], {c1}
            while todo:
                c, viag = todo.pop()
                if c not in project and is_real(stock[c], min_level):
                    f = found.setdefault(c, {"tops": set(), "group": False, "bad": []})
                    f["tops"].add(top)
                    f["group"] |= viag
                    for h in hooks:
                        if not _beats_or_ties_first(stock[c1], project[h]):
                            f["bad"].append(f"{h} (L{project[h]['level']}, {project[h]['file']}) vs {c1} (L{stock[c1]['level']}, {stock[c1]['file']}) dưới {top}")
                for n, g in children.get(c, ()):
                    if n not in seen:
                        seen.add(n)
                        todo.append((n, viag or g))
    for c, f in found.items():
        f["pinned"], f["guaranteed"] = c in pinned, not f["bad"]
    return found


def unpinned(stock: dict, project: dict, pinned: set[int], min_level: int = 12) -> dict[int, set[int]]:
    """{id alert thật không có (a) lẫn (b): các cha gốc bị móc}."""
    return {c: f["tops"] for c, f in analyse(stock, project, pinned, min_level).items() if not (f["pinned"] or f["guaranteed"])}


def parent_errors(stock: dict, project: dict) -> list[str]:
    """Cha gốc mà rule dự án nêu trong if_sid phải tồn tại và có file xếp trước file rule dự án (cha là rule dự án: lint kiểm)."""
    out = []
    for pid, r in sorted(project.items()):
        for p in sorted(r["parents"]):
            if p in project:
                continue
            if p not in stock:
                out.append(f"{pid}: cha {p} không có trong rule gốc (Wazuh bỏ rule có if_sid chưa tồn tại)")
            elif not stock[p]["file"] < r["file"]:
                out.append(f"{pid} ({r['file']}): cha gốc {p} nằm ở {stock[p]['file']}, không xếp trước file của rule (cha chưa nạp)")
    return out


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
    ap.add_argument("--min-level", type=int, default=12,
                    help="alert thật = level >= này (R65 / WAZUH_ALERT_MIN_LEVEL: 7; 12 = định nghĩa R38 cũ)")
    a = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")       # console Windows mặc định cp1252
    stock, project = load(a.stock), load(a.rules)
    gốc = set(stock)
    stock.update({i: {**r, "file": stock[i]["file"]} for i, r in project.items() if i in gốc})      # overwrite="yes": bản dự án thay bản gốc, vị trí nạp giữ nguyên
    project = {i: r for i, r in project.items() if i not in gốc}
    if not stock:
        print(f"không đọc được rule gốc ở {a.stock}", file=sys.stderr)
        return 2
    pinned = pinned_ids(a.cases)
    res = analyse(stock, project, pinned, a.min_level)
    errors = parent_errors(stock, project)
    for rid in sorted(res):
        f = res[rid]
        how = "+".join(k for k, v in (("ca ghim", f["pinned"]), ("bảo đảm cấu trúc", f["guaranteed"])) if v) or (
            f"CHẤP NHẬN CÓ GHI CHÚ ({UNPINNABLE[rid]})" if rid in UNPINNABLE else "KHÔNG CÓ")
        print(f"{rid}: level {stock[rid]['level']}, {'qua if_group, ' if f['group'] else ''}dưới cha bị móc {', '.join(map(str, sorted(f['tops'])))}: {how}")
        if how == "KHÔNG CÓ":
            errors.append(f"{rid}: không có ca `rule: {rid}` và không có bảo đảm cấu trúc ({'; '.join(f['bad'][:3])})")
    for e in errors:
        print("LỖI " + e)
    n = lambda pred: sum(1 for f in res.values() if pred(f))
    print(f"{len(res)} rule gốc alert thật dưới cha bị móc ({n(lambda f: f['group'])} qua if_group): "
          f"{n(lambda f: f['pinned'])} có ca ghim, {n(lambda f: f['guaranteed'] and not f['pinned'])} chỉ nhờ bảo đảm cấu trúc, "
          f"{len(UNPINNABLE.keys() & res.keys() - {c for c, f in res.items() if f['pinned'] or f['guaranteed']})} chấp nhận có ghi chú (không ghim được); {len(errors)} lỗi")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
