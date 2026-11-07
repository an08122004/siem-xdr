"""Nhập rule SigmaHQ vào ruleset Wazuh theo lô, ở chế độ chạy bóng (RULES.md mục 7, Task 24).

    python tools/sigmahq_import.py            # chỉ đo: ứng viên, lô chọn được (cần Docker để biết mẫu nào Wazuh đã bắt)
    python tools/sigmahq_import.py --write    # ghi wazuh/manager/rules/0966-sigmahq.xml + ca test 0966-sigmahq.yml
    python tools/sigmahq_import.py --measure  # chạy ruleset của nhánh trên mẫu tấn công, đếm mẫu MỚI chỉ rule SigmaHQ (108xxx) bắt được

Rule được xét: SigmaHQ `process_creation` Windows và `webserver`, status stable / test, level từ medium. Linux hoãn (R68:
rule Linux nhắm decoder siem-proc, còn wazuh_coverage dựng mẫu Linux dạng auditd). Rule được nhận khi: biên dịch được
mà không rớt trường log không ghi, dịch được sang Wazuh XML thành ĐÚNG MỘT rule (một vế, nên một id / một mã SHQ),
kỹ thuật ATT&CK có case playbook riêng, không khớp mẫu bình thường nào. Lô được chọn tham lam theo số mẫu tấn công MỚI
bắt được: cây Python khớp mẫu chưa có Hit Wazuh `level >= 7` (không tính rule GENERIC). Wazuh là cổng quyết định (R66):
ca CI `0966-sigmahq.yml` chạy qua Wazuh thật. Mỗi rule một ca dương (mẫu tấn công) và một ca âm (lệnh bình thường gần nhất).

Cần dataset đã chuyển đổi (tools/fetch_datasets.py, tools/convert_datasets.py) và datasets/raw/sigma_all_rules.zip.
"""
from __future__ import annotations

import argparse
import ast
import gzip
import json
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from siem.ai import sigma  # noqa: E402
from siem.ai.wazuh_events import GENERIC, apache_event, sysmon_event  # noqa: E402
from siem.ai.wazuh_xml import LEVEL, emit  # noqa: E402
from siem.detection.rules import Condition, regex_risk  # noqa: E402
from siem.pipeline.normalize import get  # noqa: E402
from siem.soar.cases import CasePlaybooks  # noqa: E402

PREFIX, BASE_ID = "SHQ", 108000
# Tên file xếp SAU 0595-win-sysmon_rules.xml (cha 61603) và 0271-web.xml: Wazuh nạp theo tên, cha nạp sau thì rule bị bỏ (7617/7619).
# Dải id vẫn 108000-108999 (ID_RANGES); số 0108 trong kế hoạch ban đầu không dùng được vì lý do nạp này.
RULES_FILE = ROOT / "wazuh/manager/rules/0966-sigmahq.xml"
CASES_FILE = ROOT / "wazuh/manager/tests/cases/0966-sigmahq.yml"
LEVELS = ("medium", "high", "critical")
WEB_LOCATION = "(demo-web) any->/usr/local/apache2/logs/access_log"      # như 0271-web.yml (rule web chỉ nhận vị trí dạng agent)
MIN_LEVEL = 7
BATCH_EVENTS = 4000          # số event mỗi lần bơm: bơm cả chục nghìn một lượt từng làm analysisd bỏ event
_TOKEN = re.compile(r"[a-z0-9_.\-]+")
_SIGMA_ID = re.compile(r"sigmahq_id=([^\s<]+)")
HEADER = """<!--
  Rule nhập từ SigmaHQ (https://github.com/SigmaHQ/sigma) bằng tools/sigmahq_import.py, theo giấy phép Detection Rule
  License (DRL 1.1) (https://github.com/SigmaHQ/Detection-Rule-License): giữ id gốc (sigmahq_id) và tác giả (author) trong
  mỗi rule. Dải ID 108000-108999, mã SHQ-NNN. Rule chạy bóng (nhóm shadow + shadow_since); bật chính thức = bỏ đúng hai thứ
  đó (unshadow) khi đạt tiêu chí. KHÔNG sửa tay: nhập lại bằng tool. Ca test: tests/cases/0966-sigmahq.yml.
-->
"""


@dataclass
class Candidate:
    row: dict[str, Any]
    domain: str                  # windows | web
    tree: dict[str, Any]
    techniques: list[str]
    hits: set[int] = field(default_factory=set)      # chỉ số mẫu tấn công chưa Hit Wazuh mà cây Python khớp
    pos: dict[str, Any] | None = None                # mẫu dương / âm của ca test (item của wazuh_coverage.load_items)
    neg: dict[str, Any] | None = None

    @property
    def title(self) -> str:
        return str(self.row.get("title") or "")

    @property
    def sigma_id(self) -> str:
        return str(self.row.get("id") or "")


def _domain(ls: dict[str, Any]) -> str | None:
    if ls.get("category") == "process_creation" and ls.get("product") == "windows":
        return "windows"
    return "web" if ls.get("category") == "webserver" and not ls.get("product") else None


def candidates(items: list[dict], rows: list[dict], originals: dict[str, str], config_dir: Path
               ) -> tuple[list[Candidate], Counter]:
    """Rule SigmaHQ nhập được, và số rule bị loại theo lý do."""
    playbooks = CasePlaybooks(config_dir / "case_playbooks.yml")
    normal = {d: [it["doc"] for it in items if it["class"] == "normal" and it["domain"] == d] for d in ("windows", "web")}
    out: list[Candidate] = []
    skipped: Counter = Counter()
    for row in rows:
        ls = row.get("logsource")
        ls = ast.literal_eval(ls) if isinstance(ls, str) else ls or {}
        dom = _domain(ls)
        if not dom or row.get("status") not in ("stable", "test") or row.get("level") not in LEVELS:
            continue
        text = originals.get(str(row.get("path")))
        if text is None:
            skipped["không có rule gốc trong file zip"] += 1
            continue
        try:
            orig = yaml.safe_load(text)
            tree, notes = sigma.compile_rule(orig, dom)
        except Exception:  # noqa: BLE001 - rule ngoài tập con Sigma hỗ trợ: bỏ, chỉ đếm
            skipped["không biên dịch được"] += 1
            continue
        if notes:       # có trường log không ghi: nhánh/bộ lọc dùng nó bị rớt, rule thành rộng hơn bản gốc
            skipped["dùng trường log không ghi"] += 1
            continue
        techs, _ = sigma.attack_tags(orig.get("tags"))
        pb, _ = playbooks.select(f"{PREFIX}-000", techs, [])
        if not techs or not pb or pb.get("id") == "PB-00":
            skipped["kỹ thuật chưa có case playbook riêng"] += 1
            continue
        try:
            em = emit(tree, domain=dom, first_id=BASE_ID, level=LEVEL[row["level"]], code=f"{PREFIX}-000", title=row["title"],
                      techniques=techs, groups=["siem", "sigmahq"], shadow_since="2000-01-01")
        except sigma.SigmaError:
            skipped["không dịch được sang Wazuh"] += 1
            continue
        if len(em.ids) != 1:
            skipped["nhiều vế (nhiều id)"] += 1
            continue
        if any(regex_risk(e.text or "") for e in ET.fromstring("<g>" + em.xml + "</g>").iter() if e.get("type") == "pcre2"):
            skipped["mẫu regex quá dài / ReDoS (lint)"] += 1
            continue
        if dom == "windows" and re.search(r"\\x(?:3c|3e|26)", em.xml):
            # Wazuh giữ nguyên thực thể XML (&gt; &lt; &amp;) trong win.eventdata.*, còn emit viết `>` `<` `&` thành > < &
            # (đo 07/11/2026: mẫu có `>` không khớp): rule không bắn được trên event thật cho tới khi emit xử lý thực thể
            skipped["giá trị có & < > (Wazuh giữ thực thể XML)"] += 1
            continue
        cond = Condition(tree)
        if any(cond.match(d) for d in normal[dom]):
            skipped["báo nhầm trên tập bình thường"] += 1
            continue
        out.append(Candidate(row, dom, tree, techs))
    return out, skipped


def _tokens(item: dict) -> set[str]:
    text = item.get("line") or get(item["doc"], "process.command_line") or get(item["doc"], "process.name") or ""
    return set(_TOKEN.findall(str(text).lower()))


def pick(cands: list[Candidate], items: list[dict], covered: set[int], batch: int) -> list[Candidate]:
    """Tham lam: mỗi bước lấy rule bắt thêm nhiều mẫu tấn công chưa Hit nhất. Ghi `hits`, mẫu dương / âm cho rule được chọn."""
    todo = [it for it in items if it["class"] == "attack" and it["domain"] in ("windows", "web") and it["i"] not in covered]
    for c in cands:
        cond = Condition(c.tree)
        c.hits = {it["i"] for it in todo if it["domain"] == c.domain and cond.match(it["doc"])}
    picked: list[Candidate] = []
    got: set[int] = set()
    pool = [c for c in cands if c.hits]
    while pool and len(picked) < batch:
        best = max(pool, key=lambda c: len(c.hits - got))
        if not best.hits - got:
            break
        picked.append(best)
        got |= best.hits
        pool.remove(best)
    by_i = {it["i"]: it for it in items}
    conds = [Condition(c.tree) for c in picked]
    kept: list[Candidate] = []
    for k, c in enumerate(picked):
        # Wazuh chọn rule anh em level cao nhất, cùng level thì rule nạp trước (id nhỏ): mẫu dương không được bị rule
        # SigmaHQ khác của lô che, nếu không ca dương báo nhầm id rule kia
        beat = [conds[m] for m, d in enumerate(picked) if m != k and (LEVEL[d.row["level"]], -m) > (LEVEL[c.row["level"]], -k)
                and d.domain == c.domain]
        own = [i for i in sorted(c.hits) if not any(b.match(by_i[i]["doc"]) for b in beat)]
        if not own:
            print(f"bỏ {c.title}: mọi mẫu của rule đều bị rule khác của lô che", file=sys.stderr)
            continue
        c.pos = by_i[own[0]]
        t = _tokens(c.pos)
        normals = [it for it in items if it["class"] == "normal" and it["domain"] == c.domain]
        c.neg = max(normals, key=lambda n: len(t & _tokens(n)) / (len(t | _tokens(n)) or 1))
        kept.append(c)
    picked = kept
    return picked


# ---------------------------------------------------------------- ghi XML + ca test
def _case_event(item: dict) -> tuple[str, str, str]:
    """(log_format, location, một dòng event) của ca test, đúng định dạng tools/wazuh_rule_test.py."""
    if item["domain"] == "web":
        return "apache", WEB_LOCATION, item["line"]
    d = item["doc"]
    parent = str(get(d, "process.parent.executable") or get(d, "process.parent.name") or "")
    msg = sysmon_event(1, str(get(d, "process.executable") or get(d, "process.name") or ""),
                       str(get(d, "process.command_line") or ""), parent,
                       str(get(d, "process.parent.command_line") or parent), str(get(d, "user.name") or "")).msg
    return "eventchannel", "EventChannel", msg.removeprefix("f:EventChannel:")


def _case(key: str, rid: int, item: dict) -> dict[str, Any]:
    fmt, loc, event = _case_event(item)
    return {key: rid if key == "rule" else [rid], "log_format": fmt, "location": loc, "events": [event]}


def write_batch(picked: list[Candidate], *, rules_file: Path, cases_file: Path, first_id: int = BASE_ID,
                today: str) -> list[int]:
    """Thêm rule của `picked` vào rules_file (+ ca test vào cases_file); rule đã có (sigmahq_id) thì bỏ, id đánh tiếp. Trả id mới."""
    old = rules_file.read_text(encoding="utf-8") if rules_file.exists() else ""
    have = set(_SIGMA_ID.findall(old))
    body = old[old.index("<group"):old.rindex("</group>")].split("\n", 1)[1] if old else ""
    nid = max([int(x) for x in re.findall(r'<rule id="(\d+)"', old)] + [first_id - 1]) + 1
    cases = (yaml.safe_load(cases_file.read_text(encoding="utf-8")) or []) if cases_file.exists() else []
    new: list[int] = []
    for c in picked:
        if c.sigma_id in have:
            continue
        em = emit(c.tree, domain=c.domain, first_id=nid, level=LEVEL[c.row["level"]], code=f"{PREFIX}-{nid - first_id + 1:03d}",
                  title=c.title, techniques=c.techniques, groups=["siem", "sigmahq"], shadow_since=today,
                  info={"sigmahq_id": c.sigma_id, "author": str(c.row.get("author") or "")})
        body += em.xml
        cases += [_case("rule", nid, c.pos), _case("none", nid, c.neg)]
        new.append(nid)
        nid += 1
    rules_file.parent.mkdir(parents=True, exist_ok=True)
    rules_file.write_text(HEADER + '<group name="siem,sigmahq,">\n' + body + "</group>\n", encoding="utf-8", newline="\n")
    cases_file.parent.mkdir(parents=True, exist_ok=True)
    cases_file.write_text("# Ca test cho wazuh/manager/rules/0966-sigmahq.xml, sinh bởi tools/sigmahq_import.py: mỗi rule một ca\n"
                          "# dương (mẫu tấn công dataset công khai) và một ca âm (lệnh bình thường gần giống nhất).\n"
                          + yaml.safe_dump(cases, allow_unicode=True, sort_keys=False, width=10 ** 9), encoding="utf-8",
                          newline="\n")
    return new


# ---------------------------------------------------------------- đo trên Wazuh
def wazuh_hits(items: list[dict]) -> tuple[set[int], set[int]]:
    """Bơm mẫu tấn công vào manager tạm (ruleset của nhánh). Trả (mẫu có Hit rule ngoài dải 108xxx, mẫu có Hit rule 108xxx),
    Hit = level >= 7 và không thuộc GENERIC."""
    import wazuh_coverage as cov
    import wazuh_noise as noise
    atk = [it for it in items if it["class"] == "attack" and it["domain"] in ("windows", "web")]
    saved, cov.CONTAINER = cov.CONTAINER, noise.NAME
    alerts: list[dict] = []
    try:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                noise.start(Path(tmp))
                for k in range(0, len(atk), BATCH_EVENTS):
                    part = atk[k:k + BATCH_EVENTS]
                    alerts += cov.run_wazuh(part)
                    if cov.LAST_SENT != len(part):
                        raise SystemExit(f"bơm hỏng: gửi {cov.LAST_SENT}/{len(part)} event")
            finally:
                subprocess.run(["docker", "rm", "-f", noise.NAME], env=cov.ENV, capture_output=True)
    finally:
        cov.CONTAINER = saved
    real = [a for a in alerts if int(a["rule"]["level"]) >= MIN_LEVEL and str(a["rule"]["id"]) not in GENERIC]
    mine = [a for a in real if BASE_ID <= int(a["rule"]["id"]) < BASE_ID + 1000]
    other = [a for a in real if a not in mine]
    return set(cov.match_alerts(atk, other)), set(cov.match_alerts(atk, mine))


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--datasets", type=Path, default=ROOT / "datasets" / "processed")
    ap.add_argument("--zip", type=Path, default=ROOT / "datasets" / "raw" / "sigma_all_rules.zip")
    ap.add_argument("--config", type=Path, default=ROOT / "server" / "config")
    ap.add_argument("--batch", type=int, default=30, help="số rule tối đa của lô (RULES.md mục 7: 20-30)")
    ap.add_argument("--write", action="store_true", help="ghi lô vào 0966-sigmahq.xml (mặc định chỉ đo)")
    ap.add_argument("--measure", action="store_true", help="chạy ruleset hiện có trên mẫu tấn công, đếm mẫu mới chỉ rule SigmaHQ bắt")
    a = ap.parse_args()
    if not a.zip.exists() or not a.datasets.exists():
        print(f"thiếu {a.zip if not a.zip.exists() else a.datasets}: chạy tools/fetch_datasets.py, tools/convert_datasets.py")
        return 2
    import wazuh_coverage as cov
    cov.DATA = a.datasets
    items = [it for it in cov.load_items(extra_normal=True) if it["domain"] in ("windows", "web")]
    if a.measure:
        stock, mine = wazuh_hits(items)
        atk = sum(it["class"] == "attack" for it in items)
        print(f"mẫu tấn công {atk}; ngoài SigmaHQ có Hit {len(stock)}; SigmaHQ có Hit {len(mine)}; MỚI chỉ SigmaHQ bắt {len(mine - stock)}")
        return 0
    with zipfile.ZipFile(a.zip) as z:
        originals = {n: z.read(n).decode("utf-8") for n in z.namelist() if n.endswith(".yml")}
    with gzip.open(a.datasets / "sigma_rules.jsonl.gz", "rt", encoding="utf-8") as f:
        rows = [json.loads(line) for line in f if line.strip()]
    done = set(_SIGMA_ID.findall(RULES_FILE.read_text(encoding="utf-8"))) if RULES_FILE.exists() else set()
    rows = [r for r in rows if str(r.get("id")) not in done]
    cands, skipped = candidates(items, rows, originals, a.config)
    stock, _ = wazuh_hits(items)
    picked = pick(cands, items, stock, a.batch)
    print(f"Ứng viên: {len(cands)} ({sum(1 for c in cands if c.hits)} bắt thêm được mẫu); đã nhập trước đó: {len(done)}; "
          "bị loại: " + ", ".join(f"{k} {v}" for k, v in skipped.most_common()))
    print(f"Lô này: {len(picked)} rule\n\n| # | Rule SigmaHQ | Mức | Kỹ thuật | Mẫu mới bắt thêm (cây Python) |\n|---|---|---|---|---|")
    got: set[int] = set()
    for i, c in enumerate(picked, 1):
        print(f"| {i} | {c.title} | {c.row.get('level')} | {', '.join(c.techniques[:3])} | {len(c.hits - got)} |")
        got |= c.hits
    print(f"\nTổng mẫu tấn công chưa Hit mà lô khớp (Python): {len(got)}")
    if a.write and picked:
        ids = write_batch(picked, rules_file=RULES_FILE, cases_file=CASES_FILE, today=date.today().isoformat())
        print(f"đã ghi {len(ids)} rule vào {RULES_FILE} và ca test vào {CASES_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
