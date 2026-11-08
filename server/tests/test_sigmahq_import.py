"""tools/sigmahq_import.py: chọn rule SigmaHQ và ghi 0966-sigmahq.xml + ca CI (RULES.md mục 7, Task 24) trên dataset giả lập nhỏ."""
from __future__ import annotations

import importlib.util
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
import yaml

from siem.pipeline.normalize import normalize

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
spec = importlib.util.spec_from_file_location("sigmahq_import", ROOT / "tools" / "sigmahq_import.py")
imp = importlib.util.module_from_spec(spec)
sys.modules["sigmahq_import"] = imp                     # @dataclass của tool tra module theo tên
spec.loader.exec_module(imp)

RUNDLL = r"C:\Windows\System32\rundll32.exe"
LINE = '198.51.100.7 - - [05/Jan/2026:09:00:00 +0000] "GET /a.php?x=../../etc/passwd HTTP/1.1" 200 5 "-" "curl/8"'
CONFIG = ROOT / "server" / "config"


def win(i: int, cmd: str, cls: str) -> dict:
    raw = {"timestamp": "2026-01-05T09:00:00+00:00", "agent_id": "dataset", "hostname": "h", "os": "windows",
           "source": "process", "event_type": "process_creation",
           "data": {"name": "rundll32.exe", "executable": RUNDLL, "command_line": cmd, "parent_name": "cmd.exe"}}
    return {"i": i, "domain": "windows", "class": cls, "doc": normalize(raw)}


def web(i: int, line: str, cls: str) -> dict:
    raw = {"timestamp": "2026-01-05T09:00:00+00:00", "agent_id": "dataset", "hostname": "h", "os": "linux",
           "source": "apache", "event_type": "web_access", "data": {"message": line}}
    return {"i": i, "domain": "web", "class": cls, "doc": normalize(raw), "line": line}


def sigma_rule(path: str, title: str, detection: str, tags: str, level: str = "high") -> tuple[dict, str]:
    text = (f"title: {title}\nid: {path}-id\nstatus: test\nauthor: Tester A\n"
            f"logsource:\n  category: process_creation\n  product: windows\ndetection:\n{detection}\n"
            f"falsepositives:\n  - Unknown\nlevel: {level}\ntags:\n{tags}\n")
    row = yaml.safe_load(text)
    row.update(path=path, detection=yaml.safe_dump(row["detection"]), logsource=str(row["logsource"]))
    return row, text


JS = "  sel:\n    Image|endswith: '\\rundll32.exe'\n    CommandLine|contains: 'javascript:'\n  condition: sel"
EVASION = "  - attack.defense-evasion\n  - attack.t1218.011"
ITEMS = [win(0, RUNDLL + ' javascript:"\\..\\mshtml,RunHTMLApplication ";alert(1)', "attack"),
         win(1, RUNDLL + ' javascript:"x"', "attack"),
         win(2, RUNDLL + " shell32.dll,Control_RunDLL desk.cpl", "normal")]


def test_candidates_skip_noisy_unmappable_and_playbookless_rules():
    rows = [
        sigma_rule("rules/a.yml", "Rundll32 JavaScript", JS, EVASION),
        sigma_rule("rules/b.yml", "Any Rundll32", "  sel:\n    Image|endswith: '\\rundll32.exe'\n  condition: sel", EVASION),
        sigma_rule("rules/c.yml", "Unsigned Rundll32", "  sel:\n    CommandLine|contains: 'javascript:'\n  filter:\n"
                   "    Signed: 'true'\n  condition: sel and not filter", EVASION),       # trường Signed log không ghi -> loại
        sigma_rule("rules/d.yml", "BITS Job", "  sel:\n    CommandLine|contains: 'javascript:'\n  condition: sel",
                   "  - attack.persistence\n  - attack.t1197"),                           # chưa có case playbook riêng
        sigma_rule("rules/e.yml", "Two branches", "  s1:\n    CommandLine|contains: 'javascript:'\n  s2:\n"
                   "    Image|endswith: '\\foo.exe'\n  condition: s1 or s2", EVASION),     # 2 vế -> 2 id -> loại
    ]
    cands, skipped = imp.candidates(ITEMS, [r for r, _ in rows], {r["path"]: t for r, t in rows}, CONFIG)
    assert [c.title for c in cands] == ["Rundll32 JavaScript"]
    assert skipped == {"báo nhầm trên tập bình thường": 1, "dùng trường log không ghi": 1,
                       "kỹ thuật chưa có case playbook riêng": 1, "nhiều vế (nhiều id)": 1}


def test_pick_counts_only_samples_wazuh_has_not_hit_yet():
    row, text = sigma_rule("rules/a.yml", "Rundll32 JavaScript", JS, EVASION)
    cands, _ = imp.candidates(ITEMS, [row], {row["path"]: text}, CONFIG)
    picked = imp.pick(cands, ITEMS, covered={0}, batch=30)
    assert picked[0].hits == {1} and picked[0].pos["i"] == 1 and picked[0].neg["i"] == 2
    assert imp.pick(cands, ITEMS, covered={0, 1}, batch=30) == []           # đã bắt hết: không nhập


@pytest.fixture
def three_sigma_rules():
    rows = [sigma_rule(f"rules/{n}.yml", f"Rundll32 rule {n}", JS.replace("javascript:", w), EVASION)
            for n, w in (("a", "javascript:"), ("b", "vbscript:"), ("c", "mshtml,"))]
    items = [win(0, RUNDLL + " javascript:x", "attack"), win(1, RUNDLL + " vbscript:x", "attack"),
             win(2, RUNDLL + " mshtml,x", "attack"), win(3, RUNDLL + " shell32.dll,Control_RunDLL", "normal"),
             web(4, LINE, "attack"), web(5, LINE.replace("passwd", "index"), "normal")]
    cands, _ = imp.candidates(items, [r for r, _ in rows], {r["path"]: t for r, t in rows}, CONFIG)
    assert len(cands) == 3
    return imp.pick(cands, items, covered=set(), batch=30)


def test_writes_xml_and_cases(tmp_path, three_sigma_rules):
    imp.write_batch(three_sigma_rules, rules_file=tmp_path / "0966-sigmahq.xml", cases_file=tmp_path / "0966-sigmahq.yml",
                    first_id=108000, today="2026-11-20")
    rules = ET.fromstring((tmp_path / "0966-sigmahq.xml").read_text(encoding="utf-8")).findall(".//rule")
    ids = {int(r.get("id")) for r in rules}
    cases = yaml.safe_load((tmp_path / "0966-sigmahq.yml").read_text(encoding="utf-8"))
    assert min(ids) == 108000 and len(ids) == 3 and all("shadow" in r.findtext("group") for r in rules)
    assert all("sigmahq_id=" in ET.tostring(r, encoding="unicode") for r in rules)
    assert {c["rule"] for c in cases if "rule" in c} == ids and {c["none"][0] for c in cases if "none" in c} == ids
    assert {c["log_format"] for c in cases} == {"eventchannel"} and cases[0]["location"] == "EventChannel"


def test_skips_rules_already_imported(tmp_path, three_sigma_rules):
    kw = dict(rules_file=tmp_path / "r.xml", cases_file=tmp_path / "c.yml", first_id=108000, today="2026-11-20")
    assert imp.write_batch(three_sigma_rules[:2], **kw) == [108000, 108001]
    assert imp.write_batch(three_sigma_rules, **kw) == [108002]                   # hai rule đầu bỏ, id đánh tiếp
    rules = ET.fromstring((tmp_path / "r.xml").read_text(encoding="utf-8")).findall(".//rule")
    assert sorted(int(r.get("id")) for r in rules) == [108000, 108001, 108002]
    assert len(yaml.safe_load((tmp_path / "c.yml").read_text(encoding="utf-8"))) == 6


def test_license_header(tmp_path, three_sigma_rules):
    imp.write_batch(three_sigma_rules, rules_file=tmp_path / "r.xml", cases_file=tmp_path / "c.yml", first_id=108000,
                    today="2026-11-20")
    assert "DRL 1.1" in (tmp_path / "r.xml").read_text(encoding="utf-8")[:600]


def test_skips_values_wazuh_keeps_as_xml_entities():
    row, text = sigma_rule("rules/g.yml", "Redirect", "  sel:\n    CommandLine|contains: ' > '\n  condition: sel", EVASION)
    cands, skipped = imp.candidates(ITEMS, [row], {row["path"]: text}, CONFIG)
    assert cands == [] and skipped == {"không dịch được sang Wazuh": 1}         # emit từ chối < > & trên Windows (M1)


def test_positive_sample_is_not_shadowed_by_an_earlier_rule_of_the_batch():
    items = [win(0, RUNDLL + " aaa bbb", "attack"), win(1, RUNDLL + " bbb", "attack"), win(2, RUNDLL + " zzz", "normal")]
    rows = [sigma_rule("rules/a.yml", "Has bbb", JS.replace("javascript:", "bbb"), EVASION),
            sigma_rule("rules/b.yml", "Has aaa", JS.replace("javascript:", "aaa"), EVASION)]
    cands, _ = imp.candidates(items, [r for r, _ in rows], {r["path"]: t for r, t in rows}, CONFIG)
    picked = imp.pick(cands, items, covered=set(), batch=30)
    assert [c.title for c in picked] == ["Has bbb"]       # "Has aaa" chỉ có mẫu 0, đã bị "Has bbb" (id nhỏ hơn) che: bỏ
    assert picked[0].pos["i"] in (0, 1)


def test_stolen_lists_samples_that_lose_a_non_batch_detection():
    """I1: --measure so lượt không có lô (0966) với lượt có lô; mẫu mất phát hiện ngoài 108xxx = lô cướp alert thật
    (cùng quy tắc 'không che rule khác' của cổng AI). Mẫu 108xxx mới bắt không tính là cướp."""
    base = {1: 92023, 2: 105005, 3: 108004, 4: 60103}
    mine = {1: 108000, 2: 105005, 3: 108004, 5: 108001}
    assert imp.stolen(base, mine) == {1: (92023, 108000), 4: (60103, None)}
    assert imp.stolen(base, base) == {}


def test_rule_overlapping_a_detected_sample_is_capped_at_level_7(tmp_path):
    """I1 (đo 08/11/2026): SHQ-018 level 10 cướp 92024 (L14, dưới 92023 L8), SHQ-003 cướp 105013 (L7). Rule lô khớp (cây
    Python) mẫu Wazuh ĐANG phát hiện thì level tối đa 7: thua rule gốc level >= 8, hòa level 7 thì rule nạp trước thắng."""
    row, text = sigma_rule("rules/a.yml", "Rundll32 JavaScript", JS, EVASION)          # high -> 10
    cands, _ = imp.candidates(ITEMS, [row], {row["path"]: text}, CONFIG)
    assert imp.pick(cands, ITEMS, covered=set(), batch=30)[0].level == 10
    picked = imp.pick(cands, ITEMS, covered={0}, batch=30)                              # mẫu 0 đã có phát hiện
    assert picked[0].level == 7
    imp.write_batch(picked, rules_file=tmp_path / "r.xml", cases_file=tmp_path / "c.yml", first_id=108000, today="2026-11-20")
    assert ET.fromstring((tmp_path / "r.xml").read_text(encoding="utf-8")).find(".//rule").get("level") == "7"
