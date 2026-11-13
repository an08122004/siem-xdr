"""Cây rule gốc/dự án của tools/wazuh_stock_reach.py (bộ rule giả nhỏ)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

import wazuh_stock_reach as reach  # noqa: E402

STOCK = reach.parse("""<group name="x,">
<rule id="100" level="3"><description>cha</description></rule>
<rule id="101" level="5"><if_sid>100</if_sid></rule>
<rule id="102" level="12"><if_sid>101</if_sid><group>a,</group></rule>
<rule id="103" level="14"><if_matched_sid>102</if_matched_sid></rule>
<rule id="104" level="8"><if_sid>100</if_sid><group>syscheck,</group></rule>
<rule id="105" level="8"><if_sid>100</if_sid><group>web,</group></rule>
<rule id="200" level="13"><!-- <if_sid>100</if_sid> --><description>không dính cây</description></rule>
</group>
<group name="evt,"><rule id="300" level="3"><description>mang nhóm evt (nhóm ngoài)</description></rule></group>
<group name="y,">
<rule id="301" level="13"><if_group>evt</if_group><description>con qua nhóm</description></rule>
<rule id="302" level="4"><if_group>evt</if_group></rule>
<rule id="303" level="14"><if_sid>302</if_sid></rule>
<rule id="304" level="12"><if_matched_group>evt</if_matched_group><frequency>2</frequency></rule>
</group>""", "0100-stock.xml")


def project(level, file="0200-proj.xml", parent=101):
    return reach.parse(f'<rule id="100001" level="{level}"><if_sid>{parent}</if_sid></rule>', file)


def test_parse_reads_tree_and_ignores_comments():
    assert STOCK[103]["parents"] == {102} and STOCK[104]["groups"] == {"x", "syscheck"} and STOCK[200]["parents"] == set()


def test_parse_outer_group_and_if_group():
    assert STOCK[300]["groups"] == {"evt"} and STOCK[301]["if_groups"] == {"evt"} and STOCK[301]["groups"] == {"y"}
    assert STOCK[304]["if_groups"] == set()      # if_matched_group không phải cạnh cây


def test_real_alert_levels():
    assert [reach.is_real(STOCK[i]) for i in (102, 104, 105, 101)] == [True, True, False, False]


def test_guarantee_holds_when_project_sibling_is_lower_level():
    # dự án L10 móc 101; con trực tiếp 102 (L12) thắng; 103 nằm dưới 102 nên cũng tới được: cả hai có bảo đảm cấu trúc
    res = reach.analyse(STOCK, project(10), set())
    assert set(res) == {102, 103} and all(f["guaranteed"] for f in res.values())
    assert reach.unpinned(STOCK, project(10), set()) == {}


def test_guarantee_broken_by_higher_project_sibling_needs_pin():
    # dự án L13 > 102 (L12): không còn bảo đảm; chỉ ca ghim cứu
    assert reach.unpinned(STOCK, project(13), set()) == {102: {101}, 103: {101}}
    assert reach.unpinned(STOCK, project(13), {102, 103}) == {}


def test_tie_needs_stock_file_first():
    assert reach.unpinned(STOCK, project(12, "0200-proj.xml"), set()) == {}                         # hòa, rule gốc nạp trước
    assert set(reach.unpinned(STOCK, project(12, "0050-proj.xml"), set())) == {102, 103}           # hòa, rule dự án nạp trước


def test_if_group_child_is_found_and_judged():
    # dự án L10 móc 300 (mang nhóm evt): 301 (L13, qua if_group) có bảo đảm; 303 (L14) dưới 302 (L4) thua rule dự án L10
    res = reach.analyse(STOCK, project(10, parent=300), set())
    assert res[301]["group"] and res[301]["guaranteed"]
    assert not res[303]["guaranteed"] and 304 not in res
    # rule dự án L13 đè 301 (L13, hòa, dự án nạp sau: vẫn bảo đảm) nhưng L14 thì không
    assert reach.analyse(STOCK, project(13, parent=300), set())[301]["guaranteed"]
    assert not reach.analyse(STOCK, project(14, parent=300), set())[301]["guaranteed"]


def test_project_hooking_through_if_group_is_a_rival():
    low = reach.parse('<rule id="100002" level="13"><if_group>evt</if_group></rule>', "0200-proj.xml")
    high = reach.parse('<rule id="100002" level="14"><if_group>evt</if_group></rule>', "0200-proj.xml")
    assert reach.analyse(STOCK, low, set())[301]["guaranteed"] and not reach.analyse(STOCK, high, set())[301]["guaranteed"]


def test_nothing_hooked_means_nothing():
    assert reach.unpinned(STOCK, {}, set()) == {}


def test_parent_errors_missing_and_misordered():
    proj = reach.parse('<rule id="100001" level="5"><if_sid>101, 999</if_sid></rule>', "0050-proj.xml")
    out = reach.parent_errors(STOCK, proj)
    assert any("999" in e and "không có" in e for e in out) and any("101" in e and "chưa nạp" in e for e in out)
    assert reach.parent_errors(STOCK, project(5)) == []


def test_min_level_r65_counts_level_7_to_11_as_real():
    """R65: rule gốc level 7-11 cũng là alert thật (WAZUH_ALERT_MIN_LEVEL = 7); --min-level 7 xét cả chúng."""
    assert not reach.is_real(STOCK[105]) and reach.is_real(STOCK[105], 7) and not reach.is_real(STOCK[101], 7)
    hook = project(10, parent=100)                 # dự án L10 móc 100: thắng 105 (L8) cùng cha
    assert 105 not in reach.unpinned(STOCK, hook, set())
    assert reach.unpinned(STOCK, hook, set(), min_level=7)[105] == {100}
    assert 105 not in reach.unpinned(STOCK, hook, {105}, min_level=7)
