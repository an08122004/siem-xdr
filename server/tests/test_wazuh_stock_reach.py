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
</group>""")
PROJECT = reach.parse('<rule id="100001" level="10"><if_sid>101</if_sid></rule>')


def test_parse_reads_tree_and_ignores_comments():
    assert STOCK[103]["parents"] == {102} and STOCK[104]["groups"] == {"syscheck"} and STOCK[200]["parents"] == set()


def test_real_alert_levels():
    assert [reach.is_real(STOCK[i]) for i in (102, 104, 105, 101)] == [True, True, False, False]


def test_descendants_of_hooked_parent_only():
    # dự án móc 101: hậu duệ thật là 102 và 103; 104 (anh em của 101) và 200 không dính
    assert reach.unpinned(STOCK, PROJECT, set()) == {102: {101}, 103: {101}}


def test_pinned_rule_is_dropped_and_nothing_hooked_means_nothing():
    assert reach.unpinned(STOCK, PROJECT, {102, 103}) == {}
    assert reach.unpinned(STOCK, {}, set()) == {}
