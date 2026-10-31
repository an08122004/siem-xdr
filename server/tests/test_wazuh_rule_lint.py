"""Lint rule XML Wazuh (tools/wazuh_rule_lint.py)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

import wazuh_rule_lint as lint  # noqa: E402

AUTH = "0101-auth.xml"


def rule(rid=101001, level=5, desc="AUT-001 test", mitre="<mitre><id>T1110</id></mitre>", extra="<match>fail</match>",
         grp="siem,", attrs="", outer="local,"):
    return (f'<group name="{outer}"><rule id="{rid}" level="{level}"{attrs}><if_sid>5700</if_sid>{extra}'
            f"<description>{desc}</description>{mitre}<group>{grp}</group></rule></group>")


def cases(rid=101001):
    return [{"rule": rid}, {"none": [rid]}]


def run(xml, name=AUTH, cs=None):
    return lint.check({name: xml}, cases() if cs is None else cs)


def has(out, text):
    return any(text in o and not o.startswith("WARNING") for o in out)


def test_clean_rule_has_no_findings():
    assert run(rule()) == []


def test_id_out_of_range():
    assert has(run(rule(rid=102001), cs=cases(102001)), "ngoài dải")


def test_duplicate_id_across_files():
    out = lint.check({AUTH: rule(), "0102-linux.xml": rule()}, cases())
    assert has(out, "trùng")


def test_overwrite_outside_tuning():
    assert has(run(rule(attrs=' overwrite="yes"')), "overwrite")


def test_low_id_without_overwrite():
    assert has(run(rule(rid=5000), cs=cases(5000)), "< 100000")


def test_missing_code_prefix():
    assert has(run(rule(desc="không có mã")), "mã")


def test_missing_mitre():
    assert has(run(rule(mitre="")), "mitre")


def test_siem_group_from_outer_counts_but_siem_xdr_does_not():
    assert run(rule(grp="x,", outer="local,siem,")) == []
    assert has(run(rule(grp="siem-xdr,")), "siem")


def test_missing_positive_or_negative_case():
    assert has(run(rule(), cs=[{"none": [101001]}]), "dương")
    assert has(run(rule(), cs=[{"rule": 101001}]), "âm")


def test_nested_quantifier_regex():
    assert has(run(rule(extra="<regex>(a+)+$</regex>")), "regex")


def test_level0_needs_condition():
    assert has(run(rule(level=0, extra="")), "level 0")
    assert run(rule(level=0, extra="<match>x y</match>")) == []


def test_tuning_file_exempt_but_needs_overwrite():
    xml = rule(rid=5712, desc="tuning", mitre="", attrs=' overwrite="yes"')
    assert lint.check({lint.TUNING_FILE: xml}, []) == []
    assert has(lint.check({lint.TUNING_FILE: rule(rid=5712, desc="t", mitre="")}, []), "overwrite")
    assert has(lint.check({lint.TUNING_FILE: rule(attrs=' overwrite="yes"')}, []), "overwrite")


def test_warnings_frequency_if_matched_group_and_bare_field():
    xml = rule(extra='<if_matched_group>x</if_matched_group><field name="a">admin</field>', attrs=' frequency="5"')
    out = run(xml)
    assert len(out) == 2 and all(o.startswith("WARNING: ") for o in out)
    assert run(rule(extra='<field name="a">^admin$</field>')) == []


def test_real_repo_rules_are_clean():
    files = {f.name: f.read_text(encoding="utf-8") for f in lint.RULES_DIR.glob("*.xml")}
    assert [o for o in lint.check(files, lint.load_cases(lint.CASES_DIR)) if not o.startswith("WARNING")] == []
