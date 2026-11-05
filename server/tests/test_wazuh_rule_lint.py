"""Lint rule XML Wazuh (tools/wazuh_rule_lint.py)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

import wazuh_rule_lint as lint  # noqa: E402

AUTH = "0101-auth.xml"


def rule(rid=101001, level=5, desc="AUT-001 test", mitre="<mitre><id>T1110</id></mitre>", extra="<match>fail</match>",
         grp="siem,", attrs="", outer="local,", shadow=True, parent=5700):
    info = '<info type="text">shadow_since=2026-11-05</info>' if shadow else ""
    grp = grp + "shadow," if shadow else grp
    return (f'<group name="{outer}"><rule id="{rid}" level="{level}"{attrs}><if_sid>{parent}</if_sid>{extra}'
            f"<description>{desc}</description>{mitre}{info}<group>{grp}</group></rule></group>")


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
    assert has(run(rule(extra='<regex type="pcre2">(a+)+$</regex>')), "regex")


def test_level0_needs_condition():
    assert has(run(rule(level=0, extra="")), "level 0")
    assert run(rule(level=0, extra="<match>x y</match>")) == []


def test_tuning_file_exempt_but_needs_overwrite():
    xml = rule(rid=5712, desc="tuning", mitre="", attrs=' overwrite="yes"')
    assert lint.check({lint.TUNING_FILE: xml}, []) == []
    assert has(lint.check({lint.TUNING_FILE: rule(rid=5712, desc="t", mitre="")}, []), "overwrite")
    assert has(lint.check({lint.TUNING_FILE: rule(attrs=' overwrite="yes"')}, []), "overwrite")


def test_warnings_frequency_if_matched_group_and_bare_field():
    xml = rule(extra='<if_matched_group>x</if_matched_group><field name="a" type="pcre2">admin</field>',
               attrs=' frequency="5"')
    out = run(xml)
    assert len(out) == 2 and all(o.startswith("WARNING: ") for o in out)
    assert run(rule(extra='<field name="a" type="pcre2">^admin$</field>')) == []


def test_regex_and_field_need_pcre2_but_match_does_not():
    assert has(run(rule(extra="<regex>a</regex>")), "pcre2")
    assert has(run(rule(extra='<field name="a">^b$</field>')), "pcre2")
    assert run(rule(extra='<regex type="pcre2">^a$</regex><url>x</url>')) == []
    assert has(lint.check({lint.TUNING_FILE: rule(rid=5712, attrs=' overwrite="yes"', extra="<regex>a</regex>")}, []),
               "pcre2") is False


def test_malformed_rules_never_crash():
    assert has(run('<group name="siem,"><rule level="5"><description>X</description></rule></group>'), "id")
    assert has(run('<group name="siem,"><rule id="abc" level="5"/></group>'), "id")
    out = run(rule().replace('<group name="local,">', "").replace("</group></rule></group>", "</group></rule>"))
    assert has(out, "ngoài <group>")


def test_duplicate_id_in_one_file_still_checks_first_element():
    tpl = '<rule id="101001" level="5"><field name="a" type="pcre2">{}</field></rule>'
    out = run(f'<group name="siem,">{tpl.format("admin")}{tpl.format("^admin$")}</group>')
    assert has(out, "trùng") and sum("từ trần" in o for o in out) == 1


def test_empty_mitre_id_is_an_error():
    assert has(run(rule(mitre="<mitre><id/></mitre>")), "mitre")


def test_tuning_exempt_from_siem_and_dynamic_from_cases():
    assert lint.check({lint.TUNING_FILE: rule(rid=5712, attrs=' overwrite="yes"', grp="x,")}, []) == []
    ai = rule(rid=109001)
    assert lint.check({"rules-dynamic/ai.xml": ai}, []) == []
    assert has(lint.check({"rules-dynamic/ai.xml": rule(rid=109001, grp="x,")}, []), "siem")


def test_real_repo_rules_are_clean():
    files = {f.name: f.read_text(encoding="utf-8") for f in lint.RULES_DIR.glob("*.xml")}
    assert [o for o in lint.check(files, lint.load_cases(lint.CASES_DIR)) if not o.startswith("WARNING")] == []


def test_level0_feeder_rule_needs_no_positive_case():
    """Rule level 0 chỉ làm cha (if_sid) của rule khác: harness chỉ thấy rule cuối của chuỗi nên không thể có ca dương riêng."""
    parent = ('<group name="local,"><rule id="101021" level="0"><decoded_as>json</decoded_as>'
              '<description>CON-021 cha</description><mitre><id>T1078</id></mitre><group>siem,</group></rule>'
              '<rule id="101000" level="2"><if_sid>101021</if_sid><match>x</match><description>AUT-000 con</description>'
              '<mitre><id>T1110</id></mitre><group>siem,</group></rule></group>')
    cs = [{"rule": 101000}, {"none": [101000, 101021]}]
    assert run(parent, cs=cs) == []
    assert has(run(parent, cs=[{"rule": 101000}, {"none": [101000]}]), "ca test âm")   # vẫn đòi ca âm


def test_level0_rule_with_if_sid_but_no_child_still_needs_positive_case():
    alone = rule(rid=101021, level=0, extra="<decoded_as>json</decoded_as>")
    assert has(run(alone, cs=[{"none": [101021]}]), "ca test dương")


def test_level0_feeder_exemption_ignores_comments_and_other_files():
    parent = rule(rid=101021, level=0, extra="<decoded_as>json</decoded_as>")
    commented = parent + "<!-- <rule id='101000'><if_sid>101021</if_sid></rule> -->"
    assert has(run(commented, cs=[{"none": [101021]}]), "ca test dương")                         # chú thích không tính
    other = lint.check({AUTH: parent, "0102-linux.xml": rule(rid=102001, extra="<if_sid>101021</if_sid>")},
                       [{"none": [101021]}, {"rule": 102001}, {"none": [102001]}])
    assert has(other, "ca test dương")                                                           # con ở file khác không tính


def test_attack_layer_counts_only_rules_that_are_on():
    xml = (rule(101001, grp="siem,", shadow=False) + rule(101002, mitre="<mitre><id>T1486</id></mitre>", grp="siem,shadow,", shadow=False)
           + rule(101003, mitre="<mitre><id>T1110.001</id></mitre>", shadow=False))
    layer = lint.attack_layer({AUTH: xml}, {"techniques": [{"id": "T1110"}, {"id": "T1486"}]})
    got = {t["techniqueID"]: t for t in layer["techniques"]}
    assert got["T1110"]["score"] == 1 and got["T1110.001"]["score"] == 1 and got["T1110"]["color"] == "#2e7d32"
    assert got["T1486"]["score"] == 0 and got["T1486"]["color"] == "#e2474b"     # chỉ có rule bóng -> chưa phủ


def test_ignore_attribute_is_forbidden():
    assert has(run(rule(attrs=' frequency="5" timeframe="60" ignore="60"')), "ràng buộc toàn cục 7")
    assert not has(run(rule(attrs=' frequency="5" timeframe="60"')), "ignore")


def test_tuning_level12_needs_shadow_or_real_before():
    """R58: overwrite có hiệu lực ngay; level >= 12 phải chạy bóng (shadow) hoặc ghi real_before=yes nếu rule gốc vốn đã là alert thật."""
    def tune(grp, info=""):
        return rule(rid=5712, level=12, attrs=' overwrite="yes"', grp=grp, shadow=False).replace("</group></rule>", "</group>" + info + "</rule>")
    real = '<info type="text">real_before=yes</info>'
    assert has(lint.check({lint.TUNING_FILE: tune("x,")}, []), "R58")
    assert not has(lint.check({lint.TUNING_FILE: tune("shadow,")}, []), "R58")
    assert not has(lint.check({lint.TUNING_FILE: tune("x,", real)}, []), "R58")


def test_new_rule_level3_needs_shadow_group_and_date():
    assert has(run(rule(shadow=False)), "chạy bóng")
    assert has(run(rule(shadow=False, grp="siem,shadow,")), "chạy bóng")                    # có nhóm, thiếu shadow_since
    assert has(run(rule().replace("shadow_since=2026-11-05", "shadow_since=hom-nay")), "chạy bóng")
    assert not has(run(rule(level=2, shadow=False)), "chạy bóng")                          # dưới level 3 không đòi


def test_shadow_exemptions_pre_live_ids_and_port_of_stock():
    plat = lint.check({"0100-platform.xml": rule(rid=100100, desc="WEB-010 x", shadow=False)}, cases(100100))
    assert not has(plat, "chạy bóng")
    port = rule(shadow=False).replace("</description>", "</description><info type=\"text\">port_of_stock=99906</info>")
    assert not has(run(port), "chạy bóng")


def test_project_parent_must_be_defined_earlier():
    two = rule(101001) + rule(101002, parent=101001)
    assert not has(run(two, cs=cases(101001) + cases(101002)), "TRƯỚC")                      # cha ở trên cùng file
    rev = rule(101002, parent=101001) + rule(101001)
    assert has(run(rev, cs=cases(101001) + cases(101002)), "TRƯỚC")                          # cha ở dưới
    assert has(run(rule(101002, parent=101999), cs=cases(101002)), "TRƯỚC")                  # cha không tồn tại
    assert not has(run(rule(parent=5715)), "TRƯỚC")                                          # cha gốc không xét ở đây
    early = lint.check({AUTH: rule(101001), "0102-linux.xml": rule(102001, parent=101001)}, cases(101001) + cases(102001))
    late = lint.check({"0100-platform.xml": rule(100001, parent=101001), AUTH: rule(101001)}, cases(100001) + cases(101001))
    assert not has(early, "TRƯỚC") and has(late, "TRƯỚC")                                    # file xếp trước / sau
    assert has(run(rule(101002, parent=101001).replace("<if_sid>", "<if_matched_sid>").replace("</if_sid>", "</if_matched_sid>"),
                   cs=cases(101002)), "TRƯỚC")
