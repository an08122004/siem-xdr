import re, xml.etree.ElementTree as ET
import pytest
from siem.ai import wazuh_xml as wx
from siem.ai.sigma import SigmaError
from siem.ai.condition import Condition

def py_match(leaf, actual):                      # ngữ nghĩa chuẩn: cây Python mà AI đang dùng
    return Condition(leaf).match({"process": {"command_line": actual}})

WIN = {"all": [{"field": "process.executable", "op": "endswith", "value": "\\rundll32.exe"},
               {"field": "process.command_line", "op": "contains", "value": "javascript:"}]}
KW = dict(domain="windows", first_id=109000, level=7, code="AI-000", title="Rundll32 JS",
          techniques=["T1218.011"], groups=["siem", "ai"], shadow_since="2026-11-20")

def rules(xml): return ET.fromstring(f"<g>{xml}</g>").findall("rule")

def test_single_term_windows():
    e = wx.emit(WIN, **KW)
    assert e.ids == [109000]
    r, = rules(e.xml)
    assert (r.get("id"), r.get("level"), r.findtext("if_sid")) == ("109000", "7", "61603")
    assert {f.get("name") for f in r.findall("field")} == {"win.eventdata.image", "win.eventdata.commandLine"}
    assert all(f.get("type") == "pcre2" for f in r.findall("field"))
    assert r.findtext("group").split(",")[:3] == ["siem", "ai", "shadow"]
    assert "shadow_since=2026-11-20" in [i.text for i in r.findall("info")]
    assert r.findtext("mitre/id") == "T1218.011" and r.findtext("description").startswith("AI-000 ")

def test_or_across_fields_becomes_sibling_rules():
    tree = {"any": [{"field": "process.command_line", "op": "contains", "value": "a1"},
                    {"field": "process.executable", "op": "endswith", "value": "\\b.exe"}]}
    e = wx.emit(tree, **KW)
    assert e.ids == [109000, 109001]
    assert [r.findtext("description")[-8:] for r in rules(e.xml)] == ["(vế 1/2)", "(vế 2/2)"]

def test_or_on_same_field_stays_one_rule():
    tree = {"any": [{"field": "process.command_line", "op": "contains", "value": v} for v in ("aa", "bb")]}
    assert len(wx.emit(tree, **KW).ids) == 1

@pytest.mark.parametrize("op,value,actual", [
    ("eq", "cmd.exe", "CMD.EXE"), ("eq", "cmd.exe", "xcmd.exe"), ("contains", "a.b", "xxA.Byy"),
    ("contains", "a.b", "axb"), ("startswith", "C:\\Win", "c:\\windows\\x"), ("endswith", ".ps1", "a.PS1"),
    ("endswith", ".ps1", "a.ps1x"), ("in", ["x", "y"], "Y"), ("regex", r"\d{3}-x", "a123-X"),
    ("contains", ["aa", "bb"], "xbbx")])
def test_pattern_matches_like_python_tree(op, value, actual):
    leaf = {"field": "process.command_line", "op": op, "value": value}
    py = re.compile(wx.pattern([leaf], []).replace(r"\z", r"\Z"))
    assert bool(py.search(actual)) == py_match(leaf, actual)

def test_case_sensitive_regex_kept():
    leaf = {"field": "process.command_line", "op": "regex", "value": "AbC", "case_sensitive": True}
    py = re.compile(wx.pattern([leaf], []).replace(r"\z", r"\Z"))
    assert py.search("xAbC") and not py.search("xabc")

def test_negative_ops_become_lookaheads():
    leaf = {"field": "process.command_line", "op": "not_contains", "value": "safe"}
    pos = {"field": "process.command_line", "op": "contains", "value": "run"}
    xml = wx.emit({"all": [pos, leaf]}, **KW).xml
    assert "(?!" in xml and len(rules(xml)) == 1

def test_negation_is_negative_lookahead():
    p = wx.pattern([{"field": "f", "op": "contains", "value": "run"}], [{"field": "f", "op": "contains", "value": "safe"}])
    py = re.compile(p.replace(r"\z", r"\Z"))
    assert py.search("x run y") and not py.search("run safe")

@pytest.mark.parametrize("domain,leaf", [
    ("linux", {"field": "process.parent.executable", "op": "eq", "value": "/bin/sh"}),
    ("windows", {"field": "source.ip", "op": "eq", "value": "10.0.0.1"}),
    ("windows", {"field": "process.command_line", "op": "exists", "value": True})])
def test_unmapped_field_or_op_raises(domain, leaf):
    with pytest.raises(SigmaError):
        wx.emit(leaf, **{**KW, "domain": domain})

def test_too_many_terms_raises():
    tree = {"all": [{"any": [{"field": "process.command_line", "op": "contains", "value": f"{i}{j}"},
                             {"field": "process.executable", "op": "contains", "value": f"{i}{j}"}]} for i, j in
                    [(1, 1), (2, 2), (3, 3), (4, 4), (5, 5), (6, 6)]]}          # 2^6 = 64 vế > 32
    with pytest.raises(SigmaError):
        wx.emit(tree, **KW)

def test_web_rule_parent_location_and_encoding():
    tree = {"field": "url.decoded", "op": "contains", "value": "' or 1=1"}
    r, = rules(wx.emit(tree, **{**KW, "domain": "web"}).xml)
    assert r.findtext("if_sid").startswith("31100,") and r.findtext("location") == r"^\("
    py = re.compile(r.findtext("url").replace(r"\z", r"\Z"))
    assert py.search("/a?id=1' or 1=1") and py.search("/a?id=1%27%20or%201%3D1")

def test_user_agent_uses_last_quoted_string():
    r, = rules(wx.emit({"field": "user_agent.original", "op": "contains", "value": "sqlmap"},
                       **{**KW, "domain": "web"}).xml)
    assert r.find("regex").get("type") == "pcre2" and r.findtext("regex").endswith(r'"\s*$')

def test_emit_escapes_hostile_values():
    hostile = 'a<b&"c]]>\\\x00\r\nđ'
    e = wx.emit({"field": "process.command_line", "op": "contains", "value": hostile},
                **{**KW, "title": "<script>x</script>\x07"})
    r, = rules(e.xml)                                    # parse được = không vỡ XML
    assert [c.tag for c in r].count("field") == 1 and "<script>" not in e.xml and "\x07" not in e.xml
    assert re.compile(r.findtext("field").replace(r"\z", r"\Z")).search("zz" + hostile)

def test_unshadow_removes_only_shadow_markers():
    e = wx.emit(WIN, **KW)
    u = wx.unshadow(e.xml)
    r, = rules(u)
    assert "shadow" not in r.findtext("group").split(",") and "shadow_since" not in u
    assert (r.get("id"), r.get("level"), len(r.findall("field"))) == ("109000", "7", 2) and wx.unshadow(u) == u

def test_level_map():
    assert wx.LEVEL == {"low": 5, "medium": 7, "high": 10, "critical": 10}


def test_info_entries_are_text_key_value():
    e = wx.emit(WIN, **KW, info={"sigmahq_id": 'a<b&"]]>\x07x', "au thor!": "Bob"})
    infos = [(i.get("type"), i.text) for i in rules(e.xml)[0].findall("info")]
    assert ("text", 'sigmahq_id=a<b&"]]>x') in infos and ("text", "author=Bob") in infos
    assert all(t == "text" for t, _ in infos)

def test_nested_any_is_flattened_not_keyerror():
    a, b, c = (({"field": "process.command_line", "op": "contains", "value": v}) for v in ("aa", "bb", "cc"))
    assert len(wx.emit({"any": [{"any": [a, b]}, c]}, **KW).ids) == 1

@pytest.mark.parametrize("bad", ["x)(?=", "a)", "(a+)+$"])
def test_hostile_or_risky_regex_raises(bad):
    with pytest.raises(SigmaError):
        wx.emit({"field": "process.command_line", "op": "regex", "value": bad}, **KW)

def test_normal_regex_still_emits():
    assert wx.emit({"field": "process.command_line", "op": "regex", "value": r"-enc\s+\w{10,}"}, **KW).ids == [109000]
