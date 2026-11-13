"""Ngoại lệ thành rule Wazuh level 0 (siem/wazuh_fields.py + siem/wazuh_exceptions.py)."""
import re
import threading
import xml.etree.ElementTree as ET

import pytest

from siem import wazuh_exceptions, wazuh_fields, wazuh_rules
from siem.wazuh_rules import WazuhRuleError


class FakeApi:
    RULES = {31103: 5, 31104: 6, 60000: 4, 100: 0}

    def __init__(self, errors=(), down=False):
        self.errors, self.reloads, self.down = list(errors), 0, down

    def rule(self, rid):
        if self.down:
            raise wazuh_rules.WazuhUnavailable("API đóng")
        return {"id": rid, "level": self.RULES[rid]} if rid in self.RULES else None

    def reload(self):
        self.reloads += 1
        if self.errors and (e := self.errors.pop(0)):
            raise WazuhRuleError(e)


def test_to_wazuh_map():
    assert wazuh_fields.to_wazuh("source.ip", None) == "srcip"
    assert wazuh_fields.to_wazuh("user.name", None) == "dstuser"
    assert wazuh_fields.to_wazuh("url.original", None) == "url"
    assert wazuh_fields.to_wazuh("file.path", None) == "file"
    assert wazuh_fields.to_wazuh("process.command_line", None) == "win.eventdata.commandLine"
    assert wazuh_fields.to_wazuh("process.command_line", "siem-procs") == "cmd"
    with pytest.raises(KeyError):
        wazuh_fields.to_wazuh("host.hostname", None)


def test_exception_rule_srcip():
    x = wazuh_fields.exception_rule(31103, [{"field": "source.ip", "value": "10.10.40.50"}], 110000, "máy quét nội bộ")
    assert '<rule id="110000" level="0">' in x
    assert "<if_sid>31103</if_sid><srcip>10.10.40.50</srcip>" in x.replace("\n", "").replace("  ", "")
    assert "máy quét nội bộ" in x


def test_exception_rule_needs_conditions():
    with pytest.raises(ValueError):
        wazuh_fields.exception_rule(31103, [], 110000, "x")


def test_srcip_must_be_single_ip():
    for bad in ("10.0.0.0/8", "any", "10.0.0.1|.*"):
        with pytest.raises(ValueError):
            wazuh_fields.exception_rule(31103, [{"field": "source.ip", "value": bad}], 110000, "x")


def test_value_is_exact_literal_and_cannot_inject_xml():
    evil = 'a<b>"c" & .* (x|y) [z] $ \\ \n</rule><rule id="1" level="15">'
    x = wazuh_fields.exception_rule(31103, [{"field": "url.original", "value": evil}], 110000, evil)
    rules = ET.fromstring(f"<g>{x}</g>").findall("rule")      # XML vẫn hợp lệ, đúng 1 rule
    assert len(rules) == 1 and rules[0].get("level") == "0"
    pat = rules[0].find("url").text
    assert pat.startswith("^") and pat.endswith("\\z") and rules[0].find("url").get("type") == "pcre2"
    assert not any(c in pat for c in "<>\"&*()[]|\n ")       # mọi ký tự đặc biệt đã thành \xHH
    py = pat.replace("\\z", "\\Z")                            # Python viết \z là \Z
    assert re.search(py, evil) and not re.search(py, "x" + evil) and not re.search(py, "a")
    assert not re.search(py, evil + "\n")                     # `$` sẽ khớp trước \n cuối, \z thì không
    assert rules[0].findtext("description") == "Ngoại lệ: " + " ".join(evil.split())      # lý do chỉ là chữ


def test_dynamic_field_uses_field_tag():
    x = wazuh_fields.exception_rule(60000, [{"field": "process.command_line", "value": "a.exe -x", "decoder": "siem-procs"}],
                                    110001, "r")
    f = ET.fromstring(f"<g>{x}</g>").find("rule/field")
    assert f.get("name") == "cmd" and f.get("type") == "pcre2"


def test_dynamic_field_cannot_inject():
    evil = '"/><rule id="1" level="15"/><field name="x'
    x = wazuh_fields.exception_rule(60000, [{"field": "file.path", "value": evil}], 110001, "r")
    rules = ET.fromstring(f"<g>{x}</g>").findall("rule")
    assert len(rules) == 1 and rules[0].find("field").get("name") == "file"
    assert not any(c in rules[0].find("field").text for c in "<>\"")


def test_reason_truncated_before_escape_and_controls_stripped():
    x = wazuh_fields.exception_rule(60000, [{"field": "file.path", "value": "a"}], 110001, "<" * 400 + "\x00\x07z")
    d = ET.fromstring(f"<g>{x}</g>").findtext("rule/description")
    assert len(d) == 300                                      # cắt trước khi escape: không cắt đôi "&lt;"
    assert "\x00" not in x and "\x07" not in x


A = [{"field": "source.ip", "value": "10.10.40.50"}]


def mk(tmp_path, rule="WZH-31103", conds=A, api=None, by="de1"):
    return wazuh_exceptions.add(rule, conds, "lý do", by, api or FakeApi(), tmp_path)


def xml(tmp_path):
    p = tmp_path / "exceptions.xml"
    return p.read_text(encoding="utf-8") if p.exists() else ""


def test_pending_not_rendered_until_second_distinct_approver(tmp_path):
    api = FakeApi()
    e = mk(tmp_path, api=api)
    assert e["id"] == 110000 and e["status"] == "pending" and e["approvals"][0]["by"] == "de1"
    assert xml(tmp_path) == "" and api.reloads == 0
    with pytest.raises(ValueError):
        wazuh_exceptions.approve(110000, "DE1", api, tmp_path)           # cùng người (không phân biệt hoa thường)
    assert xml(tmp_path) == ""
    assert wazuh_exceptions.approve(110000, "de2", api, tmp_path)["status"] == "active"
    out = xml(tmp_path)
    assert 'id="110000" level="0"' in out and "<if_sid>31103</if_sid>" in out and "<srcip>10.10.40.50</srcip>" in out
    assert [r["id"] for r in wazuh_rules.parse(out)] == [110000]


def test_ids_stable_never_reused_removed_kept_as_history(tmp_path):
    api = FakeApi()
    a, b = mk(tmp_path, api=api), mk(tmp_path, "31104", [{"field": "user.name", "value": "svc"}], api)
    for i in (a["id"], b["id"]):
        wazuh_exceptions.approve(i, "de2", api, tmp_path)
    r = wazuh_exceptions.remove(110000, "de3", "hết cần", api, tmp_path)
    assert r["status"] == "removed" and r["removed_by"] == "de3" and r["removed_reason"] == "hết cần"
    c = mk(tmp_path, conds=[{"field": "source.ip", "value": "10.10.40.51"}], api=api)
    assert c["id"] == 110002
    assert [x["id"] for x in wazuh_rules.parse(xml(tmp_path))] == [110001]
    assert [i["status"] for i in wazuh_exceptions.items(tmp_path)] == ["removed", "active", "pending"]


def test_removing_last_exception_deletes_file(tmp_path):
    api = FakeApi()
    e = mk(tmp_path, api=api)
    wazuh_exceptions.approve(e["id"], "de2", api, tmp_path)
    assert xml(tmp_path)
    wazuh_exceptions.remove(e["id"], "de3", "hết cần", api, tmp_path)
    assert not (tmp_path / "exceptions.xml").exists()          # group rỗng bị Wazuh từ chối: xóa file


def test_duplicate_rejected_but_allowed_after_removal(tmp_path):
    api = FakeApi()
    mk(tmp_path, api=api)
    with pytest.raises(wazuh_exceptions.Duplicate):
        mk(tmp_path, api=api, by="de2")
    wazuh_exceptions.remove(110000, "de1", "huy", api, tmp_path)
    assert mk(tmp_path, api=api)["id"] == 110001


def test_reload_failure_keeps_old_xml_and_registry_written_first(tmp_path):
    api = FakeApi()
    a = mk(tmp_path, api=api)
    wazuh_exceptions.approve(a["id"], "de2", api, tmp_path)
    before = xml(tmp_path)
    b = mk(tmp_path, conds=[{"field": "source.ip", "value": "10.10.40.51"}], api=api)
    seen = []
    bad = FakeApi(errors=["Failed to reload"])
    orig = bad.reload
    bad.reload = lambda: (seen.append([i["status"] for i in wazuh_exceptions.items(tmp_path)]), orig())[1]
    with pytest.raises(WazuhRuleError):
        wazuh_exceptions.approve(b["id"], "de2", bad, tmp_path)
    assert seen[0] == ["active", "active"]                     # lúc nạp lại, sổ cái ĐÃ có mục (ghi trước)
    assert xml(tmp_path) == before
    st = wazuh_exceptions.items(tmp_path)
    assert st[1]["status"] == "failed" and st[1]["id"] == 110001
    assert mk(tmp_path, conds=[{"field": "source.ip", "value": "10.10.40.52"}], api=api)["id"] == 110002


def test_failed_removal_restores_active(tmp_path):
    api = FakeApi()
    a = mk(tmp_path, api=api)
    wazuh_exceptions.approve(a["id"], "de2", api, tmp_path)
    with pytest.raises(WazuhRuleError):
        wazuh_exceptions.remove(a["id"], "de3", "x", FakeApi(errors=["boom"]), tmp_path)
    assert wazuh_exceptions.items(tmp_path)[0]["status"] == "active" and "110000" in xml(tmp_path)


def test_parent_must_exist_and_be_alerting(tmp_path):
    for rule in ("WZH-99999", "110000", "100"):                # không có / là ngoại lệ / level 0
        with pytest.raises(ValueError):
            mk(tmp_path, rule)
    with pytest.raises(wazuh_rules.WazuhUnavailable):
        mk(tmp_path, api=FakeApi(down=True))
    assert wazuh_exceptions.items(tmp_path) == []


def test_bad_input(tmp_path):
    for rule, conds in (("31103", []), ("abc", A), ("31103", [{"field": "host.name", "value": "x"}]),
                        ("31103", A + [{"field": "source.ip", "value": "1.1.1.2"}])):
        with pytest.raises((ValueError, KeyError)):
            mk(tmp_path, rule, conds)
    assert wazuh_exceptions.items(tmp_path) == [] and xml(tmp_path) == ""


def test_concurrent_adds_get_distinct_ids(tmp_path):
    api, out = FakeApi(), []

    def go(n):
        out.append(mk(tmp_path, conds=[{"field": "source.ip", "value": f"10.0.0.{n}"}], api=api)["id"])
    ts = [threading.Thread(target=go, args=(n,)) for n in range(1, 21)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sorted(out) == list(range(110000, 110020))
    assert len(wazuh_exceptions.items(tmp_path)) == 20


def test_os_error_during_write_rolls_back_registry(tmp_path, monkeypatch):
    api = FakeApi()
    a = mk(tmp_path, api=api)
    b = mk(tmp_path, conds=[{"field": "source.ip", "value": "10.10.40.51"}], api=api)
    wazuh_exceptions.approve(a["id"], "de2", api, tmp_path)

    def boom(*args, **kw):
        raise OSError("đĩa đầy")
    monkeypatch.setattr(wazuh_rules, "write_dynamic", boom)
    with pytest.raises(OSError):
        wazuh_exceptions.remove(a["id"], "de3", "x", api, tmp_path)
    with pytest.raises(OSError):
        wazuh_exceptions.approve(b["id"], "de2", api, tmp_path)
    st = wazuh_exceptions.items(tmp_path)
    assert st[0]["status"] == "active" and "removed_by" not in st[0]          # XML còn rule: sổ cái phải nói đúng
    assert st[1]["status"] == "failed" and "đĩa đầy" in st[1]["error"]
