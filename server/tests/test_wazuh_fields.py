"""Ngoại lệ thành rule Wazuh level 0 (siem/wazuh_fields.py + siem/wazuh_exceptions.py)."""
import json
import xml.etree.ElementTree as ET

import pytest

from siem import wazuh_exceptions, wazuh_fields, wazuh_rules
from siem.wazuh_rules import WazuhRuleError


class FakeApi:
    def __init__(self, errors=()):
        self.errors, self.reloads = list(errors), 0

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
    group = ET.fromstring(f"<g>{x}</g>")                      # XML vẫn hợp lệ, đúng 1 rule
    rules = group.findall("rule")
    assert len(rules) == 1 and rules[0].get("level") == "0"
    pat = rules[0].find("url").text
    assert pat.startswith("^") and pat.endswith("$") and rules[0].find("url").get("type") == "pcre2"
    assert not any(c in pat for c in "<>\"&*()[]|\n ")       # mọi ký tự đặc biệt đã thành \xHH
    import re
    assert re.search(pat, evil) and not re.search(pat, "x" + evil) and not re.search(pat, "a")
    assert rules[0].findtext("description") == "Ngoại lệ: " + " ".join(evil.split())      # lý do chỉ là chữ, không thành thẻ


def test_dynamic_field_uses_field_tag():
    x = wazuh_fields.exception_rule(60000, [{"field": "process.command_line", "value": "a.exe -x", "decoder": "siem-procs"}],
                                    110001, "r")
    f = ET.fromstring(f"<g>{x}</g>").find("rule/field")
    assert f.get("name") == "cmd" and f.get("type") == "pcre2"


def test_add_allocates_ids_stably_and_removal_rewrites(tmp_path):
    api = FakeApi()
    a = wazuh_exceptions.add("WZH-31103", [{"field": "source.ip", "value": "10.10.40.50"}], "r1", "de", api, tmp_path)
    b = wazuh_exceptions.add("31104", [{"field": "user.name", "value": "svc"}], "r2", "de", api, tmp_path)
    assert (a["id"], b["id"]) == (110000, 110001)
    wazuh_exceptions.remove(110000, api, tmp_path)
    c = wazuh_exceptions.add("31103", [{"field": "source.ip", "value": "10.10.40.51"}], "r3", "de", api, tmp_path)
    assert c["id"] == 110002                                   # không tái dùng id đã gỡ
    ids = [r["id"] for r in wazuh_rules.parse((tmp_path / "exceptions.xml").read_text(encoding="utf-8"))]
    assert ids == [110001, 110002]
    assert [i["id"] for i in wazuh_exceptions.items(tmp_path)] == [110001, 110002]


def test_reload_failure_keeps_old_file_and_registry(tmp_path):
    ok = FakeApi()
    wazuh_exceptions.add("31103", [{"field": "source.ip", "value": "10.10.40.50"}], "r1", "de", ok, tmp_path)
    before = (tmp_path / "exceptions.xml").read_text(encoding="utf-8")
    with pytest.raises(WazuhRuleError):
        wazuh_exceptions.add("31103", [{"field": "source.ip", "value": "10.10.40.51"}], "r2", "de",
                             FakeApi(errors=["Failed to reload"]), tmp_path)
    assert (tmp_path / "exceptions.xml").read_text(encoding="utf-8") == before
    assert len(wazuh_exceptions.items(tmp_path)) == 1


def test_bad_input(tmp_path):
    for rule, conds in (("31103", []), ("abc", [{"field": "source.ip", "value": "1.1.1.1"}]),
                        ("31103", [{"field": "host.name", "value": "x"}]),
                        ("31103", [{"field": "source.ip", "value": "1.1.1.1"}, {"field": "source.ip", "value": "1.1.1.2"}])):
        with pytest.raises((ValueError, KeyError)):
            wazuh_exceptions.add(rule, conds, "r", "de", FakeApi(), tmp_path)
    assert not (tmp_path / "exceptions.xml").exists()


def test_registry_is_valid_json(tmp_path):
    wazuh_exceptions.add("31103", [{"field": "source.ip", "value": "10.10.40.50"}], "r", "de", FakeApi(), tmp_path)
    assert json.loads((tmp_path / "exceptions.json").read_text(encoding="utf-8"))["next"] == 110001
