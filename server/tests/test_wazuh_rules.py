"""Đọc file rule Wazuh và ghi file rule động an toàn (siem/wazuh_rules.py)."""
import pytest

from siem import wazuh_rules
from siem.wazuh_rules import WazuhRuleError

XML_100100 = """<group name="local,syscheck,siem,">
  <rule id="100100" level="10">
    <if_sid>554, 550</if_sid>
    <description>File mới trong thư mục web: $(file)</description>
    <mitre><id>T1505.003</id></mitre>
    <info>webshell</info>
    <group>web,webshell,</group>
  </rule>
</group>"""

GOOD = """<group name="siem,"><rule id="109001" level="5"><description>ok</description></rule></group>"""
OK_MSG = "Ruleset reload request sent successfully."


class FakeApi:
    """reload() thật nằm trong WazuhApi; ở đây chỉ ghi lại số lần gọi và lỗi định sẵn cho từng lần."""

    def __init__(self, errors=()):
        self.errors = list(errors)
        self.reloads = 0

    def reload(self):
        self.reloads += 1
        if self.errors and (e := self.errors.pop(0)):
            raise WazuhRuleError(e)


def api_with(monkeypatch, body):
    api = wazuh_rules.WazuhApi("https://x:55000", "siem-rules", "pw")
    monkeypatch.setattr(api, "request", lambda method, path, b=None: body)
    return api


def test_parse_reads_id_level_groups_mitre():
    r = wazuh_rules.parse(XML_100100)[0]
    assert r["id"] == 100100 and r["level"] == 10 and "siem" in r["groups"] and "webshell" in r["groups"]
    assert r["mitre"] == ["T1505.003"] and r["info"] == ["webshell"] and r["if_sid"] == [554, 550]
    assert r["overwrite"] is False and r["description"].startswith("File mới")


def test_parse_overwrite_flag():
    xml = '<group name="x,"><rule id="5710" level="0" overwrite="yes"><description>d</description></rule></group>'
    assert wazuh_rules.parse(xml)[0]["overwrite"] is True


def test_parse_rejects_broken_xml():
    with pytest.raises(WazuhRuleError):
        wazuh_rules.parse("<group name='x'><rule id='109001'>")


def test_parse_rejects_missing_attributes():
    with pytest.raises(WazuhRuleError):
        wazuh_rules.parse('<group name="x,"><rule level="5"/></group>')


def test_reload_rejects_invalid_xml(tmp_path):
    api = FakeApi()
    (tmp_path / "ai.xml").write_text(GOOD)
    with pytest.raises(WazuhRuleError):
        wazuh_rules.write_dynamic("ai.xml", "<rule", api, root=tmp_path)
    assert (tmp_path / "ai.xml").read_text() == GOOD and api.reloads == 0


def test_write_rejects_id_outside_range(tmp_path):
    api = FakeApi()
    with pytest.raises(WazuhRuleError, match="109000"):
        wazuh_rules.write_dynamic("ai.xml", GOOD.replace("109001", "110001"), api, root=tmp_path)
    assert not (tmp_path / "ai.xml").exists() and api.reloads == 0


def test_write_rejects_unknown_file(tmp_path):
    with pytest.raises(WazuhRuleError):
        wazuh_rules.write_dynamic("evil.xml", GOOD, FakeApi(), root=tmp_path)


def test_write_ok_replaces_file_and_reloads_once(tmp_path):
    api = FakeApi()
    wazuh_rules.write_dynamic("ai.xml", GOOD, api, root=tmp_path)
    assert (tmp_path / "ai.xml").read_text() == GOOD and api.reloads == 1
    assert [p.name for p in tmp_path.iterdir()] == ["ai.xml"]          # không để lại file tạm


def test_failed_reload_restores_previous_file_and_reloads_again(tmp_path):
    old = GOOD.replace("109001", "109002")
    (tmp_path / "ai.xml").write_text(old)
    api = FakeApi(errors=["Failed to reload ruleset"])
    with pytest.raises(WazuhRuleError, match="Failed to reload"):
        wazuh_rules.write_dynamic("ai.xml", GOOD, api, root=tmp_path)
    assert (tmp_path / "ai.xml").read_text() == old and api.reloads == 2
    assert [p.name for p in tmp_path.iterdir()] == ["ai.xml"]


def test_failed_reload_removes_new_file_when_none_before(tmp_path):
    api = FakeApi(errors=["boom"])
    with pytest.raises(WazuhRuleError):
        wazuh_rules.write_dynamic("ai.xml", GOOD, api, root=tmp_path)
    assert list(tmp_path.iterdir()) == [] and api.reloads == 2


def test_api_reload_ok(monkeypatch):
    body = {"error": 0, "data": {"affected_items": [{"name": "m", "msg": OK_MSG}], "failed_items": []}}
    api_with(monkeypatch, body).reload()


def test_api_reload_error_code(monkeypatch):
    body = {"error": 1, "message": "x", "data": {"affected_items": [], "failed_items": [
        {"error": {"code": 1914, "message": "Failed to reload ruleset: bad xml"}}]}}
    with pytest.raises(WazuhRuleError, match="bad xml"):
        api_with(monkeypatch, body).reload()


def test_api_reload_failed_items_with_error_zero(monkeypatch):
    body = {"error": 0, "data": {"affected_items": [], "failed_items": [{"error": {"message": "nope"}}]}}
    with pytest.raises(WazuhRuleError, match="nope"):
        api_with(monkeypatch, body).reload()


def test_api_reload_warning_msg_is_failure(monkeypatch):
    msg = "(7612): Rule ID '109010' is duplicated"
    body = {"error": 0, "data": {"affected_items": [{"name": "m", "msg": msg}], "failed_items": []}}
    with pytest.raises(WazuhRuleError, match="7612"):
        api_with(monkeypatch, body).reload()


def test_warning_msg_restores_file(tmp_path, monkeypatch):
    """Cả đường đi: WazuhApi thật nhận cảnh báo 'trùng id' -> file cũ được khôi phục, reload lần hai."""
    calls = []
    bodies = [{"error": 0, "data": {"affected_items": [{"msg": "(7619): Empty 'if_sid' value"}], "failed_items": []}},
              {"error": 0, "data": {"affected_items": [{"msg": OK_MSG}], "failed_items": []}}]
    api = wazuh_rules.WazuhApi("https://x:55000", "siem-rules", "pw")
    monkeypatch.setattr(api, "request", lambda m, p, b=None: calls.append((m, p)) or bodies.pop(0))
    (tmp_path / "ai.xml").write_text(GOOD)
    with pytest.raises(WazuhRuleError, match="7619"):
        wazuh_rules.write_dynamic("ai.xml", GOOD.replace("109001", "109005"), api, root=tmp_path)
    assert (tmp_path / "ai.xml").read_text() == GOOD
    assert calls == [("PUT", "/manager/analysisd/reload")] * 2


@pytest.mark.parametrize("args", [[], ["only-one"], ["a", "b", "c"]])
def test_api_user_script_fails_loudly_on_wrong_argc(args):
    import subprocess
    import sys
    from pathlib import Path
    script = Path(__file__).resolve().parents[2] / "wazuh/manager/entrypoint/siem_api_user.py"
    r = subprocess.run([sys.executable, str(script), *args], capture_output=True, text=True)
    assert r.returncode != 0 and "usage" in r.stderr
