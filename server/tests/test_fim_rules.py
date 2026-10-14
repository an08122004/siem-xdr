"""FIM-001 (file / khóa registry dùng để duy trì truy cập) trên event syscheck của Wazuh, và việc không chuyển cảnh báo
chung của Wazuh cho cùng event khi rule riêng đã bắt (detection/wazuh.py covered_by)."""
from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from siem.detection import wazuh as bridge
from siem.detection.rules import RuleEngine, load_rules
from siem.pipeline.enrich import Enricher
from siem.pipeline.normalize import normalize

ROOT = Path(__file__).resolve().parent.parent
WIN = {"id": "003", "name": "PC-01", "ip": "10.10.30.30"}
LNX = {"id": "002", "name": "Ubuntu-01", "ip": "10.10.30.21"}


def wz(event_type="wazuh", agent=LNX, **ev):
    """Event thô đúng như Vector (vector/wazuh.yaml) đưa vào Kafka."""
    ev = {"timestamp": "2026-10-14T10:00:00.000+0000", "agent": agent, "manager": {"name": "wazuh-manager"},
          "id": "1791972000.1", "location": "syscheck", **ev}
    return {"timestamp": ev["timestamp"], "agent_id": f"wazuh-{agent['id']}", "source": "wazuh",
            "event_type": event_type, "data": ev}


@pytest.fixture(scope="module")
def enricher():
    return Enricher(ROOT / "config")


@pytest.fixture(scope="module")
def rules():
    return {r.id: r for r in load_rules(ROOT / "rules")}


def fired(rules, enricher, raw):
    engine = RuleEngine(list(rules.values()))
    return [d.rule.id for d in engine.process(enricher.enrich(normalize(raw)))]


def test_fim001_is_new_and_runs_in_shadow_first(rules):
    r = rules["FIM-001"]
    assert r.mode == "shadow" and r.shadow_since == "2026-10-14"            # rule mới chạy bóng >= 7 ngày (mục 4)
    assert "T1547.001" in r.mitre["technique"]                              # kỹ thuật ưu tiên trước đây chưa có rule


@pytest.mark.parametrize("agent,syscheck", [
    (WIN, {"path": "c:\\programdata\\microsoft\\windows\\start menu\\programs\\startup\\updater.lnk", "event": "added"}),
    (WIN, {"path": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "event": "added",
           "value_name": "Updater"}),
    (WIN, {"path": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "event": "modified",
           "value_name": "x"}),
    (LNX, {"path": "/etc/cron.d/backup-sync", "event": "added"}),
    (LNX, {"path": "/etc/systemd/system/evil.service", "event": "added"}),
    (LNX, {"path": "/home/ubuntu/.ssh/authorized_keys", "event": "modified"}),
    (LNX, {"path": "/etc/sudoers", "event": "modified"}),
])
def test_fim001_fires_on_raw_wazuh_syscheck(rules, enricher, agent, syscheck):
    assert fired(rules, enricher, wz(agent=agent, syscheck=syscheck)) == ["FIM-001"]


@pytest.mark.parametrize("syscheck", [
    {"path": "/root/.ssh/known_hosts", "event": "modified"},               # đổi mỗi lần SSH ra ngoài
    {"path": "/etc/cron.d/backup-sync", "event": "deleted"},               # xóa không phải cài cơ chế duy trì
    {"path": "/usr/bin/ls", "event": "modified"},                          # cập nhật gói
    {"path": "/var/www/html/shell.php", "event": "added"},                 # webshell: rule Wazuh 100100
    {"path": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\App", "event": "added"},
])
def test_fim001_ignores_ordinary_changes(rules, enricher, syscheck):
    assert fired(rules, enricher, wz(agent=WIN if syscheck["path"].startswith("HKEY") else LNX, syscheck=syscheck)) == []


def _alert(path, rule_id="550", level=7):
    return wz("wazuh_alert", syscheck={"path": path, "event": "modified"},
              rule={"id": rule_id, "level": level, "description": "Integrity checksum changed.", "groups": ["syscheck"]})


def test_generic_wazuh_alert_dropped_only_when_fim001_is_active(rules, enricher):
    shadow = list(rules.values())
    active = [dataclasses.replace(r, mode="active") if r.id == "FIM-001" else r for r in shadow]
    doc = enricher.enrich(normalize(_alert("/etc/sudoers")))
    assert bridge.to_alert(doc) is not None                                 # 550 level 7: vẫn đủ ngưỡng chuyển
    assert bridge.covered_by(doc, shadow) is None                           # chạy bóng: giữ cảnh báo Wazuh
    assert bridge.covered_by(doc, active) == "FIM-001"                      # chính thức: bỏ, chỉ còn FIM-001
    other = enricher.enrich(normalize(_alert("/etc/hostname")))
    assert bridge.covered_by(other, active) is None                         # file khác: giữ WZH-550
    local = enricher.enrich(normalize(_alert("/etc/cron.d/x", rule_id="100101", level=10)))
    assert bridge.covered_by(local, active) is None                         # rule Wazuh tự viết luôn giữ


def test_analyzer_emits_one_alert_per_fim_change_when_active(rules, enricher):
    from siem.analyzer import Analyzer
    active = [dataclasses.replace(r, mode="active") if r.id == "FIM-001" else r for r in rules.values()]
    an = Analyzer.__new__(Analyzer)
    an.enricher, an.engine, an.detector, an.buffer, an.stats = enricher, RuleEngine(active), None, [], \
        {"events": 0, "alerts": 0}
    emitted = []
    an.emit = emitted.append
    an.handle(wz(syscheck={"path": "/etc/sudoers", "event": "modified"}))   # bản archives.json -> rule riêng
    an.handle(_alert("/etc/sudoers"))                                       # bản alerts.json -> cầu nối Wazuh
    assert [a["rule"]["id"] for a in emitted] == ["FIM-001"]
