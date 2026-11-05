"""Task 15: SOAR chọn playbook theo nhóm / mã rule Wazuh (R59: IP nguồn qua syslog giả được -> không tự chặn)."""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from siem.detection import alerts as alert_builder
from siem.detection.wazuh import severity_for
from siem.soar.cases import CasePlaybooks
from siem.soar.engine import Notifier, Soar, load_playbooks
from test_pipeline import FakeES

ROOT = Path(__file__).resolve().parents[1]
RULES_XML = ROOT.parent / "wazuh" / "manager" / "rules"


def wazuh_alert(rid, level, groups, agent="web-01", ip="203.0.113.9", pid=None):
    ev = {"@timestamp": "2026-11-04T00:00:00+00:00", "event": {"id": "e1"}, "agent": {"id": agent},
          "source": {"ip": ip}, "wazuh": {"rule": {"id": rid, "level": level, "groups": groups, "description": "t"}}}
    if pid:
        ev["process"] = {"pid": pid, "name": "x"}
    return alert_builder.from_wazuh(ev, severity_for(level))


def run(alert, monkeypatch):
    from siem import store
    monkeypatch.setattr(store, "list_agents", lambda _es: [{"agent_id": "web-01", "status": "online"}])
    es = FakeES()
    soar = Soar(es, load_playbooks(ROOT / "config" / "playbooks.yml"), whitelist=[], notifier=Notifier(),
                case_playbooks=CasePlaybooks(ROOT / "config" / "case_playbooks.yml"))
    return soar.handle(alert), es


def blocked(results):
    return any(r["action"] == "block_ip" and r["status"] == "queued" for r in results)


@pytest.mark.parametrize("rid,groups", [(5712, ["syslog", "authentication_failures"]), (5720, ["syslog", "authentication_failures"]),
                                        (5763, ["syslog", "authentication_failures"]),
                                        (31152, ["web", "attack", "sql_injection"])])
def test_approved_stock_ids_block_ip_on_origin_agent_only(rid, groups, monkeypatch):
    res, es = run(wazuh_alert(rid, 10, groups), monkeypatch)
    assert blocked(res) and {a["agent_id"] for a in es.docs["siem-actions"].values()} == {"web-01"}
    assert any(a["params"]["ip"] == "203.0.113.9" for a in es.docs["siem-actions"].values())


@pytest.mark.parametrize("rid,groups", [(3357, ["postfix", "authentication_failures"]),
                                        (9551, ["wordpress", "authentication_failures"]),
                                        (9750, ["dovecot", "authentication_failures"]),
                                        (60204, ["windows", "authentication_failures"]),
                                        (31151, ["web", "web_scan"]),       # R61: WEB-006 hạ về level 7 (0999-tuning.xml)
                                        (31161, ["web", "web_scan"]), (31163, ["web", "web_scan"])])
def test_other_stock_rules_in_groups_never_block(rid, groups, monkeypatch):
    res, es = run(wazuh_alert(rid, 10, groups), monkeypatch)
    assert not blocked(res) and "siem-actions" not in es.docs
    assert any(r["action"] == "create_case" for r in res)                 # vẫn thông báo / mở case


def test_level_7_or_attack_group_does_not_block(monkeypatch):
    assert not blocked(run(wazuh_alert(31103, 7, ["web", "sql_injection"]), monkeypatch)[0])
    assert not blocked(run(wazuh_alert(31153, 10, ["web", "attack"]), monkeypatch)[0])


def test_shadow_alert_runs_no_playbook(monkeypatch):
    a = wazuh_alert(104001, 10, ["siem", "web", "shadow", "legacy_WEB-001"])
    assert a["alert"]["shadow"] is True
    res, es = run(a, monkeypatch)
    assert res == [] and not es.docs


@pytest.mark.parametrize("rid,groups", [(101001, ["siem", "auth", "legacy_AUTH-001"]),
                                        (5712, ["syslog", "sshd", "authentication_failures"]),
                                        (104004, ["siem", "web", "legacy_WEB-004"]),
                                        (101002, ["siem", "auth", "legacy_AUTH-002"])])
def test_syslog_source_never_triggers_block_ip_but_still_notifies_and_cases(rid, groups, monkeypatch):
    res, es = run(wazuh_alert(rid, 12, groups, agent="syslog-10.1.1.1"), monkeypatch)
    assert not blocked(res) and "siem-actions" not in es.docs
    assert any(r["action"] == "create_case" and r["status"] == "created" for r in res)


def test_agent_source_blocks_for_auth_and_rule_ids(monkeypatch):
    assert blocked(run(wazuh_alert(101001, 10, ["siem", "auth", "legacy_AUTH-001"]), monkeypatch)[0])
    assert blocked(run(wazuh_alert(104095, 14, ["siem", "web", "accesslog", "attack"]), monkeypatch)[0])


def test_kill_only_from_agent_not_syslog(monkeypatch):
    res, es = run(wazuh_alert(102001, 12, ["siem", "linux", "legacy_LNX-001"], pid=4242), monkeypatch)
    assert any(r["action"] == "kill_process" and r["status"] == "queued" for r in res)
    res, _ = run(wazuh_alert(102001, 12, ["siem", "linux", "legacy_LNX-001"], agent="syslog-10.1.1.1", pid=4242), monkeypatch)
    assert all(r["status"] != "queued" for r in res if r["action"] == "kill_process")


def test_yaml_code_alerts_still_use_yaml_playbooks(monkeypatch):
    a = {"alert": {"id": "y1", "source": "rule"}, "rule": {"id": "AUTH-001", "name": "bf"}, "severity": "high",
         "severity_score": 3, "source": {"ip": "10.9.9.9"}, "agent": {"id": "web-01"}, "message": "x"}
    assert blocked(run(a, monkeypatch)[0])


def test_case_playbook_group_step_order(tmp_path):
    p = tmp_path / "cp.yml"
    p.write_text("""playbooks:
  - {id: PB-A, name: a, match: [X-1], phases: []}
  - {id: PB-T, name: t, techniques: [T1190], phases: []}
  - {id: PB-G, name: g, groups: ["legacy_WEB-*"], phases: []}
  - {id: PB-TAG, name: tag, tags: [web], phases: []}
  - {id: PB-00, name: z, match: ["*"], phases: []}
""", encoding="utf-8")
    cp = CasePlaybooks(p)
    sel = lambda *a, **k: cp.select(*a, **k)[0]["id"]  # noqa: E731
    assert sel("X-1", groups=["legacy_WEB-001"]) == "PB-A"                                # mã thắng nhóm
    assert sel("WZH-1", ["T1190"], ["web"], ["legacy_WEB-001"]) == "PB-T"                 # kỹ thuật thắng nhóm
    assert sel("WZH-1", [], ["web"], ["siem", "legacy_WEB-001"]) == "PB-G"                # nhóm thắng tag
    assert cp.select("WZH-1", [], ["web"], ["siem"])[0]["id"] == "PB-TAG"
    assert cp.select("WZH-1", [], [], ["legacy_WEB-001"])[1] == "nhóm legacy_WEB-001"


def test_real_case_playbook_by_legacy_group():
    cp = CasePlaybooks(ROOT / "config" / "case_playbooks.yml")
    assert cp.select("WZH-104004", [], [], ["siem", "web", "legacy_WEB-004"])[0]["id"] == "PB-02"
    assert cp.select("WZH-102004", [], [], ["siem", "linux", "legacy_LNX-004"])[0]["id"] == "PB-14"
    assert cp.select("WZH-5712", [], [], ["authentication_failures"])[0]["id"] == "PB-01"


def test_every_playbook_rule_id_exists_in_repo_xml():
    xml_ids = {m for f in RULES_XML.glob("*.xml") for m in re.findall(r'<rule id="(\d+)"', f.read_text(encoding="utf-8"))}
    pbs = yaml.safe_load((ROOT / "config" / "playbooks.yml").read_text(encoding="utf-8"))["playbooks"]
    explicit = {i[4:] for p in pbs for i in (p.get("when") or {}).get("rule_ids", []) if re.fullmatch(r"WZH-\d+", str(i))}
    stock = {"5712", "5720", "5763", "31152"}          # rule gốc đã duyệt (R60), không nằm trong repo
    assert explicit and explicit - stock <= xml_ids, sorted(explicit - stock - xml_ids)
    assert not stock & xml_ids


def _xml_rules():
    out = []
    for f in sorted(RULES_XML.glob("*.xml")):
        for m in re.finditer(r'<rule id="(\d+)"[^>]*>(.*?)</rule>', f.read_text(encoding="utf-8"), re.S):
            if g := re.search(r"<group>(.*?)</group>", m.group(2)):
                out.append((m.group(1), [x.strip() for x in g.group(1).split(",") if x.strip()]))
    return out


@pytest.mark.parametrize("rid,groups", [r for r in _xml_rules() if any(g.startswith("legacy_") for g in r[1])])
def test_xml_twin_gets_same_case_playbook_as_yaml_code(rid, groups):
    cp = CasePlaybooks(ROOT / "config" / "case_playbooks.yml")
    a = alert_builder.from_wazuh({"@timestamp": "2026-11-04T00:00:00+00:00", "event": {"id": "e"},
                                  "wazuh": {"rule": {"id": rid, "level": 10, "groups": groups}}}, "high")
    code = a["rule"]["legacy_id"]
    got = cp.select(a["rule"]["id"], [], a["rule"]["tags"], a["rule"]["groups"], a["rule"]["legacy_ids"])[0]["id"]
    assert got == cp.select(code)[0]["id"], (rid, code)


# nhóm của rule gốc dùng trong cấu hình (stock-groups-soar.txt, manager 4.14.8)
STOCK_GROUPS = {"authentication_failures", "sql_injection", "web_scan", "attack"}


def test_every_configured_group_exists_somewhere():
    known = {g for _, gs in _xml_rules() for g in gs} | STOCK_GROUPS
    used = set()
    for name, key in (("playbooks.yml", "playbooks"), ("case_playbooks.yml", "playbooks")):
        for p in yaml.safe_load((ROOT / "config" / name).read_text(encoding="utf-8"))[key]:
            used |= set((p.get("when") or p).get("groups") or [])
    dead = {g for g in used if not any(re.fullmatch(g.replace("*", ".*"), k) for k in known)}
    assert used and not dead, dead


def test_destructive_playbooks_match_explicit_rule_ids_only() -> None:
    """R60: hành động phá hủy chỉ theo id rule cụ thể — không theo nhóm, không mẫu `*` / `WZH-*` (nhóm Wazuh như
    authentication_failures kéo theo hàng chục rule gốc có srcip là proxy / relay / NAT). Mẫu mã YAML của dự án
    (vd `WEB-*`) vẫn được: chỉ khớp rule viết tay, bỏ cùng rule YAML ở Task 18."""
    pbs = yaml.safe_load((ROOT / "config" / "playbooks.yml").read_text(encoding="utf-8"))["playbooks"]
    destructive = [p for p in pbs if {s["action"] for s in p["steps"]} & {"block_ip", "kill_process", "isolate_host"}]
    assert destructive
    for p in destructive:
        when = p.get("when") or {}
        assert not when.get("groups"), p["name"]
        assert when.get("rule_ids") and not any(r == "*" or (r.startswith("WZH-") and "*" in r)
                                                for r in when["rule_ids"]), p["name"]
