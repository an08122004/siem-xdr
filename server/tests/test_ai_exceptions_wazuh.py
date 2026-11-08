"""Task 23 (R73): ngoại lệ AI cho rule Wazuh ồn — nguồn từ alert WZH-<id> báo nhầm, duyệt qua wazuh_exceptions."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from siem import wazuh_exceptions
from siem.ai import deploy, prompts
from siem.ai.dataset import RuleEvidence
from siem.ai.golden import PublicDatasets
from siem.ai.llm import LLMResult
from siem.ai.prompts import EXCEPTION_FIELDS
from siem.ai.validate import validate_exception_wazuh
from siem.ai.worker import AIWorker
from test_ai import FakeDS, PropES


def doc(user="x", ip="10.0.0.1"):
    return {"user": {"name": user}, "source": {"ip": ip}, "event": {"id": f"{user}-{ip}"}}


def fp(n, user="svc_backup"):
    return RuleEvidence(fp=[doc(user)] * n, fp_alert_ids=[f"a{i}" for i in range(n)])


class LLM:
    model = "fake"

    def chat_json(self, system, user, schema, temperature=0.2):
        self.user = user
        return LLMResult(data={"rationale": "tài khoản sao lưu", "conditions": [{"field": "user.name", "value": "svc_backup"}]},
                         raw="{}", model="fake", seconds=0.1, prompt_tokens=1, output_tokens=1)


def check(v, name):
    return next(c for c in v.checks if c.name == name)


def test_noisy_targets_come_from_wazuh_evidence():
    saved = []
    ev = {"WZH-5710": fp(5), "WZH-31103": fp(1), "T-001": fp(9)}          # ít báo nhầm / rule YAML: bỏ qua
    AIWorker(None, LLM(), PublicDatasets(directory=Path(".")), ds_factory=lambda es: FakeDS(ev, []),
             save=saved.append).run_cycle("an")
    assert [p["target"] for p in saved if p["kind"] == "exception"] == ["exception:WZH-5710"]
    p = saved[0]
    assert p["required_approvals"] == 1 and p["status"] == "pending"
    assert p["proposal"] == {"rule": "WZH-5710", "conditions": [{"field": "user.name", "value": "svc_backup"}],
                             "reason": "tài khoản sao lưu"}


def test_exact_case_sensitive_match():
    v = validate_exception_wazuh("WZH-5710", [{"field": "user.name", "value": "svc_backup"}],
                                 fp=[doc("svc_backup")] * 4 + [doc("SVC_BACKUP")], tp=[], recent=[])
    assert check(v, "khớp báo nhầm").ok and "4/5" in check(v, "khớp báo nhầm").detail
    v = validate_exception_wazuh("WZH-5710", [{"field": "user.name", "value": "svc_backup"}],
                                 fp=[doc("SVC_BACKUP")] * 3, tp=[], recent=[])
    assert not check(v, "khớp báo nhầm").ok


def test_condition_that_hits_true_positive_fails():
    v = validate_exception_wazuh("WZH-5710", [{"field": "user.name", "value": "root"}],
                                 fp=[doc("root")] * 3, tp=[doc("root")], recent=[])
    assert not v.passed and not check(v, "không chặn alert đúng").ok


def test_unmappable_field_is_invalid():
    v = validate_exception_wazuh("WZH-5710", [{"field": "process.parent.name", "value": "x"}], fp=[doc()] * 3, tp=[], recent=[])
    assert not check(v, "ánh xạ được sang Wazuh").ok and not v.passed


def test_repeated_field_and_recent_estimate():
    conds = [{"field": "user.name", "value": "a"}, {"field": "user.name", "value": "b"}]
    assert not check(validate_exception_wazuh("WZH-1", conds, [doc("a")] * 3, [], []), "mỗi trường một lần").ok
    v = validate_exception_wazuh("WZH-1", conds[:1], [doc("a")] * 3, [], [doc("a"), doc("b")])
    assert v.passed and "1/2" in check(v, "ước lượng alert bị chặn").detail and not check(v, "ước lượng alert bị chặn").blocking


class Env:
    api = object()

    def __init__(self):
        self.es = PropES({})

    def pending(self, **kw):
        self.es.doc = {"id": "0123456789ab", "status": "pending", "approvals": [], "required_approvals": 1, "updated_at": "",
                       "proposal": {"rule": "WZH-5710", "conditions": [{"field": "user.name", "value": "svc_backup"}],
                                    "reason": "sao lưu"}} | kw
        return self.es.doc


def test_approve_exception_creates_pending_wazuh_exception(monkeypatch):
    env, calls = Env(), []
    monkeypatch.setattr(wazuh_exceptions, "add", lambda *a, **k: calls.append((a, k)) or {"id": 110003, "status": "pending"})
    out = deploy.approve(env.es, env.pending(kind="exception", target="exception:WZH-5710")["id"], "an", env.api, now="t")
    a = calls[0][0]
    assert a[0] == "WZH-5710" and a[3] == "an" and a[4] is env.api and out["exception_id"] == 110003
    assert out["status"] == "approved"


def test_approve_exception_maps_wazuh_errors(monkeypatch):
    env = Env()

    def dup(*a, **k):
        raise wazuh_exceptions.Duplicate("trùng")
    monkeypatch.setattr(wazuh_exceptions, "add", dup)
    with pytest.raises(deploy.DeployError) as e:
        deploy.approve(env.es, env.pending(kind="exception", target="exception:WZH-5710")["id"], "an", env.api)
    assert e.value.code == 409 and env.es.doc["status"] == "pending"


def test_rollback_exception_removes_it(monkeypatch):
    env, calls = Env(), []
    monkeypatch.setattr(wazuh_exceptions, "remove", lambda *a, **k: calls.append(a) or {})
    env.pending(kind="exception", status="approved", exception_id=110003)
    deploy.rollback(env.es, "0123456789ab", "an", "lý do", env.api, now="t")
    assert calls == [(110003, "an", "lý do", env.api)] and env.es.doc["status"] == "rolled_back"


def test_prompt_lists_only_mappable_fields():
    assert set(re.findall(r"`([a-z_.]+)`", prompts.exception_fields_text())) == set(EXCEPTION_FIELDS)
