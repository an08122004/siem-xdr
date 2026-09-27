"""Test phần AI hỗ trợ viết rule: ngoại lệ, kiểm định, worker (LLM giả lập), duyệt/gỡ.
Không cần Ollama / Elasticsearch."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from siem.ai import deploy
from siem.ai.dataset import EventGroup, RuleEvidence
from siem.ai.golden import Labeled, PublicDatasets
from siem.ai.llm import LLMResult
from siem.ai.validate import build_condition, scope_match, validate_exception, validate_new_rule
from siem.ai.worker import AIWorker
from siem.detection.rules import Rule, RuleEngine, load_rules, regex_risk, rules_fingerprint

T0 = datetime(2026, 9, 1, tzinfo=timezone.utc)

RULE_LOGIN = {
    "id": "T-001", "title": "Đăng nhập admin thất bại", "severity": "medium", "type": "match",
    "condition": {"all": [{"field": "event.category", "op": "eq", "value": "web"},
                          {"field": "url.path", "op": "eq", "value": "/admin/login"},
                          {"field": "http.response.status_code", "op": "eq", "value": 401}]},
}
RULE_BURST = {
    "id": "T-002", "title": "Nhiều lỗi 401", "severity": "medium", "type": "threshold",
    "condition": {"all": [{"field": "event.category", "op": "eq", "value": "web"},
                          {"field": "http.response.status_code", "op": "eq", "value": 401}]},
    "threshold": {"count": 3, "window": 60, "group_by": ["source.ip"]},
}


def ev(ip, path="/admin/login", status=401, sec=0, ua="Mozilla/5.0", i=0):
    return {"@timestamp": (T0 + timedelta(seconds=sec)).isoformat(), "event": {"id": f"e{ip}-{sec}-{i}", "category": "web",
            "module": "apache"}, "source": {"ip": ip}, "url": {"path": path}, "http": {"response": {"status_code": status}},
            "user_agent": {"original": ua}, "agent": {"id": "web-01"}}


def write_rules(tmp: Path, rules=(RULE_LOGIN, RULE_BURST)) -> Path:
    import yaml
    (tmp / "rules").mkdir(exist_ok=True)
    (tmp / "rules" / "base.yml").write_text(yaml.safe_dump(list(rules), allow_unicode=True), encoding="utf-8")
    for d in ("ai", "exceptions"):
        (tmp / "rules" / d).mkdir(exist_ok=True)
    return tmp / "rules"


# ------------------------------------------------------------------ rule engine: ngoại lệ
def test_exceptions_loaded_and_applied(tmp_path):
    rd = write_rules(tmp_path)
    (rd / "exceptions" / "x.yml").write_text(
        "- id: EXC-1\n  rule_id: T-002\n  condition: {field: source.ip, op: cidr, value: 10.9.0.0/16}\n"
        "- id: EXC-2\n  rule_id: KHONG-CO\n  condition: {field: source.ip, op: eq, value: 1.1.1.1}\n", encoding="utf-8")
    rules = {r.id: r for r in load_rules(rd)}
    assert [e.id for e in rules["T-002"].exceptions] == ["EXC-1"] and not rules["T-001"].exceptions
    eng = RuleEngine(list(rules.values()))
    scanner = [d for i in range(5) for d in eng.process(ev("10.9.1.1", "/x", sec=i))]
    other = [d for i in range(5) for d in eng.process(ev("10.1.1.1", "/x", sec=i))]
    assert scanner == [] and [d.rule.id for d in other] == ["T-002"]


def test_rules_fingerprint_changes(tmp_path):
    rd = write_rules(tmp_path)
    fp1 = rules_fingerprint(rd)
    (rd / "exceptions" / "new.yml").write_text("[]", encoding="utf-8")
    assert rules_fingerprint(rd) != fp1


def test_regex_guard():
    assert regex_risk("(a+)+$") and regex_risk("x" * 400) and regex_risk("([")
    assert regex_risk(r"^/admin/(login|logout)$") is None


def test_scope_match():
    r = Rule.from_dict(RULE_LOGIN)
    assert scope_match(r, ev("1.1.1.1", "/khac", 200))          # cùng loại event web -> rule có xem xét
    assert not scope_match(r, {"event": {"category": "authentication"}})


# ------------------------------------------------------------------ kiểm định ngoại lệ
def _exc(clauses, match="all"):
    return {"id": "EXC-t", "rule_id": "T-001", "condition": build_condition(match, clauses)}


def test_exception_good_passes():
    rule = Rule.from_dict(RULE_LOGIN)
    fp = [ev("10.50.0.7", sec=i) for i in range(5)]           # máy giám sát nội bộ, bị báo nhầm
    tp = [ev("203.0.113.9", sec=i) for i in range(3)]         # case đã xác nhận thật
    replay_ev = fp + tp
    v = validate_exception(rule, _exc([{"field": "source.ip", "op": "eq", "value": "10.50.0.7"}]), fp, tp, None, replay_ev)
    assert v.passed, [c for c in v.checks if not c.ok]
    assert v.metrics["tp_matched"] == 0 and v.metrics["fp_matched"] == 5 and v.metrics["alerts_after"] < v.metrics["alerts_before"]


def test_exception_suppressing_true_positive_is_blocked():
    rule = Rule.from_dict(RULE_LOGIN)
    fp = [ev("10.50.0.7")]
    tp = [ev("10.50.0.8")]
    v = validate_exception(rule, _exc([{"field": "source.ip", "op": "cidr", "value": "10.50.0.0/24"}]), fp * 3, tp, None, fp + tp)
    assert not v.passed and any(c.name == "không tắt sự cố thật" and not c.ok for c in v.checks)


def test_exception_too_broad_or_fake_field_blocked():
    rule = Rule.from_dict(RULE_LOGIN)
    fp = [ev("10.50.0.7")] * 3
    broad = validate_exception(rule, _exc([{"field": "event.category", "op": "eq", "value": "web"}]), fp, [], None, fp)
    assert not broad.passed and any(c.name == "đủ hẹp" and not c.ok for c in broad.checks)
    fake = validate_exception(rule, _exc([{"field": "khong.ton.tai", "op": "eq", "value": "x"}]), fp, [], None, fp)
    assert not fake.passed and any(c.name == "trường có thật" and not c.ok for c in fake.checks)
    assert fake.risk == "cao"  # không có case thật / mẫu vàng để đối chứng


def test_exception_must_keep_golden_samples():
    rule = Rule.from_dict(RULE_LOGIN)
    golden = PublicDatasets(directory=Path("."), attack=[Labeled(ev("198.51.100.1"), {"dataset": "t"})])
    fp = [ev("198.51.100.1")] * 3
    v = validate_exception(rule, _exc([{"field": "source.ip", "op": "eq", "value": "198.51.100.1"}]), fp, [], golden, fp)
    assert not v.passed and any(c.name == "giữ bộ mẫu vàng" and not c.ok for c in v.checks)


# ------------------------------------------------------------------ kiểm định rule mới
def _new(clauses):
    return {"id": "AI-001", "title": "t", "severity": "medium", "type": "match", "condition": build_condition("all", clauses)}


def test_new_rule_validation():
    susp = [ev(f"10.2.0.{i}", "/admin/backup.zip", 200, sec=i) for i in range(10)]
    normal = [ev(f"10.3.0.{i}", "/index.html", 200, sec=i) for i in range(50)]
    good = validate_new_rule(_new([{"field": "url.path", "op": "endswith", "value": ".zip"}]), [],
                             susp[:5], susp[5:], normal, normal, 20)
    assert good.passed and good.metrics["test_recall"] == 1.0 and good.metrics["normal_hits"] == 0
    noisy = validate_new_rule(_new([{"field": "http.response.status_code", "op": "eq", "value": 200}]), [],
                              susp[:5], susp[5:], normal, normal, 20)
    assert not noisy.passed and any(c.name == "báo nhầm trên dữ liệu bình thường" and not c.ok for c in noisy.checks)
    useless = validate_new_rule(_new([{"field": "url.path", "op": "eq", "value": "/khong-co"}]), [],
                                susp[:5], susp[5:], normal, normal, 20)
    assert not useless.passed and any(c.name == "bắt mẫu nghi vấn" and not c.ok for c in useless.checks)


# ------------------------------------------------------------------ worker với LLM giả lập
class FakeLLM:
    model = "fake"

    def __init__(self, answers):
        self.answers = answers
        self.prompts = []

    def chat_json(self, system, user, schema, temperature=0.2):
        self.prompts.append(user)
        data = self.answers["exception" if "Propose the exception" in user else "new_rule"]
        return LLMResult(data=data, raw="{}", model="fake", seconds=0.1, prompt_tokens=10, output_tokens=5)


class FakeDS:
    def __init__(self, evidence, events, groups=(), history=()):
        self._e, self._ev, self._g, self._h = evidence, events, list(groups), list(history)

    def evidence(self):
        return self._e

    def replay_events(self):
        return self._ev

    def event_groups(self, min_count):
        return self._g

    def proposals(self, statuses=None, since="", size=500):
        return self._h


def test_worker_cycle_creates_validated_proposals(tmp_path, monkeypatch):
    rd = write_rules(tmp_path)
    monkeypatch.setattr("siem.ai.worker.settings.RULES_DIR", rd)
    fp = [ev("10.50.0.7", sec=i) for i in range(4)]
    evidence = {"T-001": RuleEvidence(fp=fp, tp=[ev("203.0.113.9")], fp_alert_ids=["a1", "a2", "a3", "a4"])}
    golden = PublicDatasets(directory=Path("."),
                            attack=[Labeled(ev(f"10.7.0.{i}", "/admin/backup.zip", 200, i=i), {"dataset": "t"}) for i in range(20)],
                            normal=[Labeled(ev(f"10.8.0.{i}", "/admin/backup.zip", 404, i=i), {"class": "normal"}) for i in range(20)])
    llm = FakeLLM({
        "exception": {"rationale": "máy giám sát", "match": "all", "clauses": [{"field": "source.ip", "op": "eq", "value": "10.50.0.7"}]},
        "new_rule": {"propose": True, "rationale": "tải file backup", "title": "Tải file sao lưu", "description": "d",
                     "severity": "high", "mitre_tactic": "Collection", "mitre_technique": ["t1005", "SQLi", "Cross-Site"], "match": "all",
                     "clauses": [{"field": "url.path", "op": "endswith", "value": ".zip"},
                                 {"field": "http.response.status_code", "op": "eq", "value": 200}]},
    })
    saved = []
    w = AIWorker(None, llm, golden, rules_dir=rd, ds_factory=lambda es: FakeDS(evidence, fp), save=saved.append)
    summary = w.run_cycle("an")
    kinds = {p["kind"]: p for p in saved}
    assert kinds["exception"]["status"] == "pending" and kinds["exception"]["required_approvals"] == 2
    nr = kinds["new_rule"]
    assert nr["status"] == "pending", nr["validation"]["checks"]
    assert nr["proposal"]["id"] == "AI-001" and nr["proposal"]["severity"] == "medium"   # AI không được đặt high
    assert nr["proposal"]["mitre"]["technique"] == ["T1005"]                              # bỏ tên kỹ thuật tự do
    assert nr["validation"]["metrics"]["test_is_holdout"] is True
    assert "DATA:" in llm.prompts[0] and len(summary["created"]) == 2


# ------------------------------------------------------------------ duyệt / triển khai / gỡ
class PropES:
    def __init__(self, doc):
        self.doc, self.seq = doc, 1

    def get(self, index, id):
        return {"_source": dict(self.doc), "_seq_no": self.seq, "_primary_term": 1}

    def index(self, index, id, document, if_seq_no=None, **_):
        if if_seq_no is not None and if_seq_no != self.seq:
            raise RuntimeError("conflict")
        self.doc, self.seq = document, self.seq + 1


def test_approve_two_person_then_rollback(tmp_path, monkeypatch):
    rd = write_rules(tmp_path)
    monkeypatch.setattr(deploy, "golden", lambda: PublicDatasets(directory=Path(".")))
    monkeypatch.setattr(deploy.ESDataSource, "evidence", lambda self: {})
    exc = {"id": "EXC-abc", "rule_id": "T-001", "condition": {"all": [{"field": "source.ip", "op": "eq", "value": "10.50.0.7"}]}}
    es = PropES({"id": "0123456789ab", "kind": "exception", "target_rule_id": "T-001", "proposal": exc, "status": "pending",
                 "required_approvals": 2, "approvals": [], "llm": {"model": "fake"}, "updated_at": ""})
    p = deploy.approve(es, "0123456789ab", "an", rd, now="t1")
    assert p["status"] == "pending" and not list((rd / "exceptions").glob("*.yml"))
    with pytest.raises(deploy.DeployError):
        deploy.approve(es, "0123456789ab", "AN", rd, now="t2")        # cùng người không duyệt 2 lần
    p = deploy.approve(es, "0123456789ab", "binh", rd, now="t3")
    f = rd / "exceptions" / "0123456789ab.yml"
    assert p["status"] == "approved" and f.exists()
    assert [e.id for e in {r.id: r for r in load_rules(rd)}["T-001"].exceptions] == ["EXC-abc"]
    deploy.rollback(es, "0123456789ab", "an", "thử", rd, now="t4")
    assert not f.exists() and es.doc["status"] == "rolled_back"


def test_approve_blocked_when_new_true_positive(tmp_path, monkeypatch):
    rd = write_rules(tmp_path)
    monkeypatch.setattr(deploy, "golden", lambda: PublicDatasets(directory=Path(".")))
    monkeypatch.setattr(deploy.ESDataSource, "evidence",
                        lambda self: {"T-001": RuleEvidence(tp=[ev("10.50.0.7")])})   # case thật vừa được xác nhận
    exc = {"id": "EXC-x", "rule_id": "T-001", "condition": {"all": [{"field": "source.ip", "op": "eq", "value": "10.50.0.7"}]}}
    es = PropES({"id": "aaaaaaaaaaaa", "kind": "exception", "target_rule_id": "T-001", "proposal": exc, "status": "pending",
                 "required_approvals": 1, "approvals": [], "updated_at": ""})
    with pytest.raises(deploy.DeployError):
        deploy.approve(es, "aaaaaaaaaaaa", "an", rd, now="t")
    assert es.doc["status"] == "invalid" and not list((rd / "exceptions").glob("*.yml"))


def test_invalid_proposal_id_rejected():
    with pytest.raises(deploy.DeployError):
        deploy.approve(PropES({}), "../../etc", "an", Path("."))


# ------------------------------------------------------------------ gom nhóm theo loại tấn công
def web(url, i=0, ip="10.9.0.1"):
    """Event web đi qua đúng bộ chuẩn hóa thật (như dataset CSIC sau convert_datasets.py)."""
    from siem.pipeline.normalize import normalize
    line = f'{ip} - - [01/Sep/2026:00:00:{i % 60:02d} +0000] "GET {url} HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
    return normalize({"timestamp": (T0 + timedelta(seconds=i)).isoformat(), "agent_id": "t", "hostname": "shop",
                      "os": "linux", "source": "file", "event_type": "apache_access", "data": {"message": line}})


NORMAL_URLS = ["/shop/add.jsp?id=1&qty=2", "/shop/login.jsp?user=an&pwd=abc123", "/shop/img/logo.gif", "/shop/"]


def test_classify_web_attack_types():
    from siem.ai.attack_types import WebProfile, classify_web
    prof = WebProfile.build([web(u) for u in NORMAL_URLS])
    cases = {
        "/shop/add.jsp?id=%3C%21--%23exec+cmd%3D%22ls%22--%3E": "ssi",
        "/shop/add.jsp?id=1%0D%0ASet-cookie%3A+x%3D1": "crlf",
        "/shop/add.jsp?id=%3Cscript%3Ealert(1)%3C%2Fscript%3E": "xss",
        "/shop/add.jsp?id=1&qty=2+AND+1%3D1": "sqli",
        "/shop/add.jsp?id=%253F": "encoding-evasion",
        "/shop/img/logo.gif.BAK": "backup-file",
        "/shop/img/logo.gif~": "backup-file",
        "/_vti_bin/admin.dll": "sensitive-path",
        "/shop/add.jsp?idA=1&qty=2": "unknown-param",
        "/shop/add.jsp/xyz": "unknown-resource",
        "/shop/add.jsp?id=1/&qty=2": "invalid-value",
    }
    got = {u: classify_web(web(u), prof) for u in cases}
    assert got == cases
    assert {"shop", "add.jsp", "login.jsp", "logo.gif"} <= prof.app_tokens()


def test_dataset_gaps_grouped_by_type_and_app_specific_skipped(tmp_path, monkeypatch):
    rd = write_rules(tmp_path)
    monkeypatch.setattr("siem.ai.worker.settings.RULES_DIR", rd)
    attack = [web(f"/shop/img/logo{i}.gif.bak", i) for i in range(12)] + \
             [web(f"/shop/add.jsp?idA={i}&qty=2", i) for i in range(12)]
    golden = PublicDatasets(directory=Path("."), attack=[Labeled(d, {"dataset": "t"}) for d in attack],
                            normal=[Labeled(web(u, i), {"class": "normal"}) for i, u in enumerate(NORMAL_URLS * 5)])
    llm = FakeLLM({"new_rule": {"propose": True, "rationale": "file sao lưu", "title": "Dò file .bak", "description": "d",
                                "severity": "medium", "mitre_tactic": "Discovery", "mitre_technique": ["T1083"],
                                "match": "all", "clauses": [{"field": "url.path", "op": "endswith", "value": ".bak"}]}})
    saved = []
    w = AIWorker(None, llm, golden, rules_dir=rd, ds_factory=lambda es: FakeDS({}, []), save=saved.append)
    summary = w.run_cycle("an")
    assert [p["target"] for p in saved] == ["gap-dataset:t:backup-file"]
    assert saved[0]["status"] == "pending", saved[0]["validation"]["checks"]
    assert "backup-file" in saved[0]["proposal"]["tags"]
    assert any(s.startswith("gap-dataset:t:unknown-param: 12 mẫu") for s in summary["skipped"])
    assert "Attack type: Probing for backup" in llm.prompts[0]


def test_new_rule_tied_to_dataset_app_blocked():
    susp = [web(f"/shop/img/logo{i}.gif.bak", i) for i in range(10)]
    normal = [web(u, i) for i, u in enumerate(NORMAL_URLS * 5)]
    tokens = {"shop", "img", "logo.gif"}
    tied = validate_new_rule(_new([{"field": "url.path", "op": "startswith", "value": "/shop/img/"}]), [],
                             susp[:5], susp[5:], normal, [], 20, app_tokens=tokens)
    assert not tied.passed and any(c.name == "dùng chung được" and not c.ok for c in tied.checks)
    generic = validate_new_rule(_new([{"field": "url.path", "op": "regex", "value": r"\.(bak|old)$"}]), [],
                                susp[:5], susp[5:], normal, [], 20, app_tokens=tokens | {"global"})
    assert generic.passed, generic.checks


def test_retry_policy_depends_on_generator(tmp_path, monkeypatch):
    """Kiểm định loại -> chỉ chặn thử lại khi cùng model + prompt; người từ chối -> luôn chặn 30 ngày."""
    from siem.ai.worker import generator_id
    rd = write_rules(tmp_path)
    monkeypatch.setattr("siem.ai.worker.settings.RULES_DIR", rd)
    attack = [web(f"/shop/img/logo{i}.gif.bak", i) for i in range(12)]
    golden = PublicDatasets(directory=Path("."), attack=[Labeled(d, {"dataset": "t"}) for d in attack],
                            normal=[Labeled(web(u, i), {"class": "normal"}) for i, u in enumerate(NORMAL_URLS * 5)])
    llm = FakeLLM({"new_rule": {"propose": True, "rationale": "r", "title": "t", "description": "d", "severity": "low",
                                "mitre_tactic": "Discovery", "mitre_technique": [], "match": "all",
                                "clauses": [{"field": "url.path", "op": "endswith", "value": ".bak"}]}})
    target = "gap-dataset:t:backup-file"

    def run(history):
        saved = []
        AIWorker(None, llm, golden, rules_dir=rd, ds_factory=lambda es: FakeDS({}, [], history=history),
                 save=saved.append).run_cycle("an")
        return [p["target"] for p in saved]

    assert run([{"target": target, "status": "invalid", "llm": {"generator": "prompt-cu"}}]) == [target]
    assert run([{"target": target, "status": "invalid", "llm": {"generator": generator_id("fake")}}]) == []
    assert run([{"target": target, "status": "rejected", "reject_reason": "không cần", "llm": {"generator": "khac"}}]) == []
