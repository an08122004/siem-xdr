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

    def chat_json(self, system, user, schema, temperature=0.2):        # ngoại lệ: JSON theo schema
        self.prompts.append(user)
        return LLMResult(data=self.answers["exception"], raw="{}", model="fake", seconds=0.1, prompt_tokens=10,
                         output_tokens=5)

    def chat_text(self, system, user, temperature=0.2):                 # rule mới: rule Sigma dạng YAML
        self.prompts.append(user)
        return LLMResult(data={}, raw=self.answers["new_rule"], model="fake", seconds=0.1, prompt_tokens=10,
                         output_tokens=5)


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
        # model viết thêm lời dẫn ngoài khối yaml; level high; tag attack.* có cả tên tự do
        "new_rule": "Đây là rule:\n```yaml\ntitle: Tải file sao lưu\ndescription: tải file backup\nlevel: high\n"
                    "tags: [attack.collection, attack.t1005, attack.sqli-thing, attack.T1005]\n"
                    "logsource: {category: webserver}\ndetection:\n  selection:\n    cs-uri-stem|endswith: '.zip'\n"
                    "    sc-status: 200\n  condition: selection\n```\n",
    })
    saved = []
    w = AIWorker(None, llm, golden, rules_dir=rd, ds_factory=lambda es: FakeDS(evidence, fp), save=saved.append)
    summary = w.run_cycle("an")
    kinds = {p["kind"]: p for p in saved}
    assert kinds["exception"]["status"] == "pending" and kinds["exception"]["required_approvals"] == 2
    nr = kinds["new_rule"]
    assert nr["status"] == "pending", nr["validation"]["checks"]
    assert nr["proposal"]["id"] == "AI-001" and nr["proposal"]["severity"] == "medium"   # AI không được đặt high
    assert nr["proposal"]["mitre"] == {"tactic": "collection", "technique": ["T1005"]}   # chỉ giữ ID ATT&CK thật
    assert nr["validation"]["metrics"]["test_is_holdout"] is True
    # vế AND (đường dẫn .zip + mã 200) giữ nguyên: request bình thường cùng đường dẫn trả 404
    assert nr["proposal"]["condition"]["all"][1] == {"field": "http.response.status_code", "op": "eq", "value": 200}
    assert "sc-status: 200" in nr["sigma"] and "level: medium" in nr["sigma"] and "sigma: |" not in nr["yaml"]
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
    llm = FakeLLM({"new_rule": "title: Dò file .bak\nlevel: medium\nlogsource: {category: webserver}\ndetection:\n  sel:\n    cs-uri-stem|endswith: '.bak'\n  condition: sel\n"})
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
    llm = FakeLLM({"new_rule": "title: Dò file .bak\nlevel: medium\nlogsource: {category: webserver}\ndetection:\n  sel:\n    cs-uri-stem|endswith: '.bak'\n  condition: sel\n"})
    target = "gap-dataset:t:backup-file"

    def run(history):
        saved = []
        AIWorker(None, llm, golden, rules_dir=rd, ds_factory=lambda es: FakeDS({}, [], history=history),
                 save=saved.append).run_cycle("an")
        return [p["target"] for p in saved]

    assert run([{"target": target, "status": "invalid", "llm": {"generator": "prompt-cu"}}]) == [target]
    assert run([{"target": target, "status": "invalid", "llm": {"generator": generator_id("fake")}}]) == []
    assert run([{"target": target, "status": "rejected", "reject_reason": "không cần", "llm": {"generator": "khac"}}]) == []


# ------------------------------------------------------------------ biến thể, ghép mẫu, URL thông thường
def test_sqli_variants_stray_quote_and_path_variants():
    from siem.ai.attack_types import WebProfile, inspect_web
    prof = WebProfile.build([web(u) for u in NORMAL_URLS])
    cases = {
        "/shop/login.jsp?user=%27OR%27a%27%3D%27a&pwd=x": ("sqli", "tautology-quoted"),
        "/shop/add.jsp?id=1%27&qty=2": ("sqli", "quote-breakout"),
        "/shop/login.jsp?user=D%27estats&pwd=abc123": ("invalid-value", "/shop/login.jsp"),  # nháy trong tên riêng
        "/_vti_bin/admin.dll": ("sensitive-path", "/_vti_bin/"),
        "/admin4.nsf": ("sensitive-path", "extension .nsf"),
    }
    got = {u: (m.kind, m.variant) for u in cases for m in [inspect_web(web(u), prof)]}
    assert got == cases
    x = Labeled(web("/shop/add.jsp?id=%27INJECTED_PARAM&qty=2"), {"dataset": "t"})
    g = PublicDatasets(directory=Path("."), attack=[x], normal=[Labeled(web(u), {"class": "normal"}) for u in NORMAL_URLS])
    assert g.attack_type(x) == "sqli" and "id='&qty" in g.evidence(x, "window")   # bỏ chuỗi giữ chỗ của dataset
    assert g.evidence(x, "param") == "id='"


def test_diverse_largest_groups_first_then_proportional():
    from siem.ai.worker import diverse
    items = [("z", i) for i in range(6)] + [("a", 0)] + [("m", i) for i in range(3)]
    assert [g for g, _ in diverse(items, 2, key=lambda x: x[0])] == ["z", "m"]           # không theo bảng chữ cái
    assert [g for g, _ in diverse(items, 5, key=lambda x: x[0])] == ["z", "m", "a", "z", "z"]


class SeqLLM:
    """LLM giả lập trả lần lượt từng câu trả lời."""
    model = "fake"

    def __init__(self, answers):
        self.answers, self.prompts = list(answers), []

    def chat_json(self, system, user, schema, temperature=0.2):
        self.prompts.append(user)
        return LLMResult(data=self.answers.pop(0), raw="{}", model="fake", seconds=0.1, prompt_tokens=1, output_tokens=1)

    def chat_text(self, system, user, temperature=0.2):
        self.prompts.append(user)
        return LLMResult(data={}, raw=self.answers.pop(0), model="fake", seconds=0.1, prompt_tokens=1, output_tokens=1)


def test_dataset_rule_assembled_from_measured_patterns(tmp_path, monkeypatch):
    """Giữ vế Sigma bắt được tấn công ở tập train mà không khớp request bình thường; lượt sau hỏi riêng biến thể còn sót."""
    rd = write_rules(tmp_path)
    monkeypatch.setattr("siem.ai.worker.settings.RULES_DIR", rd)
    monkeypatch.setattr("siem.ai.worker.settings.AI_KNOWLEDGE_ROUND", False)   # test riêng ở test_ai_endpoint
    attack = [web(f"/shop/img/a{i:02d}.gif.bak", i) for i in range(12)] + \
             [web(f"/shop/img/b{i:02d}.gif.old", i) for i in range(12)]
    golden = PublicDatasets(directory=Path("."), attack=[Labeled(d, {"dataset": "t"}) for d in attack],
                            normal=[Labeled(web(u, i), {"class": "normal"}) for i, u in enumerate(NORMAL_URLS * 5)])
    llm = SeqLLM([
        # "/shop/" gắn với ứng dụng mẫu -> loại; "/" khớp URL thư mục bình thường -> loại; ".bak" giữ
        "title: Dò file sao lưu\nlevel: low\nlogsource: {category: webserver}\ndetection:\n"
        "  selection_app:\n    cs-uri-stem|contains: '/shop/'\n"
        "  selection_bak:\n    cs-uri-stem|endswith: '.bak'\n"
        "  selection_dir:\n    cs-uri-stem|endswith: '/'\n"
        "  condition: 1 of selection_*\n",
        "```yaml\ntitle: x\nlogsource: {category: webserver}\ndetection:\n  selection:\n"
        "    cs-uri-stem|endswith: '.old'\n  condition: selection\n```",
    ])
    saved = []
    AIWorker(None, llm, golden, rules_dir=rd, ds_factory=lambda es: FakeDS({}, []), save=saved.append).run_cycle("an")
    p = saved[0]
    assert p["status"] == "pending", p["validation"]["checks"]
    assert p["proposal"]["condition"] == {"any": [{"field": "url.path", "op": "endswith", "value": [".bak", ".old"]},
                                                  {"field": "url.decoded", "op": "endswith", "value": [".bak", ".old"]}]}
    assert "condition: selection_bak_1 or selection_2" in p["sigma"] and "/shop/" not in p["sigma"]
    assert [(a["focus"], a["train_recall"]) for a in p["llm"]["attempts"]] == [(None, 0.5), (".old", 1.0)]
    assert '"variant": ".old (6 training events still missed)"' in llm.prompts[1]
    assert "Probing for backup" not in llm.prompts[1]          # lượt bổ sung không nêu tên loại tấn công
    assert "specific to the sample application" in llm.prompts[1] and "ordinary URLs" in llm.prompts[1]
    assert '"cs-uri-stem|endswith": ".bak"' in llm.prompts[1]   # vế đã giữ đưa lại cho model


def test_new_rule_matching_ordinary_urls_blocked():
    susp = [web(f"/shop/img/{i}/", i) for i in range(10)]
    normal = [web(u, i) for i, u in enumerate(NORMAL_URLS[:3] * 5)]      # tập bình thường không có URL thư mục
    val = validate_new_rule(_new([{"field": "url.path", "op": "endswith", "value": "/"}]), [],
                            susp[:5], susp[5:], normal, [], 20)
    checks = {c.name: c.ok for c in val.checks}
    assert checks["báo nhầm trên dữ liệu bình thường"] and not checks["không khớp URL thông thường"]
    assert not val.passed


def test_thinking_turned_off_only_for_models_that_support_it():
    """qwen3 / qwen3.5 có chế độ suy nghĩ: mặc định gửi think=false; model khác không nhận tham số này."""
    from siem.ai.llm import OllamaClient

    def client(capabilities, think=False):
        c = OllamaClient("http://ollama:11434", "m", think=think)
        sent = []

        def post(path, body, timeout=None):
            sent.append((path, body))
            if path == "/api/show":
                return {"capabilities": capabilities}
            return {"message": {"content": '{"ok": true}'}, "done_reason": "stop"}
        c._post = post
        c.chat_json("s", "u", {"type": "object"})
        return [b for p, b in sent if p == "/api/chat"][0]

    assert client(["completion", "thinking"])["think"] is False
    assert "think" not in client(["completion", "tools"])
    on = client(["completion", "thinking"], think=True)
    assert on["think"] is True and on["options"]["num_predict"] == 4096   # suy nghĩ cần thêm chỗ cho token


def test_too_long_answer_spoils_one_round_not_the_whole_proposal(tmp_path, monkeypatch):
    """Chạy thật 9/10: một câu trả lời vượt giới hạn token ở lượt kiến thức làm hỏng cả đề xuất SQLi."""
    from siem.ai.llm import LLMTooLong
    rd = write_rules(tmp_path)
    monkeypatch.setattr("siem.ai.worker.settings.RULES_DIR", rd)
    attack = [web(f"/shop/img/a{i:02d}.gif.bak", i) for i in range(12)]
    golden = PublicDatasets(directory=Path("."), attack=[Labeled(d, {"dataset": "t"}) for d in attack],
                            normal=[Labeled(web(u, i), {"class": "normal"}) for i, u in enumerate(NORMAL_URLS * 5)])

    class LongLLM(SeqLLM):
        def chat_text(self, system, user, temperature=0.2):
            if len(self.prompts) == 1:                    # lượt kiến thức
                self.prompts.append(user)
                raise LLMTooLong("output vượt 1024 token")
            return super().chat_text(system, user, temperature)

    llm = LongLLM(["detection:\n  sel:\n    cs-uri-stem|endswith: '.bak'\n  condition: sel\n"])
    saved = []
    AIWorker(None, llm, golden, rules_dir=rd, ds_factory=lambda es: FakeDS({}, []), save=saved.append).run_cycle("an")
    assert saved and saved[0]["status"] == "pending", saved
    assert "1024" in " ".join(saved[0]["llm"]["attempts"][1]["rejected"])


def test_web_keeps_no_unverified_sigmahq_atoms(tmp_path, monkeypatch):
    """Chạy thật 9/10: cap=0 bị hiểu là 'mặc định 8' -> rule SQLi mang 30 vế SigmaHQ (CVE) chưa khớp mẫu train nào."""
    rd = write_rules(tmp_path)
    monkeypatch.setattr("siem.ai.worker.settings.RULES_DIR", rd)
    attack = [web(f"/shop/img/a{i:02d}.gif.bak", i) for i in range(12)]
    cve = {"id": "cve-1", "title": "Some CVE probe", "author": "X", "level": "high", "status": "test", "path": "rules/web/x.yml",
           "logsource": {"category": "webserver"}, "tags": ["attack.t1190"],
           "detection": "selection:\n  cs-uri-stem|contains: '/vulnerable/endpoint.php'\ncondition: selection\n"}
    golden = PublicDatasets(directory=Path("."), attack=[Labeled(d, {"dataset": "t"}) for d in attack],
                            normal=[Labeled(web(u, i), {"class": "normal"}) for i, u in enumerate(NORMAL_URLS * 5)],
                            sigma=[cve])
    golden._sigma_tokens = [{"vulnerable", "endpoint", "backup", "probing"}]
    llm = SeqLLM(["detection:\n  sel:\n    cs-uri-stem|endswith: '.bak'\n  condition: sel\n"] * 10)
    saved = []
    AIWorker(None, llm, golden, rules_dir=rd, ds_factory=lambda es: FakeDS({}, []), save=saved.append).run_cycle("an")
    assert saved[0]["status"] == "pending"
    assert not [a for a in saved[0]["llm"]["atoms"] if a["source"] == "sigmahq"]
    assert "cve-1" not in saved[0]["sigma"]


def test_approved_ai_rule_runs_in_shadow_then_promoted(tmp_path, monkeypatch):
    """Rule AI vừa duyệt vào chế độ chạy bóng kèm metadata bắt buộc của kho rule (đạt lint); bật chính thức chỉ khi đủ
    tiêu chí (số ngày, alert/ngày, tỉ lệ báo nhầm), ghi ai bật và số liệu lúc bật."""
    import yaml
    from siem import settings
    from siem.detection.lint import check_rule
    rd = write_rules(tmp_path)
    monkeypatch.setattr(deploy, "golden", lambda: PublicDatasets(directory=Path(".")))
    rule = {"id": "AI-077", "title": "Tải file sao lưu", "severity": "medium", "type": "match",
            "mitre": {"tactic": "collection", "technique": ["T1005"]}, "tags": ["ai-generated", "sigma", "web"],
            "condition": {"all": [{"field": "url.path", "op": "endswith", "value": ".bak"}]},
            "ai_proposal_id": "0123456789ab",
            "sigma": "title: Tải file sao lưu\nlogsource:\n  category: webserver\ndetection:\n  sel:\n"
                     "    cs-uri-stem|endswith: .bak\n  condition: sel\nfalsepositives:\n  - Sao lưu thủ công qua web\n"}
    es = PropES({"id": "0123456789ab", "kind": "new_rule", "target_rule_id": "AI-077", "proposal": rule,
                 "status": "pending", "required_approvals": 1, "approvals": [], "llm": {"model": "fake"},
                 "updated_at": "2026-10-13T10:00:00+00:00"})
    deploy.approve(es, "0123456789ab", "de", rd, now="2026-10-13T10:00:00+00:00")
    f = rd / "ai" / "AI-077.yml"
    written = yaml.safe_load(f.read_text(encoding="utf-8"))[0]
    assert written["mode"] == "shadow" and written["shadow_since"] == "2026-10-13" and written["owner"] == "de"
    assert written["logsource"] == {"category": "webserver"} and written["falsepositives"] == ["Sao lưu thủ công qua web"]
    assert check_rule(written, "ai/AI-077.yml", ai=True) == []
    assert {r.id: r for r in load_rules(rd)}["AI-077"].mode == "shadow"
    with pytest.raises(deploy.DeployError) as e:                         # mới chạy bóng, chưa đủ 7 ngày
        deploy.promote(es, "AI-077", "de", rd, now="2026-10-13T11:00:00+00:00")
    assert e.value.code == 409 and "tối thiểu" in str(e.value)
    monkeypatch.setattr(settings, "SHADOW_MIN_DAYS", 0)
    monkeypatch.setattr(deploy, "shadow_stats", lambda es, rid, since: {
        "since": since, "days": 8.0, "alerts": 40, "alerts_per_day": 5.0, "judged": 10, "fp_rate": 0.1, "verdicts": {}})
    with pytest.raises(deploy.DeployError, match="alert/ngày"):         # ồn quá
        deploy.promote(es, "AI-077", "de", rd, now="2026-10-21T11:00:00+00:00")
    monkeypatch.setattr(deploy, "shadow_stats", lambda es, rid, since: {
        "since": since, "days": 8.0, "alerts": 8, "alerts_per_day": 1.0, "judged": 5, "fp_rate": 0.2, "verdicts": {}})
    r = deploy.promote(es, "AI-077", "de", rd, now="2026-10-21T11:00:00+00:00")
    after = yaml.safe_load(f.read_text(encoding="utf-8"))[0]
    assert r["mode"] == "active" and after["mode"] == "active" and after["promoted"]["by"] == "de"
    assert {r.id: r for r in load_rules(rd)}["AI-077"].mode == "active"
    assert es.doc["promoted_by"] == "de" and "bật chính thức" in es.doc["history"][-1]["text"]
    with pytest.raises(deploy.DeployError, match="không ở chế độ chạy bóng"):
        deploy.promote(es, "AI-077", "de", rd, now="t")
    with pytest.raises(deploy.DeployError, match="rule AI"):
        deploy.promote(es, "WEB-001", "de", rd, now="t")
