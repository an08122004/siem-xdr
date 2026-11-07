"""Duyệt / bật chính thức / gỡ rule AI vào rules-dynamic/ai.xml (Task 22). ES và Wazuh API đều là hàng giả."""
import itertools
import threading

import pytest

from siem import wazuh_rules
from siem.ai import deploy
from siem.ai.wazuh_xml import EMITTER_VERSION

TREE = {"all": [{"field": "url.path", "op": "endswith", "value": ".bak"}]}
_n = itertools.count(1)


class FakeES:
    def __init__(self):
        self.docs, self.seq, self.alerts = {}, {}, []
        self.lock = threading.Lock()

    def get(self, index, id):
        if id not in self.docs:
            raise KeyError(id)
        return {"_source": dict(self.docs[id]), "_seq_no": self.seq[id], "_primary_term": 1}

    def index(self, index, id, document, if_seq_no=None, **_):
        with self.lock:
            if if_seq_no is not None and if_seq_no != self.seq.get(id):
                raise RuntimeError("conflict")
            self.docs[id], self.seq[id] = dict(document), self.seq.get(id, 0) + 1

    def search(self, index, query=None, size=10, sort=None, aggs=None, **_):
        if aggs:                                           # shadow_stats: chỉ đếm alert giả đã gài
            ids = next(f["terms"]["rule.id"] for f in query["bool"]["filter"] if "terms" in f and "rule.id" in f["terms"])
            n = sum(a in ids for a in self.alerts)
            return {"hits": {"total": {"value": n}}, "aggregations": {"v": {"buckets": []}}}
        statuses = next(f["terms"]["status"] for f in query["bool"]["filter"] if "terms" in f)
        hits = [{"_id": i, "_source": d} for i, d in self.docs.items()
                if d.get("kind") == "new_rule" and d.get("status") in statuses]
        return {"hits": {"hits": hits}}


class FakeApi:
    def __init__(self):
        self.reloads, self.fail_reload = 0, False

    def reload(self):
        self.reloads += 1
        if self.fail_reload:
            raise wazuh_rules.WazuhRuleError("Wazuh không nạp được ruleset")


class Env:
    def __init__(self, tmp_path, monkeypatch):
        self.es, self.api, self.dyn = FakeES(), FakeApi(), tmp_path
        monkeypatch.setattr(wazuh_rules, "DYNAMIC_DIR", tmp_path)
        monkeypatch.setattr(deploy, "recheck", lambda *a, **k: [])

    def pending(self, level=10, **wazuh):
        pid = f"{next(_n):012x}"
        self.es.docs[pid], self.es.seq[pid] = {
            "id": pid, "kind": "new_rule", "status": "pending", "required_approvals": 1, "approvals": [],
            "updated_at": "", "proposal": {"id": "AI-001", "title": "Tải file .bak", "condition": TREE,
                                           "mitre": {"technique": ["T1005"]}},
            "wazuh": {"emitter": EMITTER_VERSION, "domain": "web", "level": level, "rules": 1} | wazuh}, 1
        return self.es.docs[pid]

    def approved(self, since="2026-11-01"):
        p = self.pending()
        return deploy.approve(self.es, p["id"], "an", self.api, now=f"{since}T08:00:00+00:00")

    def text(self):
        return (self.dyn / "ai.xml").read_text(encoding="utf-8")


@pytest.fixture
def env(tmp_path, monkeypatch):
    return Env(tmp_path, monkeypatch)


def test_approve_writes_shadow_block(env):
    p = env.pending(level=10)
    out = deploy.approve(env.es, p["id"], "an", env.api, now="2026-11-20T08:00:00+00:00")
    text = env.text()
    assert f'<group name="siem,ai,ai_{p["id"]},">' in text and 'id="109000"' in text and 'level="10"' in text
    assert "shadow_since=2026-11-20" in text and out["status"] == "approved" and out["wazuh"]["ids"][0] == 109000
    assert out["wazuh"]["code"] == "AI-000" and out["file"] == "rules-dynamic/ai.xml" and env.api.reloads == 1


def test_second_approval_allocates_next_ids(env):
    first, second = env.approved(), env.approved()
    assert second["wazuh"]["ids"][0] == first["wazuh"]["ids"][-1] + 1


def test_approve_rejects_changed_emitter(env):
    p = env.pending(emitter="0")
    with pytest.raises(deploy.DeployError) as e:
        deploy.approve(env.es, p["id"], "an", env.api)
    assert e.value.code == 409 and "kiểm định lại" in str(e.value)


def test_reload_failure_keeps_proposal_pending(env):
    env.api.fail_reload = True
    p = env.pending()
    with pytest.raises(deploy.DeployError) as e:
        deploy.approve(env.es, p["id"], "an", env.api)
    assert e.value.code == 409 and env.es.docs[p["id"]]["status"] == "pending" and not (env.dyn / "ai.xml").exists()


def test_promote_checks_stats_then_unshadows(env):
    p = env.approved(since="2026-11-01")
    deploy.promote(env.es, p["id"], "de", env.api, now="2026-11-10T00:00:00+00:00")
    text = env.text()
    assert "shadow" not in text and 'id="109000"' in text
    assert env.es.docs[p["id"]]["promoted_by"] == "de" and "shadow_since" not in env.es.docs[p["id"]]["wazuh"]
    with pytest.raises(deploy.DeployError, match="chạy bóng"):                  # đã bật rồi
        deploy.promote(env.es, p["id"], "de", env.api, now="2026-11-11T00:00:00+00:00")


def test_promote_too_early_is_409(env):
    p = env.approved(since="2026-11-01")
    with pytest.raises(deploy.DeployError) as e:
        deploy.promote(env.es, p["id"], "de", env.api, now="2026-11-04T00:00:00+00:00")
    assert e.value.code == 409 and "tối thiểu" in str(e.value) and "shadow" in env.text()


def test_promote_too_noisy_is_409(env):
    p = env.approved(since="2026-11-01")
    env.es.alerts = [f"WZH-{p['wazuh']['ids'][0]}"] * 100
    with pytest.raises(deploy.DeployError, match="alert/ngày"):
        deploy.promote(env.es, p["id"], "de", env.api, now="2026-11-10T00:00:00+00:00")


def test_rollback_removes_block(env):
    a, b = env.approved(), env.approved()
    deploy.rollback(env.es, a["id"], "an", "báo nhầm", env.api)
    text = env.text()
    assert f"ai_{a['id']}" not in text and f"ai_{b['id']}" in text and env.es.docs[a["id"]]["status"] == "rolled_back"
    deploy.rollback(env.es, b["id"], "an", "báo nhầm", env.api)                  # gỡ nốt: file vẫn hợp lệ
    assert "<rule" not in env.text()


def test_concurrent_approvals_keep_both_blocks(env):
    p1, p2 = env.pending(), env.pending()
    ts = [threading.Thread(target=deploy.approve, args=(env.es, p["id"], "an", env.api)) for p in (p1, p2)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    text = env.text()
    assert f"ai_{p1['id']}" in text and f"ai_{p2['id']}" in text


def test_id_range_exhausted():
    with pytest.raises(deploy.DeployError) as e:
        deploy.next_ids([{"wazuh": {"ids": [109999]}}], 1)
    assert e.value.code == 409 and "hết dải id" in str(e.value)
    assert deploy.next_ids([], 2) == [109000, 109001]


def test_rolled_back_ids_are_not_reused(env):
    a = env.approved()
    deploy.rollback(env.es, a["id"], "an", "báo nhầm", env.api)
    b = env.approved()
    assert b["wazuh"]["ids"][0] > a["wazuh"]["ids"][-1]


def test_double_approve_same_pid_writes_one_block(env):
    p = env.pending()
    results = []

    def go(who):
        try:
            results.append(deploy.approve(env.es, p["id"], who, env.api))
        except deploy.DeployError as e:
            results.append(e)
    ts = [threading.Thread(target=go, args=(w,)) for w in ("an", "binh")]
    [t.start() for t in ts]
    [t.join() for t in ts]
    errs = [r for r in results if isinstance(r, deploy.DeployError)]
    assert env.text().count(f"ai_{p['id']}") == 1 and len(errs) == 1 and errs[0].code == 409
    assert len(results) == 2 and env.text().count("<rule ") == 1


def test_stale_rollback_and_promote_recheck_under_lock(env):
    a = env.approved()
    deploy.rollback(env.es, a["id"], "an", "báo nhầm", env.api)
    with pytest.raises(deploy.DeployError) as e:
        deploy.rollback(env.es, a["id"], "an", "lần hai", env.api)
    assert e.value.code == 409


def test_stale_read_in_deploy_new_is_refused(env):
    p = env.pending()
    stale = dict(env.es.docs[p["id"]])
    deploy.approve(env.es, p["id"], "an", env.api)
    stale["history"] = []
    with pytest.raises(deploy.DeployError) as e:
        deploy._deploy_new(env.es, p["id"], stale, 1, 1, "2026-11-20T00:00:00+00:00", env.api)
    assert e.value.code == 409 and env.text().count(f"ai_{p['id']}") == 1
