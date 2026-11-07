"""Cổng Wazuh cho rule AI mới (Task 21, siem/ai/wazuh_gate.py): khoảng trống và kiểm định tính trên alert của sandbox
Wazuh (sandbox giả: trả lần lượt từng kết quả, ghi lại job đã nhận). Sandbox thật: tests/test_sandbox_it.py."""
from __future__ import annotations

from pathlib import Path

import pytest

from siem.ai import wazuh_xml, worker
from siem.ai.golden import Labeled, PublicDatasets
from siem.ai.sandbox import Hit, SandboxError, SandboxResult
from siem.ai.wazuh_events import RawEvent, golden_events
from siem.ai.wazuh_gate import CANDIDATE_BASE, WazuhGate
from siem.ai.worker import AIWorker, generator_id
from test_ai import NORMAL_URLS, FakeDS, FakeLLM, web, write_rules
from test_ai_hardening import _DocsES


def _doc(n: int) -> dict:
    cmd = f"evil-tool --run {n}" if n in (11, 12, 13) else f"ok-tool {n}"
    return {"n": n, "event": {"category": "process"},
            "process": {"name": "x.exe", "executable": "C:\\x.exe", "command_line": cmd}}


DOCS = [_doc(n) for n in range(30)]
NO_RAW = _doc(99)                                      # mẫu không dựng được log thô
TRAIN, TEST4, DOC21 = DOCS[5:11], DOCS[11:15], DOCS[21]
NORMAL1000 = [_doc(n) for n in range(1000, 2000)]
RAW = {id(d): RawEvent(d["n"], "eventchannel", f"msg-{d['n']}") for d in DOCS + NORMAL1000}
TREE = {"field": "process.command_line", "op": "contains", "value": "evil-tool"}     # Python khớp 11, 12, 13


class FakeSandbox:
    def __init__(self, results):
        self.results, self.jobs = list(results), []

    def run(self, events, candidate_xml=None):
        self.jobs.append(([e.ident for e in events], candidate_xml))
        r = self.results.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


@pytest.fixture
def gate_with():
    def make(baseline=None, candidate=None):
        res = [SandboxResult(baseline or {}, None, 40.0)]
        if candidate is not None:
            res.append(candidate if isinstance(candidate, SandboxResult) else SandboxResult(candidate, None, 50.0))
        g = WazuhGate(FakeSandbox(res), RAW)
        g.fake = g.sandbox
        return g
    return make


def _check(g, normal=NORMAL1000, test=TEST4, domain="windows"):
    return g.check(TREE, domain=domain, level=7, title="t", techniques=["T1059"], train=TRAIN, test=test, normal=normal)


def by_name(checks, name):
    return next(c for c in checks if c.name == name)


# ------------------------------------------------------------------ khoảng trống
def test_gaps_ignore_generic_and_low_level(gate_with, caplog):
    caplog.set_level("INFO", logger="ai.wazuh_gate")
    g = gate_with(baseline={1: [Hit(92032, 10)], 2: [Hit(92213, 12)], 3: [Hit(60103, 5)], 4: []})
    assert [d["n"] for d in g.gaps(DOCS[1:5])] == [1, 3, 4]          # 92032 nằm trong GENERIC
    assert g.gaps([NO_RAW]) == []                                      # không đo được trên Wazuh: không phải khoảng trống
    assert len(g.fake.jobs) == 1 and g.fake.jobs[0][1] is None         # MỘT job nền mỗi chu kỳ, không có ứng viên
    assert set(g.fake.jobs[0][0]) == {e.ident for e in RAW.values()}  # ... gồm mọi log thô của bộ mẫu vàng
    assert g.baseline([DOCS[2], NO_RAW]) == {id(DOCS[2]): [Hit(92213, 12)]}
    assert "giao job nền" in caplog.text and "job nền xong" in caplog.text     # job dài phải thấy được trong log


def test_sandbox_error_is_raised_and_remembered_for_the_cycle():
    g = WazuhGate(FakeSandbox([SandboxError("canary 554 không ra")]), RAW)
    with pytest.raises(SandboxError, match="canary"):
        g.gaps(DOCS[1:5])
    with pytest.raises(SandboxError, match="canary"):                 # không giao job mới, không chờ hết giờ lần nữa
        _check(g)
    assert len(g.sandbox.jobs) == 1


# ------------------------------------------------------------------ kiểm định ứng viên
def test_gate_passes_good_candidate(gate_with):
    g = gate_with(baseline={}, candidate={11: [Hit(119000, 7)], 12: [Hit(119000, 7)]})   # test = 11..14
    checks, m = g.check(TREE, domain="windows", level=7, title="t", techniques=["T1059"],
                        train=TRAIN, test=TEST4, normal=NORMAL1000)
    assert all(c.ok for c in checks if c.blocking) and m["wazuh_test_recall"] == 0.5 and m["wazuh_normal_hits"] == 0
    assert m["wazuh_rules"] == 1
    idents, xml = g.fake.jobs[1]
    assert f'<rule id="{CANDIDATE_BASE}" level="7">' in xml and xml.startswith("<group name=") and "shadow" not in xml
    assert "AI-CAND" in xml and {d["n"] for d in TRAIN + TEST4 + NORMAL1000} <= set(idents)
    assert idents == sorted(idents)                                    # cùng thứ tự với job nền


def test_gate_fails_low_recall(gate_with):          # 1/4 = 25% < 30%
    g = gate_with(candidate={11: [Hit(119000, 7)]})
    checks, m = _check(g)
    assert not by_name(checks, "bắt mẫu nghi vấn (Wazuh)").ok and m["wazuh_test_recall"] == 0.25


def test_gate_fails_false_positives(gate_with):     # 2/1000 = 0,2% > 0,1%
    g = gate_with(candidate={11: [Hit(119000, 7)], 12: [Hit(119000, 7)], 1000: [Hit(119000, 7)], 1001: [Hit(119000, 7)]})
    checks, m = _check(g)
    assert not by_name(checks, "báo nhầm (Wazuh)").ok and m["wazuh_normal_hits"] == 2


def test_gate_blocks_candidate_that_steals_stock_alert(gate_with):
    g = gate_with(baseline={21: [Hit(92213, 12)]}, candidate={21: [Hit(119000, 10)]})   # 21 là mẫu bình thường
    checks, m = _check(g, normal=[DOC21])
    c = by_name(checks, "không che rule khác")
    assert c.blocking and not c.ok and "92213" in c.detail and m["wazuh_stolen"] == 1


def test_steal_check_covers_stock_detected_samples_outside_the_group(gate_with):
    """Review Focus #1: rule ứng viên thắng rule gốc cùng cha thì mất alert thật của mẫu tấn công mà Wazuh ĐANG bắt —
    mẫu đó không nằm trong train / test / normal của nhóm khoảng trống. Mất alert GENERIC thì không tính."""
    g = gate_with(baseline={25: [Hit(92213, 12)], 26: [Hit(92041, 10)], 27: [Hit(92213, 12)]},
                  candidate={11: [Hit(119000, 7)], 12: [Hit(119000, 7)], 25: [Hit(119000, 7)], 26: [Hit(119000, 7)],
                             27: [Hit(92213, 12)]})
    checks, m = _check(g)
    assert {25, 26, 27} <= set(g.fake.jobs[1][0])
    assert not by_name(checks, "không che rule khác").ok and m["wazuh_stolen"] == 1


def test_gate_fails_on_load_error(gate_with):
    g = gate_with(candidate=SandboxResult({}, "(7612): Rule ID '119000' is duplicated", 1.0))
    checks, _ = _check(g)
    assert not by_name(checks, "Wazuh nạp được rule").ok and "7612" in by_name(checks, "Wazuh nạp được rule").detail


def test_untranslatable_rule_fails_without_sandbox_job(gate_with):
    g = gate_with()
    checks, m = _check(g, domain="other")                              # rule "gap-own": chưa có rule Wazuh cho lĩnh vực này
    assert [(c.name, c.ok) for c in checks] == [("Wazuh nạp được rule", False)] and g.fake.jobs == []


def test_missing_raw_events_fail_without_candidate_job(gate_with):
    g = gate_with()
    checks, _ = _check(g, test=TEST4 + [NO_RAW])
    assert not by_name(checks, "có log thô").ok and len(g.fake.jobs) <= 1


def test_gate_reports_python_wazuh_mismatch(gate_with):
    # cây Python khớp mẫu 13 nhưng Wazuh không ra 119000 cho 13 (vd trường vắng + phủ định, Review Focus #5)
    g = gate_with(candidate={11: [Hit(119000, 7)], 12: [Hit(119000, 7)]})
    checks, m = _check(g)
    c = by_name(checks, "khớp Python")
    assert not c.blocking and not c.ok and m["wazuh_python_only"] == 1 and m["wazuh_wazuh_only"] == 0
    assert all(c.ok for c in checks if c.blocking)                     # lệch chỉ ghi số liệu, không chặn (R66)


# ------------------------------------------------------------------ worker
def _web_golden():
    attack = [Labeled(web(f"/shop/img/logo{i}.gif.bak", i), {"dataset": "csic2010"}) for i in range(12)]
    normal = [Labeled(web(u, i), {"dataset": "csic2010", "class": "normal"}) for i, u in enumerate(NORMAL_URLS * 5)]
    return PublicDatasets(directory=Path("."), attack=attack, normal=normal)


class ScriptSandbox:
    """Sandbox giả cho cả chu kỳ: job nền không có alert; ứng viên có đuôi `ext` trong mẫu ra alert 119000 cho event có
    `.ext` trong log thô."""

    def __init__(self, ext="bak"):
        self.ext, self.jobs = ext, []

    def run(self, events, candidate_xml=None):
        self.jobs.append(candidate_xml)
        fire = bool(candidate_xml) and self.ext in candidate_xml
        hits = {e.ident: [Hit(CANDIDATE_BASE, 7)] for e in events if fire and f".{self.ext}" in e.msg}
        return SandboxResult(hits, None, 1.0)


BAK_RULE = ("title: Dò file .bak\nlevel: medium\nlogsource: {category: webserver}\ndetection:\n  sel:\n"
            "    cs-uri-stem|endswith: '.bak'\n  condition: sel\n")


@pytest.fixture
def worker_with_gate_raising(tmp_path, monkeypatch):
    def make(err):
        rd = write_rules(tmp_path)
        monkeypatch.setattr("siem.ai.worker.settings.RULES_DIR", rd)
        g = _web_golden()
        raw = golden_events(g, g.directory)
        return AIWorker(None, FakeLLM({"new_rule": BAK_RULE}), g, rules_dir=rd, ds_factory=lambda es: FakeDS({}, []),
                        save=lambda p: None, gate_factory=lambda: WazuhGate(FakeSandbox([err]), raw))
    return make


def test_cycle_records_error_when_sandbox_unavailable(worker_with_gate_raising):
    s = worker_with_gate_raising(SandboxError("canary")).run_cycle()
    assert any("sandbox" in e for e in s["errors"]) and s["created"] == []


def test_cycle_without_sandbox_does_not_treat_every_sample_as_gap(tmp_path, monkeypatch):
    rd = write_rules(tmp_path)
    monkeypatch.setattr("siem.ai.worker.settings.RULES_DIR", rd)
    saved = []
    s = AIWorker(None, FakeLLM({"new_rule": BAK_RULE}), _web_golden(), rules_dir=rd,
                 ds_factory=lambda es: FakeDS({}, []), save=saved.append).run_cycle()
    assert saved == [] and any("sandbox" in e for e in s["errors"])


def test_generator_revision_is_11():
    assert worker.GENERATOR_REVISION == "11"


def test_new_rule_proposal_carries_wazuh_block(tmp_path, monkeypatch):
    rd = write_rules(tmp_path)
    monkeypatch.setattr("siem.ai.worker.settings.RULES_DIR", rd)
    g = _web_golden()
    raw, sb, saved = golden_events(g, g.directory), ScriptSandbox(), []
    AIWorker(None, FakeLLM({"new_rule": BAK_RULE}), g, rules_dir=rd, ds_factory=lambda es: FakeDS({}, []),
             save=saved.append, gate_factory=lambda: WazuhGate(sb, raw)).run_cycle("an")
    p = saved[0]
    assert p["target"] == "gap-dataset:csic2010:backup-file" and p["status"] == "pending", p["validation"]["checks"]
    assert p["wazuh"]["emitter"] == wazuh_xml.EMITTER_VERSION and p["wazuh"]["rules"] >= 1
    assert p["wazuh"]["domain"] == "web" and p["wazuh"]["level"] == wazuh_xml.LEVEL["medium"] and p["wazuh"]["validated_at"]
    names = {c["name"] for c in p["validation"]["checks"]}
    assert {"bắt mẫu nghi vấn (Wazuh)", "báo nhầm (Wazuh)", "không che rule khác", "ước lượng alert khi replay (Python)"} <= names
    assert "trùng rule sẵn có" not in names and p["validation"]["metrics"]["wazuh_test_recall"] == 1.0
    assert sb.jobs[0] is None and "119000" in sb.jobs[1] and len(sb.jobs) == 2


def test_python_failure_skips_the_sandbox(tmp_path, monkeypatch):
    rd = write_rules(tmp_path)
    monkeypatch.setattr("siem.ai.worker.settings.RULES_DIR", rd)
    g = _web_golden()
    sb, saved = ScriptSandbox(), []
    noisy = BAK_RULE.replace("cs-uri-stem|endswith: '.bak'", "cs-uri-stem|contains: '/'")   # khớp mọi request bình thường
    AIWorker(None, FakeLLM({"new_rule": noisy}), g, rules_dir=rd, ds_factory=lambda es: FakeDS({}, []),
             save=saved.append, gate_factory=lambda: WazuhGate(sb, golden_events(g, g.directory))).run_cycle("an")
    assert saved[0]["status"] == "invalid" and "wazuh" not in saved[0] and sb.jobs == [None]


def test_stale_pending_proposals_gated_on_wazuh(tmp_path):
    g = _web_golden()
    gen = generator_id("fake")

    def prop(pid, cond, target="gap-dataset:csic2010:backup-file"):
        rule = {"id": f"AI-{pid}", "title": f"rule {pid}", "severity": "medium", "type": "match",
                "tags": ["ai-generated", "dataset-gap", "backup-file"], "condition": cond, "mitre": {"technique": []}}
        return {"id": pid, "kind": "new_rule", "target": target, "title": f"đề xuất {pid}", "status": "pending",
                "proposal": rule, "llm": {"model": "fake", "generator": gen}, "history": [],
                "validation": {"checks": [], "metrics": {}}}

    bak = {"field": "url.path", "op": "endswith", "value": ".bak"}
    history = [prop("201", bak),                                                       # qua cổng -> có khối wazuh
               prop("202", {"field": "url.path", "op": "endswith", "value": ".zzz"}),   # Wazuh không bắt mẫu nào
               prop("203", bak, target="gap-dataset:csic2010:sqli"),                    # không còn là khoảng trống
               prop("204", bak) | {"wazuh": {"emitter": wazuh_xml.EMITTER_VERSION}}]   # đã kiểm định: bỏ qua
    es, sb = _DocsES(history), ScriptSandbox()
    w = AIWorker(es, FakeLLM({}), g, rules_dir=tmp_path, ds_factory=lambda e: FakeDS({}, []), save=None)
    summary = {"rechecked": [], "errors": []}
    w._recheck_stale(history, gen, summary, WazuhGate(sb, golden_events(g, g.directory)))
    assert [es.docs[i]["status"] for i in ("201", "202", "203", "204")] == ["pending", "invalid", "invalid", "pending"]
    assert es.docs["201"]["wazuh"]["emitter"] == wazuh_xml.EMITTER_VERSION and es.docs["201"]["wazuh"]["domain"] == "web"
    assert any(c["name"] == "bắt mẫu nghi vấn (Wazuh)" for c in es.docs["201"]["validation"]["checks"])
    assert "bắt mẫu nghi vấn (Wazuh)" in es.docs["202"]["history"][-1]["text"]
    assert "khoảng trống" in es.docs["203"]["history"][-1]["text"] and "wazuh" not in es.docs["202"]
    assert len(sb.jobs) == 3 and summary["errors"] == []                # 1 job nền + 2 ứng viên


def test_stale_recheck_keeps_proposal_when_sandbox_down(tmp_path):
    g = _web_golden()
    gen = generator_id("fake")
    p = {"id": "301", "kind": "new_rule", "target": "gap-dataset:csic2010:backup-file", "status": "pending",
         "proposal": {"id": "AI-301", "title": "t", "severity": "medium", "type": "match",
                      "condition": {"field": "url.path", "op": "endswith", "value": ".bak"}},
         "llm": {"generator": gen}, "history": []}
    es = _DocsES([p])
    w = AIWorker(es, FakeLLM({}), g, rules_dir=tmp_path, ds_factory=lambda e: FakeDS({}, []), save=None)
    summary = {"rechecked": [], "errors": []}
    w._recheck_stale([p], gen, summary, WazuhGate(FakeSandbox([SandboxError("hết giờ")]), golden_events(g, g.directory)))
    assert es.docs["301"]["status"] == "pending" and any("sandbox" in e for e in summary["errors"])


def test_broken_stale_proposal_does_not_stop_the_recheck(tmp_path):
    """Một đề xuất cũ hỏng (mức độ lạ -> KeyError ở LEVEL) bị đánh invalid kèm lý do; đề xuất sau vẫn được kiểm định."""
    g = _web_golden()
    gen = generator_id("fake")

    def prop(pid, severity):
        return {"id": pid, "kind": "new_rule", "target": "gap-dataset:csic2010:backup-file", "status": "pending",
                "proposal": {"id": f"AI-{pid}", "title": "t", "severity": severity, "type": "match",
                             "condition": {"field": "url.path", "op": "endswith", "value": ".bak"}},
                "llm": {"generator": gen}, "history": []}

    history = [prop("401", "khong-ro"), prop("402", "medium")]
    es = _DocsES(history)
    w = AIWorker(es, FakeLLM({}), g, rules_dir=tmp_path, ds_factory=lambda e: FakeDS({}, []), save=None)
    summary = {"rechecked": [], "errors": []}
    w._recheck_stale(history, gen, summary, WazuhGate(ScriptSandbox(), golden_events(g, g.directory)))
    assert es.docs["401"]["status"] == "invalid" and "KeyError" in es.docs["401"]["history"][-1]["text"]
    assert es.docs["402"]["status"] == "pending" and es.docs["402"]["wazuh"]["emitter"] == wazuh_xml.EMITTER_VERSION
    assert summary["errors"] == [] and len(summary["rechecked"]) == 2


def test_generator_id_changes_with_emitter_version(monkeypatch):
    """Kết luận của cổng Wazuh phụ thuộc bộ dịch: đổi EMITTER_VERSION thì mục tiêu bị cổng loại được thử lại ngay."""
    before = generator_id("m")
    monkeypatch.setattr(wazuh_xml, "EMITTER_VERSION", "2-thu")
    assert generator_id("m") != before
