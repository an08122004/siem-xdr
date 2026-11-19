"""Nguồn gap-ml: rule tần suất từ sự cố ML đã xác nhận (frequency.py, wazuh_xml.emit_frequency, worker, deploy)."""
from datetime import datetime, timezone

import pytest

from siem.ai import deploy
from siem.ai import frequency as fq
from siem.ai.llm import LLMResult
from siem.ai.sandbox import Hit, SandboxResult
from siem.ai.sigma import SigmaError
from siem.ai.validate import Check
from siem.ai.wazuh_events import log_event
from siem.ai.wazuh_gate import CANDIDATE_BASE, WazuhGate
from siem.ai.wazuh_xml import emit_frequency, unshadow
from siem.ai.worker import AIWorker, legacy_reason

NOW = datetime.now(timezone.utc).timestamp()
LINE = '{ip} - - [19/Nov/2026:12:00:00 +0700] "GET /portal/ HTTP/1.1" 401 459 "-" "Mozilla/5.0"'


def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).isoformat()


def web_event(ip, t, sid="31101"):
    return {"@timestamp": iso(t), "source": {"ip": ip}, "wazuh": {"rule": {"id": sid, "level": 5,
            "description": "Web server 400 error code."}}, "raw": {"full_log": LINE.format(ip=ip),
            "location": "/var/log/apache2/access.log"}}


class GapDS:
    """Hai sự cố ML true_positive: 10.10.1.62 (20 lần 401 trong ~200 giây, chưa rule nào báo) và 10.10.1.60 (rule Wazuh
    đã báo). Người dùng thường: 10.10.1.41 hai lần 401 sát nhau (6 ngày trước), 10.10.1.42 một lần (hôm qua)."""

    def __init__(self, normal_burst=2):
        t = NOW - 3600
        self.spray = [web_event("10.10.1.62", t - 200 + 10 * k) for k in range(20)]
        self.normal = [web_event("10.10.1.41", NOW - 6 * 86400 + k) for k in range(normal_burst)] + \
            [web_event("10.10.1.42", NOW - 86400)]
        self.incidents = [{"alert": {"id": f"a{n}"}, "rule": {"description": "n_401=20 (thường 0)",
                           "mitre": {"tactic": "Reconnaissance", "technique": ["T1595"]}},
                           "source": {"ip": ip}, "ml": {"model": "web"}, "event_time": iso(t)}
                          for n, ip in enumerate(["10.10.1.62", "10.10.1.60"])]

    def evidence(self):
        return {}

    def proposals(self, statuses=None, since="", size=500):
        return []

    def ml_incidents(self):
        return self.incidents

    def alert_ips(self, start, end, real_only=False):
        return {"10.10.1.60"}

    def events_of(self, ip, start, end):
        return [e for e in self.spray + self.normal if e["source"]["ip"] == ip and start <= e["@timestamp"] <= end]

    def rule_hits(self, sid):
        return self.spray + self.normal

    def replay_events(self):
        return []


class JsonLLM:
    model = "fake"

    def __init__(self, answer):
        self.answer, self.prompts = answer, []

    def chat_json(self, system, user, schema, temperature=0.2):
        self.prompts.append(user)
        return LLMResult(data=self.answer, raw="{}", model="fake", seconds=0.1, prompt_tokens=1, output_tokens=1)


class FreqGate:
    def __init__(self):
        self.calls = []

    def check_frequency(self, xml, attack, normal):
        self.calls.append((xml, attack, normal))
        return [Check("bắt sự cố (Wazuh)", True, "1/1")], {"wazuh_incidents_detected": len(attack)}


DOC = {"no_rule": "", "title": "Password spraying against web portal", "description": "Dò mật khẩu.",
       "rationale": "20 lần 401.", "techniques": ["T1110.003", "bad"]}


def run(ds, llm):
    saved, gate = [], FreqGate()
    w = AIWorker(None, llm, None, ds_factory=lambda es: ds, save=saved.append, gate_factory=lambda: gate)
    w._next_ai_id = lambda ds: "AI-300"
    return w.run_cycle("an"), saved, gate


def test_cycle_turns_confirmed_ml_incident_into_frequency_rule():
    llm = JsonLLM(DOC)
    summary, saved, gate = run(GapDS(), llm)
    assert [p["target"] for p in saved] == ["gap-ml:web:31101"]
    p = saved[0]
    assert p["status"] == "pending" and p["proposal"]["type"] == "frequency"
    assert p["proposal"]["frequency"] == {"sid": 31101, "count": 3, "timeframe": 300, "group_by": "source.ip"}
    assert p["proposal"]["mitre"]["technique"] == ["T1110.003"] and p["wazuh"]["domain"] == "frequency"
    assert p["evidence"]["ml_alert_ids"] == ["a0"] and p["validation"]["metrics"]["held_fires"] == 0
    assert any("a1" in s and "rule Wazuh đã báo" in s for s in summary["skipped"])        # 10.10.1.60 đã có rule bắt
    assert '"threshold": 3' in llm.prompts[0] and "10.10.1.62" in llm.prompts[0]
    xml, attack, normal = gate.calls[0]
    assert 'frequency="3" timeframe="300"' in xml and "<if_matched_sid>31101</if_matched_sid>" in xml
    assert list(attack) == ["10.10.1.62"] and len(attack["10.10.1.62"]) == 20
    assert "(sbx-" in attack["10.10.1.62"][0].msg and "/var/log/apache2/access.log:10.10.1.62" in attack["10.10.1.62"][0].msg
    assert "10.10.1.41" in normal and len(normal["10.10.1.41"]) == 2


def test_llm_can_decline():
    _, saved, _ = run(GapDS(), JsonLLM(DOC | {"no_rule": "quản trị viên chạy thử"}))
    assert saved[0]["status"] == "no_action"


def test_threshold_above_incident_means_invalid_without_llm_or_sandbox():
    llm = JsonLLM(DOC)
    _, saved, gate = run(GapDS(normal_burst=30), llm)          # người thường 30 lần / 300 giây > sự cố 20 lần
    assert saved[0]["status"] == "invalid" and not llm.prompts and not gate.calls
    assert saved[0]["proposal"]["frequency"]["count"] == 31


class SeqSandbox:
    """Sandbox giả: job 1 = không ứng viên, job 2 = có ứng viên."""

    def __init__(self, base, cand):
        self.results, self.xml = [SandboxResult(base, None, 40.0), SandboxResult(cand, None, 41.0)], []

    def run(self, events, candidate_xml=None):
        self.xml.append(candidate_xml)
        return self.results.pop(0)


def raws(ip, idents):
    return [log_event(i, "/var/log/apache2/access.log", LINE.format(ip=ip)) for i in idents]


def freq_check(base, cand):
    g = WazuhGate(SeqSandbox(base, cand), {})
    attack = {"10.10.1.62": raws("10.10.1.62", range(1, 7)), "10.10.1.63": raws("10.10.1.63", (9, 10))}
    checks, m = g.check_frequency("<rule/>", attack, {"10.10.1.41": raws("10.10.1.41", (7, 8))})
    return {c.name: c for c in checks}, m, g.sandbox.xml


def test_check_frequency_compares_detection_per_ip():
    # 10.10.1.62: ứng viên kích hoạt; 10.10.1.63: job nền có 31151 (level 10) mà job ứng viên mất hết -> che rule khác
    c, m, xml = freq_check({10: [Hit(31151, 10)]}, {5: [Hit(CANDIDATE_BASE, 7)]})
    assert xml[0] is None and "ai_candidate" in xml[1]
    assert c["bắt sự cố (Wazuh)"].ok and m["wazuh_incidents_detected"] == 1           # 1/2 IP = 50%
    assert c["IP bình thường không kích hoạt (Wazuh)"].ok
    assert not c["không che rule khác"].ok and "10.10.1.63" in c["không che rule khác"].detail


def test_check_frequency_blocks_rule_firing_on_normal_ip():
    # 31151 rời sang event khác của cùng IP: vẫn bị phát hiện, không tính là che
    c, _, _ = freq_check({4: [Hit(31151, 10)]}, {5: [Hit(CANDIDATE_BASE, 7)], 6: [Hit(31151, 10)],
                                                 8: [Hit(CANDIDATE_BASE, 7)]})
    assert c["không che rule khác"].ok
    assert not c["IP bình thường không kích hoạt (Wazuh)"].ok and "10.10.1.41" in c["IP bình thường không kích hoạt (Wazuh)"].detail


def test_gap_ml_proposals_are_not_legacy_and_recheck_skips_them():
    assert legacy_reason({"kind": "new_rule", "target": "gap-ml:web:31101"}) == ""
    assert deploy.recheck({"target": "gap-ml:web:31101", "proposal": {"type": "frequency"}}) == []


def test_max_in_span_is_sliding_not_fixed_windows():
    # 3 event cuối cửa sổ cố định này + 3 event đầu cửa sổ sau: cửa sổ trượt 300 giây thấy cả 6
    assert fq.max_in_span([290, 295, 299, 301, 305, 310], 300) == 6
    assert fq.max_in_span([0, 400, 800], 300) == 1
    assert fq.max_in_span([], 300) == 0


def test_fires_like_wazuh_sandbox():
    # đo sandbox 19/11: frequency=5, IP A 8 event -> kích hoạt đúng ở event thứ 5, bộ đếm về 0, A#6–8 không kích hoạt
    assert fq.fires([0, 1, 2, 3, 4, 5, 6, 7], 5, 300) == [4]
    assert fq.fires([0, 1, 2], 5, 300) == []                       # IP B: 3 event
    assert fq.fires(list(range(10)), 5, 300) == [4, 9]
    assert fq.fires([0, 100, 200, 400, 500], 3, 300) == [200]      # event quá timeframe rơi khỏi bộ đếm


def test_threshold_from_normal_users_and_minimum():
    normal = fq.by_ip([("10.0.0.1", t) for t in (0, 10, 20)] + [("10.0.0.2", 0), ("", 5)])
    assert fq.threshold(normal, 300) == 4                          # 3 lần nhiều nhất + 1
    assert fq.threshold({}, 300) == fq.MIN_COUNT
    assert "" not in normal


def test_emit_frequency_matches_stock_31151_shape_and_shadow_cycle():
    em = emit_frequency(sid=31101, count=5, timeframe=300, rule_id=109001, level=7, code="AI-200", title="Dò <mật khẩu>",
                        techniques=["T1110.003", "bad"], groups=["siem", "ai"], shadow_since="2026-11-19")
    assert em.ids == [109001]
    assert '<rule id="109001" level="7" frequency="5" timeframe="300">' in em.xml
    assert "<if_matched_sid>31101</if_matched_sid>" in em.xml and "<same_source_ip />" in em.xml
    assert "<description>AI-200 Dò &lt;mật khẩu&gt;</description>" in em.xml
    assert "<mitre><id>T1110.003</id></mitre>" in em.xml and "bad" not in em.xml
    assert "<group>siem,ai,shadow,</group>" in em.xml and "shadow_since=2026-11-19" in em.xml
    live = unshadow(em.xml)
    assert "shadow" not in live and "<group>siem,ai,</group>" in live


@pytest.mark.parametrize("kw", [{"count": 1}, {"timeframe": 0}, {"sid": 0}])
def test_emit_frequency_rejects_nonsense(kw):
    base = dict(sid=31101, count=5, timeframe=300, rule_id=109001, level=7, code="AI-1", title="t", techniques=[],
                groups=["siem"], shadow_since=None)
    with pytest.raises(SigmaError):
        emit_frequency(**(base | kw))
