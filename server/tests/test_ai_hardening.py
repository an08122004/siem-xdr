"""Test các lỗ hổng tìm ra khi rà soát AI worker chạy thật với qwen3.5:9b (11/10/2026): rule chỉ có tên chương trình
phổ biến, tên file bài thử tự đặt, lớp bọc Invoke-AtomicTest, vế SigmaHQ quá nhiều, đề xuất cũ giữ chỗ, Ollama khởi
động lại giữa chu kỳ. Không cần Ollama / Elasticsearch / dataset thật."""
from __future__ import annotations

import http.client
import io
import urllib.error
from pathlib import Path

import pytest

from siem.ai import llm as llm_mod
from siem.ai import worker as wk
from siem.ai.baseline import ordinary_processes
from siem.ai.deploy import recheck_dataset_rule
from siem.ai.golden import Labeled, PublicDatasets
from siem.ai.validate import common_program_only, lab_wrapper
from siem.ai.worker import AIWorker, generator_id
from siem.detection.rules import Rule
from test_ai import FakeDS, SeqLLM
from test_ai_endpoint import _tech, _test, atomic_labeled

CL = "process.command_line"


def _leaf(field, op, value):
    return {"field": field, "op": op, "value": value}


def test_selection_naming_only_a_common_program_is_not_a_signature():
    """AI-157 (model): Image|endswith '/usr/bin/su'; AI-153 (vế SigmaHQ "Nohup Execution"): Image|endswith '/nohup' —
    qua kiểm định chỉ vì tập bình thường không có su / nohup. Tên chương trình đi kèm đối số, hay cha lạ, thì vẫn được."""
    exe, name, parent = "process.executable", "process.name", "process.parent.name"
    assert common_program_only({"any": [_leaf(exe, "endswith", "/usr/bin/su"), _leaf(name, "eq", "nohup")]}) == \
        ["su", "nohup"]
    assert common_program_only({"all": [_leaf(name, "eq", "cmd.exe"), _leaf(parent, "eq", "explorer.exe")]}) == \
        ["cmd.exe", "explorer.exe"]
    for ok in ({"all": [_leaf(name, "eq", "reg.exe"), _leaf(CL, "contains", "hklm\\sam")]},                  # có đối số
               {"all": [_leaf(name, "in", ["cmd.exe", "powershell.exe"]), _leaf(parent, "eq", "winword.exe")]},  # Office
               {"all": [_leaf(parent, "eq", "eventvwr.exe"), {"not": _leaf(name, "eq", "mmc.exe")}]},           # UAC bypass
               _leaf(name, "in", ["akagi64.exe", "akagi.exe"])):                                            # công cụ
        assert common_program_only(ok) == [], ok


def test_invoke_atomictest_wrapper_is_a_lab_trace():
    """Bench 9/10: 9/26 rule qua chứa lớp bọc powershell -Command "& {...}" của Invoke-AtomicTest ('& {Get-ADComputer')."""
    cond = {"any": [{"all": [_leaf(CL, "contains", "-Command"), _leaf(CL, "contains", "& {Get-ADComputer")]},
                    _leaf(CL, "contains", "Get-ADComputer -Filter *")]}
    assert lab_wrapper(cond) == ["& {Get-ADComputer"]


LAB_INDEX = {"privilege-escalation": {
    **_tech("T1548.001", "Abuse Elevation Control Mechanism: Setuid and Setgid", "privilege-escalation", [
        _test("Set a SetUID flag on file", ["linux"], "sh", "sudo touch #{f}\nsudo chown root #{f}\nsudo chmod u+xs #{f}",
              "g-suid", {"f": {"default": "/tmp/evilBinary"}}),
        _test("Make and modify binary from C source", ["linux"], "sh",
              "cp #{src} /tmp/hello.c\nsudo gcc /tmp/hello.c -o /tmp/hello\nsudo chmod u+s /tmp/hello", "g-hello",
              {"src": {"default": "PathToAtomicsFolder/T1548.001/src/hello.c"}}),
        _test("Read netrc", ["linux"], "sh", "cat #{file}", "g-netrc", {"file": {"default": "~/.netrc"}}),
    ]),
    **_tech("T1036.003", "Masquerading: Rename Legitimate Utilities", "defense-evasion", [
        _test("Masquerade svchost", ["windows"], "command_prompt", "copy C:\\Windows\\System32\\cmd.exe #{out}", "g-svc",
              {"out": {"default": "%TEMP%\\svchost.exe"}}),
        _test("Sticky keys", ["windows"], "command_prompt", "takeown /f #{bin}", "g-sethc",
              {"bin": {"default": "C:\\Windows\\System32\\sethc.exe"}}),
        _test("SOAPHound", ["windows"], "command_prompt", "#{tool} --dump #{out}", "g-soap",
              {"tool": {"default": "PathToAtomicsFolder\\..\\ExternalPayloads\\SOAPHound.exe"},
               "out": {"default": "%TEMP%\\loot_dump.bin"}}),
    ]),
}}


def _golden() -> PublicDatasets:
    normal = [Labeled(d, {"dataset": "baseline-endpoint", "class": "normal", "platform": p})
              for p in ("windows", "linux") for d in ordinary_processes(p)]
    return PublicDatasets(directory=Path("."), attack=atomic_labeled(LAB_INDEX), normal=normal)


def test_lab_tokens_are_names_the_test_author_chose_not_real_targets():
    """Chạy thật 11/10: AI-154 qua kiểm định với `/tmp/evilBinary`, `/tmp/hello`. Tên file bài thử tự đặt trong thư mục
    tạm / mã nguồn của bài thử là dấu vết lab; ~/.netrc, sethc.exe, công cụ tải về (SOAPHound) là thứ kẻ tấn công dùng."""
    g = _golden()
    assert next(x for x in g.attack if x.label["guid"] == "g-suid").label["lab_values"] == ["/tmp/evilBinary"]
    lin, win = g.lab_tokens("linux"), g.lab_tokens("windows")
    assert {"evilbinary", "hello.c", "hello"} <= lin and not {".netrc", "netrc"} & lin
    assert {"loot_dump.bin", "loot_dump"} <= win
    assert not {"svchost", "svchost.exe", "sethc", "sethc.exe", "soaphound", "soaphound.exe"} & win


def test_recheck_blocks_lab_names_and_bare_common_programs():
    rd = {"id": "AI-154", "title": "t", "severity": "medium", "type": "match",
          "tags": ["ai-generated", "dataset-gap", "endpoint", "linux"],
          "condition": {"any": [_leaf(CL, "contains", ["/tmp/evilBinary", "u+xs"]),
                                _leaf("process.executable", "endswith", "/usr/bin/su")]}}
    problems = recheck_dataset_rule(rd, Rule.from_dict(rd), _golden())
    assert any("evilbinary" in p for p in problems), problems
    assert any("tên chương trình phổ biến" in p and "su" in p for p in problems), problems
    assert any("lệnh linux bình thường" in p for p in problems), problems          # `su` giờ có trong tập bình thường


class _DocsES:
    def __init__(self, docs):
        self.docs = {d["id"]: dict(d) for d in docs}

    def get(self, index, id):
        return {"_source": dict(self.docs[id]), "_seq_no": 1, "_primary_term": 1}

    def index(self, index, id, document, **_):
        self.docs[id] = document


def test_stale_pending_proposals_rechecked_with_current_rules():
    """Rà soát 11/10: 11/44 đề xuất cũ đang chờ duyệt sẽ bị chặn lúc duyệt nhưng vẫn giữ chỗ (target có đề xuất pending
    thì không được đề xuất lại). Mỗi chu kỳ kiểm tra lại đề xuất của generator cũ; qua được thì vẫn chờ người duyệt."""

    def prop(pid, values, gen):
        rule = {"id": f"AI-{pid}", "title": "t", "severity": "medium", "type": "match",
                "tags": ["ai-generated", "dataset-gap", "endpoint", "linux"],
                "condition": {"any": [_leaf(CL, "contains", values)]}}
        return {"id": pid, "kind": "new_rule", "target": f"gap-dataset:atomic-red-team:linux-T{pid}",
                "title": f"đề xuất {pid}", "status": "pending", "proposal": rule,
                "llm": {"model": "cũ", "generator": gen}, "history": []}

    gen = generator_id("fake")
    history = [prop("101", ["systemctl daemon-reload"], "rev9"),          # AI-155: giờ khớp lệnh bình thường
               prop("102", ["-path '*/.aws/credentials'"], "rev9"),       # vẫn qua -> vẫn chờ người duyệt
               prop("103", ["systemctl daemon-reload"], gen)]              # cùng generator: không kiểm tra lại
    es = _DocsES(history)
    w = AIWorker(es, SeqLLM([]), _golden(), rules_dir=Path("."), ds_factory=lambda e: FakeDS({}, []), save=None)
    summary = {"rechecked": []}
    w._recheck_stale(history, gen, summary)
    assert [p["status"] for p in history] == ["invalid", "pending", "pending"]
    assert es.docs["101"]["status"] == "invalid" and "lệnh linux bình thường" in es.docs["101"]["history"][-1]["text"]
    assert es.docs["102"]["status"] == "pending" and es.docs["103"]["status"] == "pending"
    assert len(summary["rechecked"]) == 1 and summary["rechecked"][0].startswith("101 ")


def test_sigmahq_unverified_atoms_capped_by_count_not_only_by_rule(tmp_path):
    """Chạy thật 11/10: AI-153 mang 44 vế SigmaHQ chưa kiểm chứng dù giới hạn 10 vế GỐC: vế gốc khớp lệnh bình thường
    bị tách nhỏ (sigma.split), mọi mảnh sạch của cùng vế gốc đều được giữ."""
    values = "".join(f"    - 'uniqueproc{i} --flag-{i}'\n" for i in range(19))
    hq = [{"id": "dddd-4444", "title": "Big rule", "author": "Tester D", "level": "high", "status": "test",
           "path": "rules/x", "logsource": {"category": "process_creation", "product": "linux"},
           "tags": ["attack.t1059.004"],
           "detection": "sel:\n  CommandLine|contains:\n    - 'systemctl daemon-reload'\n" + values + "condition: sel\n"}]
    g = _golden()
    w = AIWorker(None, SeqLLM([]), g, rules_dir=tmp_path, ds_factory=lambda e: FakeDS({}, []), save=None)
    train = [x for x in g.attack if x.label["platform"] == "linux"]

    def spare_after(atom_cap):
        spare: list = []
        w._measure_atoms(w._community_atoms(hq), "linux", train, g.normal_for("endpoint", "linux"), set(), set(), [],
                         spare=spare, cap=wk.MAX_UNVERIFIED_SIGMAHQ, atom_cap=atom_cap, report=False, budget=200)
        return spare

    assert len(spare_after(None)) == 19                       # trước 11/10: 19 mảnh của MỘT vế gốc
    assert len(spare_after(wk.MAX_UNVERIFIED_SIGMAHQ_ATOMS)) == wk.MAX_UNVERIFIED_SIGMAHQ_ATOMS


def test_ollama_restart_mid_cycle_is_retried_but_timeouts_are_not(monkeypatch):
    """10/10: Ollama khởi động lại giữa chu kỳ -> "Connection refused" / "Remote end closed connection", mất 2 đề xuất."""
    calls, waits = [], []

    def flaky(req, timeout):
        calls.append(req.full_url)
        if len(calls) == 1:
            raise urllib.error.URLError(ConnectionRefusedError(111, "Connection refused"))
        if len(calls) == 2:
            raise http.client.RemoteDisconnected("Remote end closed connection without response")
        return io.BytesIO(b'{"ok": 1}')

    monkeypatch.setattr(llm_mod.urllib.request, "urlopen", flaky)
    monkeypatch.setattr(llm_mod.time, "sleep", waits.append)
    client = llm_mod.OllamaClient("http://ollama:11434", "m")
    assert client._post("/api/chat", {}) == {"ok": 1} and waits == [10, 30] and len(calls) == 3

    def slow(req, timeout):
        calls.append(req.full_url)
        raise TimeoutError("timed out")

    calls.clear()
    monkeypatch.setattr(llm_mod.urllib.request, "urlopen", slow)
    with pytest.raises(llm_mod.LLMError):
        client._post("/api/chat", {})
    assert len(calls) == 1
