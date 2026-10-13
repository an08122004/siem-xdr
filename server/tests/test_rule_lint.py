"""Detection-as-code: kho rule thật phải đạt lint (metadata, ReDoS, ca test dương / âm, playbook riêng), và lint phải bắt
được từng loại lỗi. Chạy cùng CI (.github/workflows/ci.yml) và tools/rule_lint.py."""
from __future__ import annotations

import shutil
import textwrap
from pathlib import Path

import pytest

from siem.detection.lint import attack_layer, check_rule, lint
from siem.detection.rules import Rule, load_rules

ROOT = Path(__file__).resolve().parent.parent

GOOD = {"id": "TST-001", "title": "thử", "severity": "high", "type": "match",
        "mitre": {"tactic": "Execution", "technique": ["T1059.004"]}, "tags": ["linux"],
        "logsource": {"product": "linux", "category": "process_creation"}, "owner": "detection-engineering",
        "falsepositives": ["quản trị viên"], "condition": {"field": "process.name", "op": "eq", "value": "nc"}}


def test_repository_rules_pass_lint():
    rep = lint(ROOT / "rules", ROOT / "config")
    assert rep.errors == [], "\n".join(rep.errors)
    assert len(rep.rules) >= 40 and all(r.positive and r.negative for r in rep.rules.values() if not r.ai)
    assert all(r.ok for r in rep.results) and len(rep.results) >= 80
    assert {c["id"] for c in rep.coverage if not c["covered"]} <= {"T1547", "T1486"}    # 10/12 kỹ thuật ưu tiên
    layer = attack_layer(rep)
    assert layer["domain"] == "enterprise-attack" and layer["versions"]["layer"] == "4.5"
    ids = {t["techniqueID"] for t in layer["techniques"]}
    assert {"T1190", "T1003.001", "T1486"} <= ids


@pytest.mark.parametrize("change, expect", [
    ({"logsource": None}, "thiếu `logsource`"),
    ({"owner": ""}, "thiếu `owner`"),
    ({"falsepositives": []}, "thiếu `falsepositives`"),
    ({"mitre": {"tactic": "Execution", "technique": ["T59"]}}, "mitre.technique"),
    ({"mitre": {"technique": ["T1059"]}}, "mitre.tactic"),
    ({"id": "abc"}, "id phải dạng"),
    ({"mode": "test"}, "mode phải là"),
    ({"severity": "urgent"}, "severity"),
    ({"condition": {"field": "url.decoded", "op": "regex", "value": "union(\\s|/\\*.*?\\*/|\\+)+select"}}, "ReDoS"),
])
def test_check_rule_reports_each_problem(change, expect):
    d = {k: v for k, v in (GOOD | change).items() if v is not None}
    errs = check_rule(d, "x.yml", ai=False)
    assert any(expect in e for e in errs), errs
    assert check_rule(GOOD, "x.yml", ai=False) == []


def test_redos_regex_is_not_loaded_by_analyzer(tmp_path):
    """Regex quay lui theo cấp số nhân (WEB-001 cũ) làm một request treo analyzer: rule bị từ chối khi nạp, rule khác
    vẫn chạy."""
    bad = GOOD | {"id": "TST-002", "condition": {"field": "url.decoded", "op": "regex",
                                               "value": "union(\\s|/\\*.*?\\*/|\\+)+(all\\s+)?select"}}
    with pytest.raises(ValueError, match="ReDoS"):
        Rule.from_dict(bad)
    import yaml
    (tmp_path / "r.yml").write_text(yaml.safe_dump([GOOD, bad], allow_unicode=True), encoding="utf-8")
    assert [r.id for r in load_rules(tmp_path)] == ["TST-001"]


def _repo_copy(tmp_path: Path) -> tuple[Path, Path]:
    rules, config = tmp_path / "rules", tmp_path / "config"
    shutil.copytree(ROOT / "rules", rules)
    shutil.copytree(ROOT / "config", config)
    return rules, config


def test_lint_requires_positive_and_negative_cases_that_pass(tmp_path):
    rules, config = _repo_copy(tmp_path)
    (rules / "extra.yml").write_text(textwrap.dedent("""\
        - id: LNX-901
          title: netcat
          severity: high
          mitre: {tactic: Execution, technique: [T1059.004]}
          tags: [linux]
          logsource: {product: linux, category: process_creation}
          owner: detection-engineering
          falsepositives: [quản trị viên chẩn đoán mạng]
          type: match
          condition: {field: process.name, op: eq, value: nc}
        - id: LNX-901
          title: trùng id
          severity: low
          mitre: {tactic: Execution, technique: [T1059]}
          tags: [linux]
          logsource: {product: linux}
          owner: x
          falsepositives: [x]
          condition: {field: process.name, op: eq, value: x}
        """), encoding="utf-8")
    (rules / "cases" / "extra.yml").write_text(textwrap.dedent("""\
        - rule: LNX-901
          name: nc bắn
          expect: alert
          events:
            - {event: {category: process}, process: {name: ncat}}
        """), encoding="utf-8")
    rep = lint(rules, config)
    text = "\n".join(rep.errors)
    assert "trùng id" in text
    assert "LNX-901 «nc bắn»: mong đợi bắn, thực tế không bắn" in text        # ca dương sai -> báo lỗi
    assert "LNX-901: thiếu ca âm" in text


def test_lint_flags_rule_without_specific_case_playbook(tmp_path):
    rules, config = _repo_copy(tmp_path)
    (rules / "extra.yml").write_text(textwrap.dedent("""\
        - id: ZZZ-001
          title: kỹ thuật không có playbook
          severity: low
          mitre: {tactic: Collection, technique: [T1005]}
          tags: [x]
          logsource: {product: linux}
          owner: x
          falsepositives: [x]
          condition: {field: a, op: exists}
        """), encoding="utf-8")
    rep = lint(rules, config)
    assert any("ZZZ-001: không có case playbook riêng" in e for e in rep.errors)
