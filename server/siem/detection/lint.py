"""Kiểm tra kho rule (detection-as-code, SOC-OPERATIONS.md mục 4) — chạy trong CI (tools/rule_lint.py, pytest) và trong
manager (độ phủ ATT&CK cho KPI). Lỗi (errors) chặn merge; lưu ý (warnings) chỉ báo.

  - metadata bắt buộc: id, title, severity, mitre (tactic + technique hợp lệ), tags, logsource, owner, falsepositives
  - rule biên dịch được, mode hợp lệ, id không trùng, regex không có nguy cơ ReDoS (mọi rule, không chỉ rule AI)
  - mỗi rule viết tay có ít nhất 1 ca test DƯƠNG và 1 ca ÂM trong rules/cases, mọi ca đạt (detection/ruletest.py)
  - mỗi rule có case playbook riêng (không rơi về PB-00 Điều tra chung)
  - ngoại lệ trỏ tới rule tồn tại
Độ phủ: kỹ thuật trong config/threat_profile.yml có rule CHẠY CHÍNH THỨC đã qua kiểm thử. Rule AI tính là đã kiểm thử
vì đã qua kiểm định trên dataset (ai/validate.py) trước khi được duyệt."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .rules import EXCEPTIONS_DIR, RULE_MODES, SEVERITY_SCORE, SKIP_DIRS, Rule, RuleException, regex_risk
from .ruletest import Result, load_cases, run_all

ID_RE = re.compile(r"^[A-Z]{2,5}-\d{3,}$")
TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
TYPES = ("match", "threshold", "sequence")
REQUIRED = ("id", "title", "severity", "mitre", "tags", "logsource", "owner", "falsepositives")


@dataclass
class RuleInfo:
    id: str
    file: str
    mode: str
    techniques: list[str]
    ai: bool
    playbook: str | None = None
    positive: int = 0
    negative: int = 0
    failed: int = 0

    @property
    def tested(self) -> bool:
        return self.ai or (self.positive > 0 and self.negative > 0 and self.failed == 0)


@dataclass
class Report:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    rules: dict[str, RuleInfo] = field(default_factory=dict)
    results: list[Result] = field(default_factory=list)
    profile: dict[str, Any] = field(default_factory=dict)
    coverage: list[dict[str, Any]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def coverage_pct(self) -> float:
        return round(100.0 * sum(1 for c in self.coverage if c["covered"]) / len(self.coverage), 1) if self.coverage else 0.0


def _regexes(spec: Any) -> list[str]:
    out: list[str] = []
    if isinstance(spec, list):
        for s in spec:
            out += _regexes(s)
    elif isinstance(spec, dict):
        for key in ("all", "any"):
            if key in spec:
                out += _regexes(spec[key])
        if "not" in spec:
            out += _regexes(spec["not"])
        if spec.get("op") == "regex":
            v = spec.get("value")
            out += [str(x) for x in (v if isinstance(v, list) else [v])]
    return out


def _docs(path: Path) -> list[dict[str, Any]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    return [d for d in (data if isinstance(data, list) else [data]) if isinstance(d, dict)]


def check_rule(d: dict[str, Any], where: str, ai: bool) -> list[str]:
    """Lỗi metadata / cú pháp của một rule (danh sách rỗng = đạt)."""
    rid = str(d.get("id", "?"))
    errs = [f"{where} {rid}: thiếu `{k}`" for k in REQUIRED if d.get(k) in (None, "", [], {})]
    if d.get("id") and not ID_RE.match(rid):
        errs.append(f"{where} {rid}: id phải dạng ABC-001")
    if str(d.get("severity", "")).lower() not in SEVERITY_SCORE:
        errs.append(f"{where} {rid}: severity phải là low | medium | high | critical")
    if d.get("type", "match") not in TYPES:
        errs.append(f"{where} {rid}: type phải là match | threshold | sequence")
    if str(d.get("mode", "active")).lower() not in RULE_MODES:
        errs.append(f"{where} {rid}: mode phải là active | shadow")
    mitre = d.get("mitre") or {}
    techs = mitre.get("technique") if isinstance(mitre, dict) else None
    techs = techs if isinstance(techs, list) else [techs] if techs else []
    if not techs or any(not TECH_RE.match(str(t)) for t in techs):
        errs.append(f"{where} {rid}: mitre.technique phải là danh sách mã kỹ thuật hợp lệ (T1059, T1059.001)")
    if isinstance(mitre, dict) and not mitre.get("tactic"):
        errs.append(f"{where} {rid}: thiếu mitre.tactic")
    if d.get("falsepositives") and not (isinstance(d["falsepositives"], list)
                                        and all(isinstance(x, str) and x.strip() for x in d["falsepositives"])):
        errs.append(f"{where} {rid}: falsepositives phải là danh sách câu mô tả")
    if d.get("logsource") and not isinstance(d["logsource"], dict):
        errs.append(f"{where} {rid}: logsource phải có dạng {{product: ..., category: ...}}")
    try:
        Rule.from_dict(d)
    except Exception as e:  # noqa: BLE001
        errs.append(f"{where} {rid}: không biên dịch được: {e}")
    specs = [d.get("condition")] + [st.get("condition") for st in (d.get("sequence") or {}).get("steps") or []] + \
        [ex.get("condition") for ex in d.get("exceptions") or []]
    for pat in _regexes(specs):
        if (why := regex_risk(pat)):
            errs.append(f"{where} {rid}: {why}: {pat[:80]}")
    return errs


def load_profile(config_dir: Path | None) -> dict[str, Any]:
    path = config_dir / "threat_profile.yml" if config_dir else None
    if not path or not path.exists():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def covers(technique: str, rule_techniques: list[str]) -> bool:
    return any(t == technique or t.startswith(technique + ".") for t in rule_techniques)


def lint(rules_dir: Path, config_dir: Path | None = None, run_cases: bool = True) -> Report:
    rep = Report()
    compiled: dict[str, Rule] = {}
    for path in sorted(rules_dir.glob("**/*.y*ml")):
        rel = path.relative_to(rules_dir)
        if set(SKIP_DIRS) & set(rel.parts):
            continue
        where, ai = str(rel).replace("\\", "/"), rel.parts[0] == "ai"
        try:
            docs = _docs(path)
        except yaml.YAMLError as e:
            rep.errors.append(f"{where}: YAML lỗi: {e}")
            continue
        for d in docs:
            if d.get("enabled", True) is False:
                continue
            rid = str(d.get("id", "?"))
            if rid in rep.rules:
                rep.errors.append(f"{where} {rid}: trùng id với {rep.rules[rid].file}")
                continue
            errs = check_rule(d, where, ai)
            rep.errors += errs
            mitre = d.get("mitre") if isinstance(d.get("mitre"), dict) else {}
            techs = mitre.get("technique") or []
            info = RuleInfo(rid, where, str(d.get("mode", "active")).lower(),
                            [str(t) for t in (techs if isinstance(techs, list) else [techs])], ai)
            rep.rules[rid] = info
            if not errs:
                compiled[rid] = Rule.from_dict(d)
                compiled[rid].source_file = where
            if info.mode == "shadow" and not d.get("shadow_since"):
                rep.warnings.append(f"{where} {rid}: chạy bóng nhưng thiếu shadow_since (ngày bắt đầu chạy bóng)")
    for path in sorted((rules_dir / EXCEPTIONS_DIR).glob("*.y*ml")):
        for d in _docs(path):
            try:
                ex = RuleException.from_dict(d)
            except Exception as e:  # noqa: BLE001
                rep.errors.append(f"{EXCEPTIONS_DIR}/{path.name}: ngoại lệ lỗi: {e}")
                continue
            if ex.rule_id not in rep.rules:
                rep.errors.append(f"{EXCEPTIONS_DIR}/{path.name}: ngoại lệ {ex.id} trỏ tới rule không tồn tại {ex.rule_id}")
    _playbooks(rep, config_dir)
    if run_cases:
        _cases(rep, rules_dir, compiled)
    _coverage(rep, config_dir)
    return rep


def _playbooks(rep: Report, config_dir: Path | None) -> None:
    path = config_dir / "case_playbooks.yml" if config_dir else None
    if not path or not path.exists():
        return
    from ..soar.cases import CasePlaybooks
    cp = CasePlaybooks(path)
    for info in rep.rules.values():
        pb, _ = cp.select(info.id, info.techniques, [])
        info.playbook = pb["id"] if pb else None
        if info.playbook in (None, "PB-00"):
            (rep.warnings if info.ai else rep.errors).append(
                f"{info.file} {info.id}: không có case playbook riêng (rơi về PB-00 Điều tra chung)")


def _cases(rep: Report, rules_dir: Path, compiled: dict[str, Rule]) -> None:
    cases_dir = rules_dir / "cases"
    try:
        cases = load_cases(cases_dir) if cases_dir.exists() else []
    except ValueError as e:
        rep.errors.append(f"cases: {e}")
        return
    rep.results = run_all(compiled, cases)
    for r in rep.results:
        info = rep.rules.get(r.case.rule)
        if not info:
            rep.errors.append(f"cases/{r.case.source}: rule {r.case.rule} không tồn tại")
            continue
        if r.case.expect == "alert":
            info.positive += 1
        else:
            info.negative += 1
        if not r.ok:
            info.failed += 1
            rep.errors.append(f"cases/{r.case.source} {r.case.rule} «{r.case.name}»: mong đợi "
                              f"{'bắn' if r.case.expect == 'alert' else 'không bắn'}, thực tế {r.detail}")
    for info in rep.rules.values():
        if info.ai or (info.positive and info.negative):
            continue
        missing = " và ".join(x for x, n in (("ca dương", info.positive), ("ca âm", info.negative)) if not n)
        rep.errors.append(f"{info.file} {info.id}: thiếu {missing} trong rules/cases")


def _coverage(rep: Report, config_dir: Path | None) -> None:
    rep.profile = load_profile(config_dir)
    for t in rep.profile.get("techniques") or []:
        tid = str(t["id"])
        active = [r.id for r in rep.rules.values() if r.mode == "active" and r.tested and covers(tid, r.techniques)]
        shadow = [r.id for r in rep.rules.values() if r.mode == "shadow" and covers(tid, r.techniques)]
        rep.coverage.append({"id": tid, "name": t.get("name", ""), "why": t.get("why", ""), "covered": bool(active),
                             "rules": active, "shadow": shadow})


def attack_layer(rep: Report, name: str = "SOC Platform - độ phủ rule") -> dict[str, Any]:
    """Layer cho MITRE ATT&CK Navigator: điểm = số rule chạy chính thức; kỹ thuật ưu tiên chưa có rule tô đỏ."""
    by_tech: dict[str, list[str]] = {}
    for r in rep.rules.values():
        if r.mode != "active":
            continue
        for t in r.techniques:
            by_tech.setdefault(t, []).append(r.id)
    priority = {c["id"] for c in rep.coverage}
    techniques = [{"techniqueID": t, "score": len(ids), "comment": ", ".join(sorted(ids)),
                   **({"color": "#2e7d32"} if t.split(".")[0] in priority else {})}
                  for t, ids in sorted(by_tech.items())]
    techniques += [{"techniqueID": c["id"], "score": 0, "color": "#e2474b",
                    "comment": "kỹ thuật ưu tiên (threat_profile.yml) chưa có rule chạy chính thức đã kiểm thử"}
                   for c in rep.coverage if not c["covered"]]
    return {"name": name, "domain": "enterprise-attack",
            "versions": {"layer": "4.5", "navigator": "5.1.0"},
            "description": f"Sinh bởi tools/rule_lint.py từ server/rules. Độ phủ kỹ thuật ưu tiên: {rep.coverage_pct()}%.",
            "techniques": techniques,
            "gradient": {"colors": ["#ffffff", "#66b1ff"], "minValue": 0, "maxValue": 3},
            "legendItems": [{"label": "Kỹ thuật ưu tiên có rule", "color": "#2e7d32"},
                            {"label": "Kỹ thuật ưu tiên chưa có rule", "color": "#e2474b"}]}


def markdown(rep: Report) -> str:
    passed = sum(r.ok for r in rep.results)
    lines = [f"## Kiểm tra kho rule: {'ĐẠT' if rep.ok else 'KHÔNG ĐẠT'}", "",
             f"- {len(rep.rules)} rule ({sum(r.mode == 'shadow' for r in rep.rules.values())} chạy bóng), "
             f"{len(rep.results)} ca test ({passed} đạt)",
             f"- Lỗi: {len(rep.errors)}, lưu ý: {len(rep.warnings)}",
             f"- Độ phủ kỹ thuật ưu tiên ({rep.profile.get('name', 'threat_profile.yml')}): {rep.coverage_pct()}%", ""]
    if rep.coverage:
        lines += ["| Kỹ thuật | Tên | Rule chạy chính thức | Đang chạy bóng |", "|---|---|---|---|"]
        lines += [f"| {c['id']} | {c['name']} | {', '.join(c['rules']) or '**chưa có**'} | {', '.join(c['shadow']) or ''} |"
                  for c in rep.coverage]
        lines.append("")
    for title, items in (("Lỗi", rep.errors), ("Lưu ý", rep.warnings)):
        if items:
            lines += [f"### {title}", ""] + [f"- {x}" for x in items] + [""]
    return "\n".join(lines)
