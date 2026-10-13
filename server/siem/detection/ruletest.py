"""Test rule dạng dữ liệu (detection-as-code, SOC-OPERATIONS.md mục 4): mỗi rule có ít nhất một ca DƯƠNG (phải bắn) và
một ca ÂM (gần giống nhưng hợp lệ, không được bắn). Ca test nằm cùng kho rule, ở server/rules/cases/*.yml:

    - rule: WEB-004
      name: tham số tên id sau dấu & không phải lệnh
      expect: none                  # alert | none
      events:                       # theo thứ tự; @timestamp tự đánh T0 + i*step nếu thiếu
        - {event: {category: web}, url: {decoded: "/p.php?page=2&id=5"}}     # event đã chuẩn hóa
        - {apache: "GET /p.php?page=2&id=5 HTTP/1.1", status: 200}           # dòng access log -> qua normalize
        - {times: 5, event: {...}}                                            # lặp 5 lần
      repeat: 30                    # tùy chọn: lặp cả danh sách events (rule ngưỡng)
      vary: {field: user.name, values: [a, b, c]}   # tùy chọn: lần lặp thứ i đặt field = values[i % len]
      step: 1                       # giây giữa hai event

Chạy: tools/rule_lint.py (CI) hoặc pytest (tests/test_rule_lint.py)."""
from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from ..pipeline.normalize import Doc, normalize, put
from .rules import Rule, RuleEngine

T0 = datetime(2026, 1, 5, 9, 0, 0, tzinfo=timezone.utc)
EXPECT = ("alert", "none")


@dataclass
class Case:
    rule: str
    name: str
    expect: str
    spec: dict[str, Any]
    source: str


@dataclass
class Result:
    case: Case
    ok: bool
    fired: int
    detail: str = ""


def load_cases(cases_dir: Path) -> list[Case]:
    cases = []
    for path in sorted(cases_dir.glob("*.y*ml")):
        for i, d in enumerate(yaml.safe_load(path.read_text(encoding="utf-8")) or []):
            where = f"{path.name}#{i + 1}"
            if not isinstance(d, dict) or not d.get("rule") or d.get("expect") not in EXPECT or not d.get("events"):
                raise ValueError(f"{where}: ca test cần rule, expect (alert|none), events")
            cases.append(Case(str(d["rule"]), str(d.get("name") or where), d["expect"], d, where))
    return cases


def _apache(item: dict[str, Any], ts: datetime) -> Doc:
    t = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
    ip, ua = item.get("ip", "203.0.113.50"), item.get("ua", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/129.0")
    line = f'{ip} - - [{t}] "{item["apache"]}" {item.get("status", 200)} 512 "-" "{ua}"'
    return normalize({"timestamp": ts.isoformat(), "agent_id": "case-web", "hostname": "case-web", "os": "linux",
                      "source": "file", "event_type": "apache_access", "data": {"message": line}})


def expand(spec: dict[str, Any]) -> list[Doc]:
    """Danh sách event (đã chuẩn hóa) theo đặc tả của ca test."""
    base: list[dict[str, Any]] = []
    for item in spec["events"]:
        for _ in range(int(item.get("times", 1)) if isinstance(item, dict) and "times" in item else 1):
            base.append(item)
    vary = spec.get("vary") or {}
    step = float(spec.get("step", 1))
    docs: list[Doc] = []
    for rep in range(int(spec.get("repeat", 1))):
        for item in base:
            ts = T0 + timedelta(seconds=step * len(docs))
            if "apache" in item:
                doc = _apache(item, ts)
            else:
                doc = copy.deepcopy(item.get("event", item) if "times" in item else item)
                doc.setdefault("@timestamp", ts.isoformat())
                doc.setdefault("event", {}).setdefault("id", f"case-{len(docs)}")
            if vary:
                vals = vary["values"]
                put(doc, vary["field"], vals[rep % len(vals)] if spec.get("repeat") else vals[len(docs) % len(vals)])
            docs.append(doc)
    return docs


def run_case(rule: Rule, case: Case) -> Result:
    eng = RuleEngine([rule])
    fired = 0
    try:
        for doc in expand(case.spec):
            fired += sum(1 for d in eng.process(doc) if d.rule.id == rule.id)
    except Exception as e:  # noqa: BLE001 - đặc tả hỏng: báo lỗi của ca, không làm dừng cả bộ
        return Result(case, False, fired, f"lỗi khi chạy: {e}")
    ok = (fired > 0) == (case.expect == "alert")
    return Result(case, ok, fired, "" if ok else ("không bắn" if case.expect == "alert" else f"bắn {fired} lần"))


def run_all(rules: dict[str, Rule], cases: list[Case]) -> list[Result]:
    out = []
    for c in cases:
        if c.rule not in rules:
            out.append(Result(c, False, 0, f"rule {c.rule} không tồn tại"))
        else:
            out.append(run_case(rules[c.rule], c))
    return out
