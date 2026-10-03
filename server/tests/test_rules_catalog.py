"""Test danh mục rule (siem-rules) cho dashboard "Thư viện rule": đọc rule / ngoại lệ / đề xuất AI, tóm tắt điều kiện,
ghép đề xuất với rule hiện có liên quan, đồng bộ vào Elasticsearch (giả lập)."""
from __future__ import annotations

import textwrap

import pytest

from siem import rules_catalog as rc


@pytest.fixture()
def rules_dir(tmp_path):
    (tmp_path / "ai").mkdir()
    (tmp_path / "exceptions").mkdir()
    (tmp_path / "web.yml").write_text(textwrap.dedent("""
        - id: WEB-001
          title: Tấn công SQL Injection
          severity: high
          mitre: {tactic: Initial Access, technique: [T1190]}
          tags: [web, sqli]
          type: match
          condition:
            all:
              - {field: event.category, op: eq, value: web}
              - {field: url.decoded, op: regex, value: ["union\\\\s+select", "'\\\\s*or\\\\s*1=1"]}
        - id: WEB-099
          title: Rule đã tắt
          enabled: false
          condition: {field: url.path, op: eq, value: /x}
        """), encoding="utf-8")
    (tmp_path / "auth.yml").write_text(textwrap.dedent("""
        - id: AUTH-001
          title: Brute-force đăng nhập
          severity: medium
          mitre: {tactic: Credential Access, technique: [T1110]}
          tags: [auth, bruteforce]
          type: threshold
          condition:
            - {field: event.category, op: eq, value: authentication}
            - {field: event.outcome, op: eq, value: failure}
          threshold: {group_by: [source.ip], count: 5, window: 60, distinct: user.name}
        """), encoding="utf-8")
    (tmp_path / "ai" / "AI-021.yml").write_text(textwrap.dedent("""
        - id: AI-021
          title: Dò thư mục nhạy cảm
          severity: medium
          tags: [ai-generated, web, sensitive-path]
          condition: {any: [{field: url.path, op: startswith, value: [/_vti_bin, /cfide, /msadc, /iisadmpwd, /scripts]}]}
          ai_proposal_id: p-old
        """), encoding="utf-8")
    (tmp_path / "exceptions" / "EXC-1.yml").write_text(textwrap.dedent("""
        - id: EXC-1
          rule_id: AUTH-001
          description: máy quét được phép
          condition: {all: [{field: source.ip, op: eq, value: 10.0.0.5}]}
          source: manual
        """), encoding="utf-8")
    return tmp_path


PROPOSALS = [
    {"id": "p-sqli", "kind": "new_rule", "status": "pending", "target": "gap-dataset:csic2010:sqli", "target_rule_id": "AI-022",
     "title": "Rule mới AI-022 — SQLi không dấu nháy", "created_at": "2026-10-01T00:00:00+00:00",
     "updated_at": "2026-10-01T00:00:00+00:00", "approvals": [], "required_approvals": 1, "yaml": "- id: AI-022\n",
     "proposal": {"id": "AI-022", "title": "SQLi không dấu nháy", "severity": "medium", "type": "match",
                  "mitre": {"tactic": "Initial Access", "technique": []}, "tags": ["ai-generated", "dataset-gap", "web"],
                  "condition": {"any": [{"field": "url.decoded", "op": "contains", "value": ["and 1=1", "or 1=1"]}]}},
     "validation": {"passed": True, "risk": "thấp", "metrics": {"test_total": 196, "test_detected": 177, "test_recall": 0.903,
                                                                "normal_total": 10000, "normal_hits": 0, "alerts_per_day": 0.25}}},
    {"id": "p-exc", "kind": "exception", "status": "invalid", "target": "exception:AUTH-001", "target_rule_id": "AUTH-001",
     "title": "Ngoại lệ cho AUTH-001", "created_at": "2026-10-02T00:00:00+00:00", "approvals": [{"by": "an"}],
     "required_approvals": 2, "proposal": {"rule_id": "AUTH-001", "condition": {"all": [{"field": "source.ip", "op": "eq", "value": "10.50.0.7"}]}},
     "validation": {"passed": False, "metrics": {"fp_total": 5, "fp_matched": 5}}},
]


def by_id(docs):
    return {d["_id"]: d for d in docs}


def test_condition_summary_and_fields():
    assert rc.summarize({"all": [{"field": "a", "op": "eq", "value": 1}, {"any": [{"field": "b", "op": "contains", "value": ["x", "y"]},
                                                                                 {"not": {"field": "c", "op": "exists"}}]}]}) \
        == "a = 1 VÀ (b chứa [x, y] HOẶC KHÔNG (có trường c))"
    assert rc.summarize({"field": "u", "op": "in", "value": list("abcdef")}) == "u thuộc [a, b, c, d, +2]"
    text, fields = rc.rule_text({"type": "sequence", "sequence": {"within": 120, "group_by": ["host.name"], "steps": [
        {"condition": {"field": "event.action", "op": "eq", "value": "logon_failed"}, "count": 3},
        {"condition": {"field": "event.action", "op": "eq", "value": "logon"}}]}})
    assert text == "bước 1: event.action = logon_failed (≥3 lần); bước 2: event.action = logon — trong 120 giây, theo host.name"
    assert fields == {"event.action", "host.name"}


def test_rules_exceptions_and_proposals(rules_dir):
    docs = by_id(rc.build(rules_dir, PROPOSALS, {"WEB-001": {"h24": 3, "d7": 10, "last": "2026-10-03T10:00:00Z"}}))
    web = docs["rule:WEB-001"]
    assert web["origin"] == "rule" and web["source"] == "builtin" and web["file"] == "web.yml"
    assert web["alerts"] == {"h24": 3, "d7": 10, "last": "2026-10-03T10:00:00Z"}
    assert web["mitre"] == {"tactic": "Initial Access", "technique": ["T1190"]} and "event.category" in web["fields"]
    assert "rule:WEB-099" not in docs                                           # rule tắt không nằm trong danh mục
    auth = docs["rule:AUTH-001"]
    assert auth["condition_text"].endswith("— đếm ≥5 trong 60 giây, user.name khác nhau, theo source.ip")
    assert {"source.ip", "user.name"} <= set(auth["fields"]) and auth["alerts"]["d7"] == 0
    ai = docs["rule:AI-021"]
    assert ai["source"] == "ai" and ai["origin_label"] == "Rule AI (đã duyệt)" and ai["ai_proposal_id"] == "p-old"
    assert ai["mitre"]["tactic"] == rc.NONE_TACTIC and ai["mitre"]["technique"] == [rc.NONE_LIST]   # chỗ trống vẫn lọc được
    exc = docs["exception:EXC-1"]
    assert exc["rule"] == {"id": "AUTH-001", "name": "Brute-force đăng nhập"} and exc["condition_text"] == "bỏ qua khi source.ip = 10.0.0.5"
    p = docs["proposal:p-sqli"]
    assert p["origin"] == "ai_proposal" and p["proposal"]["test"] == "177/196" and p["proposal"]["fp"] == "0/10000"
    assert p["proposal"]["pick"] == "Rule mới AI-022 — SQLi không dấu nháy (chờ duyệt, p-sqli)"
    assert "sqli" in p["tags"]                                                  # loại tấn công lấy từ target
    pe = docs["proposal:p-exc"]
    assert pe["type"] == "exception" and pe["proposal"]["approvals"] == "1/2" and pe["proposal"]["fp"] == "5/5 báo nhầm khớp"
    assert all(d["@timestamp"] == d["updated_at"] for d in docs.values())


def test_proposals_are_paired_with_related_rules(rules_dir):
    docs = by_id(rc.build(rules_dir, PROPOSALS, {}))
    sqli = [d for d in docs.values() if d["origin"] == "comparison" and d["proposal"]["id"] == "p-sqli"]
    assert sqli[0]["rule"]["id"] == "WEB-001"                                    # liên quan nhất xếp đầu
    assert {"cùng loại tấn công sqli", "cùng xét trường url.decoded", "cùng tactic Initial Access"} <= set(sqli[0]["reasons"])
    assert sqli[0]["proposal"]["condition_text"] == "url.decoded chứa [and 1=1, or 1=1]"     # 2 điều kiện cạnh nhau
    assert "cùng tag ai-generated" not in sqli[0]["reasons_text"]               # tag chung chung không tính
    assert "AUTH-001" not in {d["rule"]["id"] for d in sqli}                     # không liên quan -> không ghép
    exc = docs["cmp:p-exc:AUTH-001"]
    assert exc["reasons"][0] == "ngoại lệ áp dụng cho chính rule này" and exc["score"] >= 10


def test_common_traits_weigh_little_and_shared_patterns_count():
    """T1190 / url.decoded có ở mọi rule web: không đủ để coi là liên quan. Cùng loại tấn công (từ vựng AI ánh xạ sang
    tag viết tay) và cùng chuỗi mẫu thì có."""
    def rule(rid, tags, values, field="url.decoded"):
        return {"rule": {"id": rid, "name": rid}, "type": "match", "tags": tags, "fields": [field],
                "mitre": {"tactic": "Initial Access", "technique": ["T1190"]}, "patterns": sorted(rc.pattern_tokens(
                    {"field": field, "op": "contains", "value": values})), "severity": "high", "source": "builtin",
                "file": "web.yml", "condition_text": "", "alerts": {}}
    rules = [rule("WEB-001", ["web", "sqli"], ["union select"]), rule("WEB-003", ["web", "lfi"], ["../", "/etc/passwd"]),
             rule("WEB-005", ["web", "scanner"], ["nikto", "sqlmap"]), rule("WEB-006", ["web", "dirbusting"], ["/_vti_bin", "/.git"]),
             rule("LNX-005", ["linux", "recon"], ["whoami", "uname"], field="process.command_line")]
    prop = {"rule": {"id": "AI-030", "name": "dò đường dẫn"}, "type": "match", "tags": ["sensitive-path"],   # AI không gắn tag web
            "attack": {"key": "sensitive-path", "tags": sorted(rc.ATTACK_TAGS["sensitive-path"])}, "fields": ["url.decoded"],
            "mitre": {"tactic": "Initial Access", "technique": ["T1190"]}, "updated_at": "x", "condition_text": "",
            "severity": "medium", "patterns": sorted(rc.pattern_tokens({"field": "url.path", "op": "startswith", "value": ["/_vti_bin", "/cfide"]})),
            "proposal": {"id": "p", "pick": "p", "kind_label": "Rule mới", "status_label": "chờ duyệt"}}
    docs = {d["rule"]["id"]: d for d in rc.comparison_docs([prop], rules)}
    assert "WEB-001" not in docs and "WEB-003" not in docs            # chỉ chung T1190 / url.decoded / tactic -> không ghép
    assert "LNX-005" not in docs                                     # "recon" trên Linux khác lĩnh vực dò quét web
    assert "cùng loại tấn công dirbusting" in docs["WEB-006"]["reasons"] and "cùng bắt chuỗi _vti_bin" in docs["WEB-006"]["reasons"]
    assert docs["WEB-006"]["score"] > docs["WEB-005"]["score"]       # WEB-006 vừa cùng loại vừa cùng chuỗi mẫu
    assert any("nhiều rule cùng có" in r for r in docs["WEB-006"]["reasons"])   # đặc điểm phổ biến được ghi rõ là yếu
    assert rc.pattern_tokens({"all": [{"field": "event.category", "op": "eq", "value": "web"},
                                      {"field": "url.decoded", "op": "regex", "value": "union(\\s|/\\*)+select"}]}) == {"union", "select"}


class FakeES:
    def __init__(self):
        self.bulks, self.deleted = [], []

    def search(self, index, **kw):
        if index == "ai-rule-proposals":
            return {"hits": {"hits": [{"_id": p["id"], "_source": p} for p in PROPOSALS]}}
        raise ConnectionError("chưa có alert")                                   # danh mục vẫn dựng được

    def bulk(self, operations, refresh=None):
        self.bulks.append(operations)
        return {"errors": False, "items": []}

    def delete_by_query(self, index, query, **kw):
        self.deleted.append(query)


def test_sync_writes_once_and_removes_stale(rules_dir, monkeypatch):
    monkeypatch.setattr(rc, "_last_sig", None)
    es = FakeES()
    n = rc.sync(es, rules_dir)
    ids = [op["index"]["_id"] for op in es.bulks[0] if "index" in op]
    assert n == len(ids) and "rule:WEB-001" in ids and "proposal:p-sqli" in ids
    assert es.deleted[0] == {"bool": {"must_not": [{"ids": {"values": ids}}]}}   # rule bị xóa / gỡ -> bản ghi cũ bị xóa
    assert rc.sync(es, rules_dir) == 0 and len(es.bulks) == 1                     # không đổi gì -> không ghi lại
    (rules_dir / "ai" / "AI-021.yml").unlink()                                    # gỡ rule AI
    rc.sync(es, rules_dir)
    assert "rule:AI-021" not in [op["index"]["_id"] for op in es.bulks[1] if "index" in op]
