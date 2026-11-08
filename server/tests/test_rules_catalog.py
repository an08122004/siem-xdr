"""Test danh mục rule (siem-rules) cho dashboard "Thư viện rule": rule Wazuh, đề xuất AI, phát hiện nền tảng, độ phủ
ATT&CK, tóm tắt điều kiện, đồng bộ vào Elasticsearch (giả lập)."""
from __future__ import annotations

from pathlib import Path

from siem import rules_catalog as rc

CONFIG = Path(__file__).resolve().parent.parent / "config"


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


def test_proposals_detectors_and_timestamps():
    docs = by_id(rc.build(PROPOSALS, {}, today="2026-11-07T00:00:00+00:00"))
    p = docs["proposal:p-sqli"]
    assert p["origin"] == "ai_proposal" and p["proposal"]["test"] == "177/196" and p["proposal"]["fp"] == "0/10000"
    assert p["proposal"]["pick"] == "Rule mới AI-022 — SQLi không dấu nháy (chờ duyệt, p-sqli)"
    assert "sqli" in p["tags"]                                                  # loại tấn công lấy từ target
    pe = docs["proposal:p-exc"]
    assert pe["type"] == "exception" and pe["proposal"]["approvals"] == "1/2" and pe["proposal"]["fp"] == "5/5 báo nhầm khớp"
    assert all(d["@timestamp"] == d["updated_at"] for d in docs.values())
    assert docs["detector:RBA-001"]["@timestamp"] == "2026-11-07T00:00:00+00:00"
    assert not {d["origin"] for d in docs.values()} & {"rule", "exception", "comparison"}     # engine YAML đã xóa
    # mặc định: mốc ngày hiện tại (dashboard xem 20 năm: mốc 1970 thì bản ghi biến mất khỏi Grafana)
    assert rc.build([], {})[0]["@timestamp"] > "2026"


def test_catalog_detectors_and_coverage_from_wazuh_rules():
    """Phát hiện nền tảng (RBA, HLT) có bản ghi; độ phủ kỹ thuật ưu tiên tính từ rule Wazuh đang bật (R49)."""
    wazuh = [{"_id": "rule:WZH-60204", "origin": "wazuh_rule", "source": "wazuh", "rule": {"id": "WZH-60204", "name": "x"},
              "mitre": {"tactic": rc.NONE_TACTIC, "technique": ["T1110.001"]}, "tags": ["wazuh"], "fields": [rc.NONE_LIST],
              "mode": "active", "bridged": True, "shadow": False, "status": "enabled"}]
    docs = by_id(rc.build([], {"HLT-001": {"h24": 1, "d7": 4, "d90": 9}}, rc.load_profile(CONFIG), wazuh))
    assert {d["rule"]["id"] for d in docs.values() if d["origin"] == "detector"} >= {"RBA-001", "HLT-001", "HLT-006"}
    assert docs["detector:HLT-001"]["alerts"]["d90"] == 9
    cov = {d["technique"]: d for d in docs.values() if d["origin"] == "coverage"}
    assert len(cov) == 12 and cov["T1486"]["covered_text"] == "CHƯA CÓ"
    assert cov["T1110"]["rules_text"] == "WZH-60204" and cov["T1110"]["sources"] == "wazuh"
    assert docs["rule:WZH-60204"]["technique_text"] == "T1110.001"
    assert rc.load_profile(None) == {} and rc.load_profile(Path("khong-co")) == {}


class FakeES:
    def __init__(self):
        self.bulks, self.deleted, self.props = [], [], list(PROPOSALS)

    def search(self, index, **kw):
        if index == "ai-rule-proposals":
            return {"hits": {"hits": [{"_id": p["id"], "_source": p} for p in self.props]}}
        raise ConnectionError("chưa có alert")                                   # danh mục vẫn dựng được

    fail_ids: set = frozenset()

    def bulk(self, operations, refresh=None):
        self.bulks.append(operations)
        ids = [op["index"]["_id"] for op in operations if "index" in op]
        return {"errors": bool(self.fail_ids & set(ids)),
                "items": [{"index": {"_id": i, **({"status": 400, "error": "x"} if i in self.fail_ids else {"status": 200})}}
                          for i in ids]}

    def delete_by_query(self, index, query, **kw):
        self.deleted.append(query)


def test_sync_writes_once_and_removes_stale(monkeypatch):
    monkeypatch.setattr(rc, "_last_sig", None)
    monkeypatch.setattr(rc, "_doc_sigs", {})
    es = FakeES()
    n = rc.sync(es)
    ids = [op["index"]["_id"] for op in es.bulks[0] if "index" in op]
    assert n == len(ids) and "proposal:p-exc" in ids and "proposal:p-sqli" in ids
    assert es.deleted[0] == {"bool": {"must_not": [{"ids": {"values": ids}}, {"term": {"origin": "wazuh_rule"}}]}}   # bản ghi không còn -> bị xóa
    assert rc.sync(es) == 0 and len(es.bulks) == 1                                # không đổi gì -> không ghi lại
    es.props = PROPOSALS[:1]                                                      # đề xuất biến mất khỏi ai-rule-proposals
    rc.sync(es)
    assert "proposal:p-exc" not in es.deleted[-1]["bool"]["must_not"][0]["ids"]["values"]   # chỉ xóa, không bản ghi nào đổi để gửi lại


class FakeWazuh:
    """GET /rules giả lập: 2 trang (limit 1) để kiểm tra phân trang."""
    def __init__(self, fail=False):
        self.fail, self.calls = fail, []
        self.items = [
            {"id": 5710, "level": 5, "description": "sshd: thử đăng nhập user không tồn tại", "groups": ["syslog", "sshd"],
             "mitre": {"id": ["T1110"], "tactic": ["Credential Access"]}, "status": "enabled",
             "filename": "0095-sshd_rules.xml", "relative_dirname": "ruleset/rules"},
            {"id": 101010, "level": 10, "description": "Brute-force đăng nhập", "groups": ["auth", "shadow", "legacy_AUTH-001"],
             "mitre": {"id": ["T1110"], "tactic": ["Credential Access"]}, "status": "disabled",
             "filename": "ai.xml", "relative_dirname": "etc/rules-dynamic"}]

    def rules(self, offset=0, limit=500):
        self.calls.append(offset)
        if self.fail:
            raise ConnectionError("Wazuh API tắt")
        return {"data": {"affected_items": self.items[offset:offset + 1], "total_affected_items": 2}}


def test_wazuh_rule_docs_pages_and_maps(monkeypatch):
    monkeypatch.setattr(rc, "WAZUH_PAGE", 1)
    api = FakeWazuh()
    docs = {d["rule"]["id"]: d for d in rc.wazuh_rule_docs(api, {"WZH-5710": {"d7": 3}})}
    assert api.calls == [0, 1] and set(docs) == {"WZH-5710", "WZH-101010"}
    stock, proj = docs["WZH-5710"], docs["WZH-101010"]
    assert stock["severity"] == "low" and stock["shadow"] is False and stock["mode"] == "nobridge"   # R65: không còn bóng; level 5 < 7 không ra alert
    assert stock["alerts"]["d7"] == 3 and stock["mitre"]["technique"] == ["T1110"] and stock["file"] == "ruleset/rules/0095-sshd_rules.xml"
    assert proj["severity"] == "high" and proj["shadow"] is True and proj["legacy_id"] == "AUTH-001"
    assert proj["mode"] == "off" and proj["status"] == "disabled" and proj["source"] == "wazuh" and proj["origin"] == "wazuh_rule" and "legacy_id" not in stock


def test_wazuh_stock_docs_follow_shadow_setting(monkeypatch):
    """Thư viện hiển thị rule gốc level 7-11 là chính thức (R65); WAZUH_STOCK_SHADOW=true thì lại là chạy bóng."""
    api = FakeWazuh()
    api.items[0]["level"] = 8
    doc = next(d for d in rc.wazuh_rule_docs(api, {}) if d["rule"]["id"] == "WZH-5710")
    assert doc["shadow"] is False and doc["mode"] == "active"
    monkeypatch.setattr(rc.settings, "WAZUH_STOCK_SHADOW", True)
    doc = next(d for d in rc.wazuh_rule_docs(FakeWazuh(), {}) if d["rule"]["id"] == "WZH-5710")
    assert doc["shadow"] is True and doc["mode"] == "shadow"


def test_sync_includes_wazuh_and_keeps_old_on_api_error(monkeypatch):
    monkeypatch.setattr(rc, "_last_sig", None)
    monkeypatch.setattr(rc, "_doc_sigs", {})
    es = FakeES()
    rc.sync(es, api=FakeWazuh())
    ids = [op["index"]["_id"] for op in es.bulks[0] if "index" in op]
    assert "rule:WZH-5710" in ids and "proposal:p-sqli" in ids
    rc.sync(es, api=FakeWazuh(fail=True), force=True)                          # API tắt: vẫn ghi phần còn lại, không xóa rule Wazuh
    ids2 = [op["index"]["_id"] for op in es.bulks[1] if "index" in op]
    assert "rule:WZH-5710" not in ids2 and "proposal:p-sqli" in ids2
    assert {"term": {"origin": "wazuh_rule"}} in es.deleted[1]["bool"]["must_not"]
    rc.sync(es, force=True)                                                       # không truyền api: cũng không xóa rule Wazuh
    assert {"term": {"origin": "wazuh_rule"}} in es.deleted[2]["bool"]["must_not"]
    rc.sync(es, api=FakeWazuh(), force=True)                                      # lấy thành công: được dọn bản ghi Wazuh thừa
    assert es.deleted[3]["bool"]["must_not"] == [{"ids": {"values": [op["index"]["_id"] for op in es.bulks[3] if "index" in op]}}]


def test_doc_signatures_only_for_stored_docs_and_pruned(monkeypatch):
    monkeypatch.setattr(rc, "_last_sig", None)
    monkeypatch.setattr(rc, "_doc_sigs", {})
    es = FakeES()
    es.fail_ids = {"proposal:p-sqli"}
    rc.sync(es)
    sent = lambda n: [op["index"]["_id"] for op in es.bulks[n] if "index" in op]
    assert "proposal:p-sqli" not in rc._doc_sigs and "proposal:p-exc" in rc._doc_sigs  # bản ghi lỗi không có chữ ký
    es.fail_ids = set()
    rc.sync(es)
    assert sent(1) == ["proposal:p-sqli"]                                              # chỉ gửi lại bản ghi lỗi
    es.props = PROPOSALS[:1]                                                           # bỏ đề xuất rồi trả lại y nguyên
    rc.sync(es)
    assert "proposal:p-exc" not in rc._doc_sigs
    es.props = list(PROPOSALS)
    rc.sync(es)
    assert len(es.bulks) == 3 and sent(2) == ["proposal:p-exc"]                       # xuất hiện lại -> gửi lại (chỉ nó)


def test_doc_signatures_keep_wazuh_when_api_fails(monkeypatch):
    monkeypatch.setattr(rc, "_last_sig", None)
    monkeypatch.setattr(rc, "_doc_sigs", {})
    es = FakeES()
    rc.sync(es, api=FakeWazuh())
    assert "rule:WZH-5710" in rc._doc_sigs
    rc.sync(es, api=FakeWazuh(fail=True))
    assert "rule:WZH-5710" in rc._doc_sigs                                             # API lỗi: không cắt chữ ký rule Wazuh


def test_wazuh_rule_docs_not_bridged_never_counts_as_running():
    """Rule bật nhưng cầu nối bỏ (syscheck level 5, sca mọi level, rule dự án level 2) không ra alert: không "chính thức"."""
    from siem.rules_catalog import attack_coverage

    class Api:
        def rules(self, offset=0, limit=500):
            mk = lambda i, lv, g, f="x.xml", d="ruleset/rules": {"id": i, "level": lv, "groups": g, "status": "enabled", "filename": f,
                                                               "relative_dirname": d, "mitre": {"id": ["T1110"]}}
            return {"data": {"total_affected_items": 4, "affected_items": [
                mk(550, 5, ["syscheck"]), mk(19007, 12, ["sca"]), mk(101099, 2, ["auth"], "0101-auth.xml", "etc/rules"),
                mk(101100, 5, ["auth"], "0101-auth.xml", "etc/rules")]}}
    docs = {d["rule"]["id"]: d for d in rc.wazuh_rule_docs(Api(), {})}
    for rid in ("WZH-550", "WZH-19007", "WZH-101099"):
        assert docs[rid]["bridged"] is False and docs[rid]["mode"] == "nobridge" and docs[rid]["mode_label"] == "không tạo alert"
    assert docs["WZH-101100"]["bridged"] is True and docs["WZH-101100"]["mode"] in ("active", "shadow")
    only_bad = [docs[r] for r in ("WZH-550", "WZH-19007", "WZH-101099")]
    assert not attack_coverage(only_bad, {"techniques": [{"id": "T1110"}]})[0]["covered"]


def test_wazuh_rule_docs_real_api_shape_and_overwritten_rules():
    """Dạng thật của Wazuh 4.14 API (05/11): `mitre` là list mã kỹ thuật; rule gốc bị đè ở 0999-tuning.xml có 2 bản
    (ruleset/rules và etc/rules) -> một bản ghi, lấy bản đè."""
    items = [
        {"id": 5712, "level": 10, "description": "sshd brute force", "groups": ["syslog", "sshd", "authentication_failures"],
         "mitre": ["T1110"], "status": "enabled", "filename": "0095-sshd_rules.xml", "relative_dirname": "ruleset/rules"},
        {"id": 92041, "level": 10, "description": "gốc", "groups": ["windows"], "mitre": ["T1027", "T1112"],
         "status": "enabled", "filename": "0800-sysmon_id_1.xml", "relative_dirname": "ruleset/rules"},
        {"id": 92041, "level": 10, "description": "bản đè", "groups": ["windows"], "mitre": ["T1027", "T1112"],
         "status": "enabled", "filename": "0999-tuning.xml", "relative_dirname": "etc/rules"},
        {"id": 104095, "level": 14, "description": "WEB-012", "groups": ["siem", "web"], "mitre": [],
         "status": "enabled", "filename": "0271-web.xml", "relative_dirname": "etc/rules"}]

    class Api:
        def rules(self, offset=0, limit=500):
            page = items[offset:offset + 2]
            return {"data": {"affected_items": page, "total_affected_items": len(items)}}

    docs = rc.wazuh_rule_docs(Api(), {})
    by_id = {d["rule"]["id"]: d for d in docs}
    assert len(docs) == 3 and set(by_id) == {"WZH-5712", "WZH-92041", "WZH-104095"}
    assert by_id["WZH-92041"]["description"] == "bản đè" and by_id["WZH-92041"]["file"] == "etc/rules/0999-tuning.xml"
    assert by_id["WZH-5712"]["mitre"]["technique"] == ["T1110"]
    assert by_id["WZH-104095"]["mitre"]["technique"] == [rc.NONE_LIST]          # giá trị giữ chỗ cho bộ lọc Grafana
