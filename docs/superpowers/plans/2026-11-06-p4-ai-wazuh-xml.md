# P4 — Rule AI và SigmaHQ ra Wazuh XML: kế hoạch triển khai

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cho AI sinh rule và bộ nhập SigmaHQ hoạt động trở lại sau khi chuyển hẳn sang Wazuh XML (R65). Cả hai phải ra rule Wazuh XML và được kiểm định trên chính Wazuh. Sau đó xóa hẳn engine YAML.

**Architecture:**
- Cây điều kiện Python của `sigma.compile_rule` vẫn là bộ tìm nhanh. Vòng tách / nới / tổng quát hóa vế cần chạy lại hàng trăm lần.
- Ứng viên cuối được dịch sang XML (`ai/wazuh_xml.emit`) rồi bơm log thô của dataset vào một manager Wazuh cô lập (`wazuh-sandbox`). Ngưỡng tính trên alert Wazuh thật: Wazuh là cổng quyết định.
- Rule đạt được ghi vào `rules-dynamic/ai.xml` ở chế độ bóng (nhóm `shadow`). Bật chính thức hay gỡ đều dựng lại file từ các đề xuất đã triển khai trong ES.
- SigmaHQ dùng cùng bộ dịch, ghi `0966-sigmahq.xml` tĩnh và kiểm bằng CI.

**Tech Stack:** Python 3.12 (pytest), Wazuh manager 4.14.8 (pcre2, analysisd queue socket), Docker Compose (profile `ai`), Elasticsearch 8 (index `ai-rule-proposals`, `siem-alerts`), Ollama `qwen3.5:9b`.

**Spec (đọc kèm):**
- `docs/superpowers/plans/2026-10-31-wazuh-unified-ruleset.md`: mục P4 (Task 19–24 dạng phác thảo), kết quả đo S1/S2.
- `docs/wazuh-ruleset-decisions.md`: R1–R65.
- `AI-README.md` §9.

## Hiện trạng (đo 06/11/2026, main 597cd5d)

- `RULE_ENGINE_ENABLED=false`. `ai/deploy.py:_need_engine` trả 409 cho duyệt / bật / gỡ.
- Index `ai-rule-proposals` có 178 đề xuất: 145 invalid, 32 pending, 0 đã triển khai. Vì vậy không phải chuyển rule AI cũ nào.
- Worker chết **cả hai nhánh**, không chỉ nhánh rule mới:
  - (1) ngoại lệ cho rule ồn: duyệt `load_rules()` YAML, mà rule YAML không còn ra alert;
  - (2) khoảng trống dataset: `golden.event_hit` chạy rule YAML.
- Đã có sẵn:
  - `wazuh_rules.write_dynamic`: khôi phục và reload lại khi lỗi;
  - `wazuh_exceptions.add/approve/remove`: hai người duyệt, R48;
  - cơ chế bóng cho rule Wazuh: nhóm `shadow` + `<info>shadow_since=…`. `detection/alerts.py:141` đánh dấu `alert.shadow`, SOAR bỏ qua (R59), lint đòi `shadow_since` (R63/R65);
  - bộ dựng log thô từ dataset: `tools/wazuh_coverage.py`. Hàm `sysmon_message` và `load_items` cho CSIC, Atomic, tiến trình thường;
  - bơm hàng đợi analysisd kèm canary: `tools/wazuh_rule_test.inject`, `wazuh_coverage.run_wazuh`.

## Quyết định thiết kế (ghi vào `docs/wazuh-ruleset-decisions.md` ở Task 26)

| # | Quyết định | Lý do |
|---|---|---|
| R66 | Cây Python (`sigma.compile_rule`) giữ làm bộ tìm. Wazuh sandbox là cổng quyết định: recall / báo nhầm / "che rule khác" tính trên alert Wazuh. Python với Wazuh lệch nhau thì chỉ ghi số liệu, không chặn | Vòng tìm vế gọi replay hàng trăm lần, Wazuh mỗi lần mất hàng chục giây. Nhưng chỉ alert Wazuh mới là thật |
| R67 | Sandbox là service compose `wazuh-sandbox` (profile `ai`, `network_mode: none`, cùng image với `wazuh-manager`). Worker giao việc qua thư mục job trên volume `ai_sandbox`. Worker KHÔNG có docker socket | logtest không giải mã được eventchannel (wazuh_rule_test.py). Bơm vào manager thật sẽ sinh alert giả |
| R68 | Rule Linux (AI / SigmaHQ) chỉ nhắm decoder `siem-proc` (trường `cmd`, `exe`, `name`, `parent`, cha 102000), không nhắm auditd | auditd tách dòng lệnh thành `a0..aN`, có khi mã hóa hex, nên không có trường dòng lệnh để so |
| R69 | Mỗi vế (term) DNF thành một `<rule>` anh em. Trong một vế, mỗi trường Wazuh có đúng một phần tử pcre2 `(?i)^(?=…)(?!…)`: điều kiện dương là lookahead, phủ định là negative lookahead. IP → `SigmaError`. User-Agent dùng regex chuỗi ngoặc kép cuối dòng như 104005 | Không phụ thuộc chuyện Wazuh có cho hai `<field>` trùng tên hay không. Rule chữ ký không viết theo IP |
| R70 | Level: `low` 5, `medium` 7, `high` 10, `critical` 10 | Rule sinh tự động không được thắng rule gốc level 11–12 cùng cha (thắng là cắt cây con, mất alert thật) |
| R71 | Rule AI / SigmaHQ mới luôn chạy bóng: nhóm `shadow` + `shadow_since`. Bật chính thức = bỏ đúng hai thứ đó (`unshadow`) | Dùng lại cơ chế có sẵn (alerts.py, SOAR, lint) |
| R72 | `ai.xml` dựng lại từ các đề xuất đã triển khai trong ES: mỗi đề xuất một khối `<group name="siem,ai,ai_<pid>,">`. XML đóng băng lúc duyệt (`wazuh.deployed_xml`). Mọi thay đổi đi qua một khóa | ES là nguồn sự thật, không phải sửa XML tại chỗ. Hai người duyệt cùng lúc không mất khối của nhau |
| R73 | Đề xuất ngoại lệ AI: người bấm duyệt gọi `wazuh_exceptions.add` (tạo ngoại lệ chờ duyệt), người thứ hai duyệt ở trang ngoại lệ. Đề xuất AI loại ngoại lệ đặt `required_approvals: 1` | Một đường duyệt duy nhất (R48). Điều kiện ngoại lệ so chính xác, phân biệt hoa thường như `wazuh_fields.literal` |
| R74 | Số alert/ngày trên event thật (`siem-events` 7 ngày) vẫn ước lượng bằng cây Python, ghi `replay_estimate` | Wazuh không xử lý lại event cũ. Bơm lại `full_log` cần cả vị trí và header agent, ngoài phạm vi |

## Bản đồ task

Đánh số lại so với phác thảo:
- Task 20 cũ tách thành 20 (sandbox) và 21 (cổng);
- thêm Task 23 (ngoại lệ AI), vì engine tắt cũng làm chết nhánh này;
- 22 cũ → 24, 23 cũ → 25, 24 cũ → 26.

| Task | Nội dung | Cần trước |
|---|---|---|
| 19 | Bộ dịch cây Sigma → Wazuh XML (`ai/wazuh_xml.py`) | — |
| 20 | Sandbox Wazuh + bộ dựng log thô (`ai/sandbox.py`, `ai/wazuh_events.py`, `wazuh/sandbox/`) | — |
| 21 | Cổng Wazuh cho rule AI mới + khoảng trống tính trên Wazuh (`ai/wazuh_gate.py`, worker, validate) | 19, 20 |
| 22 | Duyệt / bật chính thức / gỡ rule AI vào `ai.xml` (gỡ 409) | 19 (giao diện đề xuất ở Interfaces Task 21) |
| 23 | Ngoại lệ AI cho rule Wazuh ồn → `wazuh_exceptions` | — |
| 24 | SigmaHQ lô 1 → `0966-sigmahq.xml` + ca CI | 19, 20 |
| 25 | Xóa engine YAML | 21–24 |
| 26 | Tài liệu, phán quyết R66–R74, triển khai thử | 25 |

Đợt song song (mỗi task một worktree):
1. Đợt 1: 19, 20, 23.
2. Đợt 2: 21, 22, 24.
3. Đợt 3: 25.
4. Đợt 4: 26.

Các task 21, 22, 23 cùng sửa `worker.py`, `validate.py`, `deploy.py`. Gộp theo thứ tự 23 → 21 → 22, rebase trước khi gộp.

## Global Constraints

- Python để chạy test: `PY=D:/GSANM/BTL/siem-xdr/server/.venv/Scripts/python`. Chạy từ `server/`: `$PY -m pytest tests/<file> -q`. Bộ đầy đủ: `$PY -m pytest -q` (CI: `working-directory: server`, `python -m pytest -q`).
- Wazuh manager 4.14.8. Sandbox dùng đúng `image:` của service `wazuh-manager` trong `docker-compose.yml`.
- Dải id (`server/siem/wazuh_rules.py` `ID_RANGES`):
  - `0966-sigmahq.xml` 108000–108999;
  - `ai.xml` 109000–109999;
  - `exceptions.xml` 110000–110999.
  - Ứng viên trong sandbox: `CANDIDATE_BASE = 119000`, chỉ tồn tại trong sandbox.
- Không dùng `ignore` (R55). Tối đa 2 thẻ `<list>` mỗi rule. Rule có nhóm `shadow` phải có `<info type="text">shadow_since=YYYY-MM-DD</info>`.
- Ghi `rules-dynamic` CHỈ qua `wazuh_rules.write_dynamic(name, xml_text, api)`.
- Ngưỡng giữ nguyên số:
  - recall tập kiểm tra ≥ 30%;
  - báo nhầm trên dữ liệu bình thường ≤ 0,1%;
  - ngoại lệ khớp ≥ 50% báo nhầm;
  - bật chính thức: ≥ `SHADOW_MIN_DAYS` (7) ngày, < `SHADOW_MAX_ALERTS_PER_DAY` (5) alert/ngày, báo nhầm < `SHADOW_MAX_FP_RATE` (30%).
- CI `wazuh-rules` phải xanh: lint, ossec.log không có `(7612)|(7617)|(7619)`, `wazuh_stock_reach.py`, `wazuh_rule_test.py`.
- Thử nghiệm KHÔNG đụng stack thật `siem-xdr-*`. Dùng project riêng `docker compose -p p4<tên>` và mạng riêng, tránh mạng cố định `soc-lab`.
- Không in hay commit `secrets/`. Không đổi mật khẩu admin console. Gộp hay push `main` chỉ khi chủ dự án yêu cầu.
- Runner trong sandbox chỉ dùng stdlib, chạy bằng `/var/ossec/framework/python/bin/python3`.
- Thông điệp người dùng và tài liệu viết tiếng Việt. Chi tiết pipeline AI ghi vào `AI-README.md`, `README.md` chỉ tóm tắt và link.

## Review Focus

1. **Rule mới thắng rule gốc cùng cha và cắt cây con** (kể cả khi đang bóng: bóng chỉ là cờ của cầu nối, Wazuh vẫn chọn rule thắng). Hệ quả là mất alert thật. Mong đợi: cổng chặn.
   - Test `test_gate_blocks_candidate_that_steals_stock_alert` (Task 21).
   - Ca `0998-stock-real-alerts.yml` vẫn xanh với `0966` (Task 24).
2. **Sandbox hỏng**: manager không lên, canary không ra, job mồ côi, hết thời gian. Mong đợi: `SandboxError`, chu kỳ ghi lỗi, KHÔNG coi là "rule không bắt" hay "mọi mẫu là khoảng trống".
   - Test `test_run_raises_when_canary_missing`, `test_run_times_out_and_cleans_job` (Task 20).
   - Test `test_cycle_records_error_when_sandbox_unavailable` (Task 21).
3. **Giá trị có ký tự đặc biệt** (`<`, `&`, `"`, `\`, `]]>`, NUL, CRLF, unicode) trong điều kiện hay tiêu đề do LLM hoặc SigmaHQ viết. Mong đợi: XML vẫn hợp lệ, không chèn được thẻ, mẫu chỉ khớp đúng chuỗi. Test `test_emit_escapes_hostile_values` (Task 19).
4. **Hai thao tác duyệt / bật / gỡ cùng lúc.** Mong đợi: `ai.xml` giữ đủ khối của cả hai. Test `test_concurrent_approvals_keep_both_blocks` (Task 22).
5. **Trường vắng mặt kết hợp phủ định.** Python: `not` trên trường vắng là đúng. Wazuh: `<field>` trên trường vắng là không khớp. Mong đợi: lệch được đo và báo, không làm hỏng cổng. Test `test_gate_reports_python_wazuh_mismatch` (Task 21).

---

### Task 19: Bộ dịch cây Sigma → Wazuh XML

**Files:**
- Create: `server/siem/ai/wazuh_xml.py`
- Modify: `server/siem/wazuh_fields.py`: tách `escape_literal(value) -> str` (phần trong của `literal`). `literal` = `^` + `escape_literal` + `\z`.
- Test: `server/tests/test_wazuh_xml.py`

**Interfaces:**
- Consumes:
  - cây từ `sigma.compile_rule(rule, domain) -> (tree, notes)`. Nút: `{"all": [...]}`, `{"any": [...]}`, `{"not": x}`, lá `{"field", "op", "value"[, "case_sensitive"]}`. `value` là chuỗi hoặc list.
  - Ngữ nghĩa phải giữ đúng như `detection/rules.Condition`:
    - mọi op chuỗi so không phân biệt hoa thường;
    - `regex` không phân biệt hoa thường trừ khi `case_sensitive: true`;
    - `neq` / `not_contains` là lá âm;
    - `exists`, `cidr`, `gt/gte/lt/lte` → `SigmaError`.
  - `sigma.SigmaError`, `sigma.MAX_TERMS` (32).
- Produces:
  - `EMITTER_VERSION = "1"`
  - `LEVEL = {"low": 5, "medium": 7, "high": 10, "critical": 10}`
  - `PARENTS: dict[str, dict]`, theo domain:
    - `windows`: if_sid `61603`;
    - `linux`: if_sid `102000`;
    - `web`: if_sid `31100,31101,31103,31104,31105,31106,31108,31120,31121,31122,31123` + `location ^\(`.
  - `class Emitted(NamedTuple): xml: str; ids: list[int]`. `xml` là chuỗi các `<rule>`, không có `<group>` bọc ngoài.
  - `emit(tree: dict, *, domain: str, first_id: int, level: int, code: str, title: str, techniques: list[str], groups: list[str], shadow_since: str | None, info: dict[str, str] | None = None) -> Emitted`
  - `pattern(pos: list[dict], neg: list[dict]) -> str`: mẫu pcre2 cho một trường trong một vế. Công khai để test so với Python.
  - `unshadow(xml: str) -> str`

Bảng trường (`FIELDS[domain][ecs] -> tên Wazuh`). Trường nào không có trong bảng thì `SigmaError(f"trường {f} không có trong log Wazuh của {domain}")`.

| ECS | windows (eventchannel) | linux (siem-proc) | web (apache) |
|---|---|---|---|
| process.executable | `win.eventdata.image` | `exe` | — |
| process.command_line | `win.eventdata.commandLine` | `cmd` | — |
| process.name | `win.eventdata.image`, so phần cuối `\` + giá trị | `name` | — |
| process.parent.executable | `win.eventdata.parentImage` | — | — |
| process.parent.name | `win.eventdata.parentImage`, so phần cuối `\` + giá trị | `parent` | — |
| process.parent.command_line | `win.eventdata.parentCommandLine` | — | — |
| user.name | `win.eventdata.user` | — | — |
| winlog.event_data.CurrentDirectory | `win.eventdata.currentDirectory` | — | — |
| url.original / url.path / url.query / url.decoded | — | — | thẻ tĩnh `<url>` (mỗi ký tự ngoài `[A-Za-z0-9]` khớp `(?:c\|%HH)`) |
| http.request.method | — | — | `<protocol>` |
| http.response.status_code | — | — | `<id>` |
| user_agent.original (chỉ `contains`) | — | — | `<regex>` `(?i)"[^"]{0,300}?P[^"]{0,300}"\s*$` |

- [ ] **Step 1: Đo trước trên manager tạm (S3), ghi vào mục "Kết quả đo P4" cuối file này**

  Dựng manager tạm `p4spike` (`--network none`) như `tools/wazuh_noise.start`. Chép một file rule thử (id 119000+) vào `etc/rules`. Bơm bằng `wazuh_coverage.run_wazuh`. Cần đo:
  - (a) `<field type="pcre2">(?i)^(?=[\s\S]*?abc)(?![\s\S]*?xyz)</field>` khớp hay không khớp đúng;
  - (b) `(?:'|%27)` trong `<url>` khớp cả URL thô lẫn URL mã hóa phần trăm;
  - (c) `<protocol type="pcre2">` và `<id type="pcre2">` nhận pcre2;
  - (d) cùng một event khớp hai rule anh em 119000 (L7) và 119001 (L10) dưới 61603 thì alert là 119001 (xác nhận lại R70).

  Nếu (a)–(c) sai: dừng, báo lại cho controller trước khi viết Step 3.

- [ ] **Step 2: Viết test thất bại**

```python
import re, xml.etree.ElementTree as ET
import pytest
from siem.ai import wazuh_xml as wx
from siem.ai.sigma import SigmaError
from siem.detection.rules import Condition      # Task 25 chuyển sang siem.ai.condition

def py_match(leaf, actual):                      # ngữ nghĩa chuẩn: cây Python mà AI đang dùng
    return Condition(leaf).match({"process": {"command_line": actual}})

WIN = {"all": [{"field": "process.executable", "op": "endswith", "value": "\\rundll32.exe"},
               {"field": "process.command_line", "op": "contains", "value": "javascript:"}]}
KW = dict(domain="windows", first_id=109000, level=7, code="AI-000", title="Rundll32 JS",
          techniques=["T1218.011"], groups=["siem", "ai"], shadow_since="2026-11-20")

def rules(xml): return ET.fromstring(f"<g>{xml}</g>").findall("rule")

def test_single_term_windows():
    e = wx.emit(WIN, **KW)
    assert e.ids == [109000]
    r, = rules(e.xml)
    assert (r.get("id"), r.get("level"), r.findtext("if_sid")) == ("109000", "7", "61603")
    assert {f.get("name") for f in r.findall("field")} == {"win.eventdata.image", "win.eventdata.commandLine"}
    assert all(f.get("type") == "pcre2" for f in r.findall("field"))
    assert r.findtext("group").split(",")[:3] == ["siem", "ai", "shadow"]
    assert "shadow_since=2026-11-20" in [i.text for i in r.findall("info")]
    assert r.findtext("mitre/id") == "T1218.011" and r.findtext("description").startswith("AI-000 ")

def test_or_across_fields_becomes_sibling_rules():
    tree = {"any": [{"field": "process.command_line", "op": "contains", "value": "a1"},
                    {"field": "process.executable", "op": "endswith", "value": "\\b.exe"}]}
    e = wx.emit(tree, **KW)
    assert e.ids == [109000, 109001]
    assert [r.findtext("description")[-8:] for r in rules(e.xml)] == ["(vế 1/2)", "(vế 2/2)"]

def test_or_on_same_field_stays_one_rule():
    tree = {"any": [{"field": "process.command_line", "op": "contains", "value": v} for v in ("aa", "bb")]}
    assert len(wx.emit(tree, **KW).ids) == 1

@pytest.mark.parametrize("op,value,actual", [
    ("eq", "cmd.exe", "CMD.EXE"), ("eq", "cmd.exe", "xcmd.exe"), ("contains", "a.b", "xxA.Byy"),
    ("contains", "a.b", "axb"), ("startswith", "C:\\Win", "c:\\windows\\x"), ("endswith", ".ps1", "a.PS1"),
    ("endswith", ".ps1", "a.ps1x"), ("in", ["x", "y"], "Y"), ("regex", r"\d{3}-x", "a123-X"),
    ("contains", ["aa", "bb"], "xbbx")])
def test_pattern_matches_like_python_tree(op, value, actual):
    leaf = {"field": "process.command_line", "op": op, "value": value}
    py = re.compile(wx.pattern([leaf], []).replace(r"\z", r"\Z"))
    assert bool(py.search(actual)) == py_match(leaf, actual)

def test_case_sensitive_regex_kept():
    leaf = {"field": "process.command_line", "op": "regex", "value": "AbC", "case_sensitive": True}
    py = re.compile(wx.pattern([leaf], []).replace(r"\z", r"\Z"))
    assert py.search("xAbC") and not py.search("xabc")

def test_negative_ops_become_lookaheads():
    leaf = {"field": "process.command_line", "op": "not_contains", "value": "safe"}
    pos = {"field": "process.command_line", "op": "contains", "value": "run"}
    xml = wx.emit({"all": [pos, leaf]}, **KW).xml
    assert "(?!" in xml and len(rules(xml)) == 1

def test_negation_is_negative_lookahead():
    p = wx.pattern([{"field": "f", "op": "contains", "value": "run"}], [{"field": "f", "op": "contains", "value": "safe"}])
    py = re.compile(p.replace(r"\z", r"\Z"))
    assert py.search("x run y") and not py.search("run safe")

@pytest.mark.parametrize("domain,leaf", [
    ("linux", {"field": "process.parent.executable", "op": "eq", "value": "/bin/sh"}),
    ("windows", {"field": "source.ip", "op": "eq", "value": "10.0.0.1"}),
    ("windows", {"field": "process.command_line", "op": "exists", "value": True})])
def test_unmapped_field_or_op_raises(domain, leaf):
    with pytest.raises(SigmaError):
        wx.emit(leaf, **{**KW, "domain": domain})

def test_too_many_terms_raises():
    tree = {"all": [{"any": [{"field": "process.command_line", "op": "contains", "value": f"{i}{j}"},
                             {"field": "process.executable", "op": "contains", "value": f"{i}{j}"}]} for i, j in
                    [(1, 1), (2, 2), (3, 3), (4, 4), (5, 5), (6, 6)]]}          # 2^6 = 64 vế > 32
    with pytest.raises(SigmaError):
        wx.emit(tree, **KW)

def test_web_rule_parent_location_and_encoding():
    tree = {"field": "url.decoded", "op": "contains", "value": "' or 1=1"}
    r, = rules(wx.emit(tree, **{**KW, "domain": "web"}).xml)
    assert r.findtext("if_sid").startswith("31100,") and r.findtext("location") == r"^\("
    py = re.compile(r.findtext("url").replace(r"\z", r"\Z"))
    assert py.search("/a?id=1' or 1=1") and py.search("/a?id=1%27%20or%201%3D1")

def test_user_agent_uses_last_quoted_string():
    r, = rules(wx.emit({"field": "user_agent.original", "op": "contains", "value": "sqlmap"},
                       **{**KW, "domain": "web"}).xml)
    assert r.find("regex").get("type") == "pcre2" and r.findtext("regex").endswith(r'"\s*$')

def test_emit_escapes_hostile_values():
    hostile = 'a<b&"c]]>\\\x00\r\nđ'
    e = wx.emit({"field": "process.command_line", "op": "contains", "value": hostile},
                **{**KW, "title": "<script>x</script>\x07"})
    r, = rules(e.xml)                                    # parse được = không vỡ XML
    assert [c.tag for c in r].count("field") == 1 and "<script>" not in e.xml and "\x07" not in e.xml
    assert re.compile(r.findtext("field").replace(r"\z", r"\Z")).search("zz" + hostile)

def test_unshadow_removes_only_shadow_markers():
    e = wx.emit(WIN, **KW)
    u = wx.unshadow(e.xml)
    r, = rules(u)
    assert "shadow" not in r.findtext("group").split(",") and "shadow_since" not in u
    assert (r.get("id"), r.get("level"), len(r.findall("field"))) == ("109000", "7", 2) and wx.unshadow(u) == u

def test_level_map():
    assert wx.LEVEL == {"low": 5, "medium": 7, "high": 10, "critical": 10}
```

- [ ] **Step 3: Chạy test, phải thất bại**

  Run: `cd server && $PY -m pytest tests/test_wazuh_xml.py -q`
  Expected: FAIL, `ModuleNotFoundError: siem.ai.wazuh_xml`.

- [ ] **Step 4: Viết `server/siem/ai/wazuh_xml.py` và `wazuh_fields.escape_literal`**

  - DNF trên cây (không dùng `sigma._dnf`, vì hàm đó chạy trên AST tên selection):
    - `not` đẩy xuống lá theo De Morgan;
    - kết quả là danh sách vế `(pos: list[leaf], neg: list[leaf])`;
    - vượt `MAX_TERMS` thì `SigmaError`;
    - vế chỉ có lá phủ định thì `SigmaError("vế chỉ có điều kiện phủ định")`.
  - Gom lá theo trường Wazuh. Hai giá trị `any` trên cùng một trường đã được `sigma._any` gộp thành `in`.
  - `pattern`:
    - `(?i)^` + lookahead cho mỗi lá dương + negative lookahead cho mỗi lá âm;
    - `contains` = `(?=[\s\S]*?L)`, `startswith` = `(?=L)`, `endswith` = `(?=[\s\S]*?L\z)`, `eq` = `(?=L\z)`;
    - `in` = alternation của các literal;
    - `regex` = `(?=[\s\S]*?(?:R))`, giữ nguyên mẫu. Lá có `case_sensitive: true` thì bọc `(?-i:…)`;
    - `neq` / `not_contains` = negative lookahead của `eq` / `contains`;
    - với `L = escape_literal(value)`.
  - Tiêu đề: bỏ ký tự điều khiển, cắt 200 ký tự rồi mới `xml.sax.saxutils.escape`, như `exception_rule`.
  - Mô tả có hậu tố `(vế k/n)` khi có từ hai vế.
  - Thứ tự phần tử trong `<rule>`: `if_sid`, `location`, các trường, `description`, `mitre`, `info`, `group`.

- [ ] **Step 5: Chạy lại test, phải qua; chạy cả bộ**

  Run: `cd server && $PY -m pytest tests/test_wazuh_xml.py tests/test_wazuh_rules.py -q && $PY -m pytest -q`
  Expected: PASS, không test cũ nào hỏng.

- [ ] **Step 6: Commit**

```bash
git add server/siem/ai/wazuh_xml.py server/siem/wazuh_fields.py server/tests/test_wazuh_xml.py docs/superpowers/plans/2026-11-06-p4-ai-wazuh-xml.md
git commit -m "feat(ai): dịch cây Sigma sang rule Wazuh XML (Task 19)"
```

---

### Task 20: Sandbox Wazuh và bộ dựng log thô

**Files:**
- Create: `wazuh/sandbox/runner.py`: vòng xử lý job, chỉ stdlib.
- Create: `wazuh/sandbox/entrypoint/10-sandbox.sh`: tắt filebeat như `wazuh/manager/entrypoint/10-siem-setup.sh`, tạo list CDB rỗng cho mọi `<list>` trong ossec.conf, `install -d -o 10001 -g 10001 -m 0775 /sandbox/jobs`, chạy nền `runner.py watch /sandbox`.
- Create: `server/siem/ai/wazuh_events.py`
- Create: `server/siem/ai/sandbox.py`
- Modify: `docker-compose.yml`:
  - thêm service `wazuh-sandbox` (profile `ai`, `network_mode: none`, không secrets, không ports). Mount:
    - `./wazuh/manager/rules:/var/ossec/etc/rules:ro`;
    - `./wazuh/manager/decoders:/var/ossec/etc/decoders:ro`;
    - `./wazuh/manager/ossec.conf:/wazuh-config-mount/etc/ossec.conf:ro`;
    - `wazuh_dynamic_rules:/live-dynamic:ro`;
    - `${AI_SANDBOX_PATH:-ai_sandbox}:/sandbox`;
    - `./wazuh/sandbox:/sandbox-runner:ro`;
    - `./wazuh/sandbox/entrypoint:/entrypoint-scripts:ro`;
  - service AI (`command: ["python", "-m", "siem.ai"]`) thêm `${AI_SANDBOX_PATH:-ai_sandbox}:/sandbox`;
  - khai báo volume `ai_sandbox`.
- Modify: `server/siem/settings.py`: `AI_SANDBOX_DIR = Path(os.getenv("AI_SANDBOX_DIR", "/sandbox"))`, `AI_SANDBOX_TIMEOUT = float(os.getenv("AI_SANDBOX_TIMEOUT", "900"))`.
- Modify: `tools/wazuh_coverage.py`: `sysmon_message` và `GENERIC` import từ `siem.ai.wazuh_events`, xóa bản cũ.
- Test: `server/tests/test_wazuh_events.py`, `server/tests/test_sandbox.py`, `server/tests/test_sandbox_runner.py`, `server/tests/test_sandbox_it.py` (skip nếu không có `SANDBOX_IT_DIR`).

**Interfaces:**
- Consumes: `PublicDatasets` (`ai/golden.py`). File thô trong `DATASETS_DIR`: `csic_anomalous.jsonl.gz`, `csic_normal.jsonl.gz`, `atomic.jsonl.gz`. Ngoài ra `ai/baseline.ordinary_processes`, và từ `tools/wazuh_coverage.load_items` hai cách ghép thô với chuẩn hóa.
- Produces (`wazuh_events.py`):
  - `@dataclass(frozen=True) class RawEvent: ident: int; fmt: str; msg: str`. `fmt` ∈ `eventchannel | siem-proc | apache`.
  - `sysmon_event(ident, image, cmd, parent, parent_cmd, user) -> RawEvent`: `EventRecordID = ident`.
  - `siem_proc_event(ident, exe, cmd, name, parent, uid=0) -> RawEvent`:
    - header `1:[001] (sbx-<ident>) any->siem-procs:`;
    - thân `ossec: output: 'siem-procs': siem-proc: pid=<ident> ppid=1 uid=<uid> name=<name> parent=<parent> exe=<exe> cmd=<cmd>`.
  - `apache_event(ident, line) -> RawEvent`: header `1:[001] (sbx-<ident>) any->/var/log/apache2/access.log:`.
  - `GENERIC: dict[str, str]`: chuyển nguyên từ wazuh_coverage.
  - `golden_events(g: PublicDatasets, data_dir: Path, extra_normal: bool = True) -> dict[int, RawEvent]`: khóa là `id(doc)` của `Labeled.doc` trong `g`, chỉ dùng trong một chu kỳ. Atomic Linux dùng `siem_proc_event` với `name = basename(exe)`, `parent = "sh"`. Mục không dựng được log thô (EVTX mẫu…) thì không có khóa.
- Produces (`sandbox.py`):
  - `class SandboxError(RuntimeError)`
  - `@dataclass class Hit: rule_id: int; level: int`
  - `@dataclass class SandboxResult: hits: dict[int, list[Hit]]; load_error: str | None; seconds: float`
  - `class Sandbox: __init__(self, root: Path = settings.AI_SANDBOX_DIR, timeout: float = settings.AI_SANDBOX_TIMEOUT)`
  - `Sandbox.run(self, events: list[RawEvent], candidate_xml: str | None = None) -> SandboxResult`
  - `alert_ident(alert: dict) -> int | None`: eventchannel lấy `data.win.system.eventRecordID`; còn lại lấy `sbx-(\d+)` trong `agent.name` hoặc `location`. Xem Step 1 (b).
- Giao thức job: thư mục `/sandbox/jobs/<12 hex>/`.
  - Worker ghi `events.jsonl` (`{"msg": …}`), có thể kèm `candidate.xml`, rồi ghi `ready` cuối cùng.
  - Runner ghi `result.json` `{"sent", "processed", "dropped", "canary": bool, "seconds", "load_error": str|null}`, `alerts.jsonl`, rồi `done`.
  - Worker đọc xong thì xóa job. Runner xóa job cũ hơn 1 giờ.

- [ ] **Step 1: Đo trước (S4) trên `docker compose -p p4sbx --profile ai up -d wazuh-sandbox`, ghi vào "Kết quả đo P4"**
  - (a) thời gian `wazuh-control restart` cho tới khi `wazuh-analysisd.state` cập nhật;
  - (b) header `(sbx-<ident>)` có hiện ở `agent.name` hoặc `location` của alert không. Nếu không, ghép theo `full_log`, bỏ dòng apache trùng (như `wazuh_coverage.match_alerts`) và ghi rõ;
  - (c) tốc độ bơm 50.000 event.

  Mục tiêu: một job 50.000 event dưới 180 giây. Không đạt thì báo controller.

- [ ] **Step 2: Viết test thất bại**

```python
# test_wazuh_events.py
import re
from siem.ai import wazuh_events as we
PREMATCH = re.compile(r"^ossec: output: '[^']*': siem-proc: pid=\d+ ppid=")   # decoders/0102-siem-procs.xml

def test_siem_proc_event_matches_decoder_prematch():
    e = we.siem_proc_event(42, "/usr/bin/curl", "curl http://x | sh", "curl", "bash")
    head, body = e.msg.split("any->siem-procs:", 1)
    assert head == "1:[001] (sbx-42) " and PREMATCH.match(body) and "pid=42 " in body and e.fmt == "siem-proc"

def test_sysmon_event_record_id_is_ident():
    e = we.sysmon_event(7, "C:\\Windows\\System32\\cmd.exe", "cmd /c whoami", "C:\\x.exe", "x", "LAB\\u")
    assert e.msg.startswith("f:EventChannel:") and "<EventRecordID>7</EventRecordID>" in e.msg

def test_apache_event_header():
    assert we.apache_event(9, "1.2.3.4 - - [x] \"GET / HTTP/1.1\" 200 1").msg.startswith(
        "1:[001] (sbx-9) any->/var/log/apache2/access.log:1.2.3.4 ")

# test_sandbox.py: runner giả là một thread ghi result.json / alerts.jsonl / done
def test_run_maps_alerts_to_idents(tmp_path, fake_runner):
    fake_runner(tmp_path, alerts=[{"rule": {"id": "92032", "level": 3}, "agent": {"name": "sbx-5"}}], canary=True)
    res = Sandbox(tmp_path, timeout=5).run([we.apache_event(5, "l")])
    assert res.hits == {5: [Hit(92032, 3)]} and res.load_error is None
    assert not any((tmp_path / "jobs").iterdir())                      # đã dọn job

def test_run_raises_when_canary_missing(tmp_path, fake_runner):
    fake_runner(tmp_path, alerts=[], canary=False)
    with pytest.raises(SandboxError, match="canary"):
        Sandbox(tmp_path, timeout=5).run([we.apache_event(1, "l")])

def test_run_times_out_and_cleans_job(tmp_path):
    with pytest.raises(SandboxError, match="quá"):
        Sandbox(tmp_path, timeout=0.3).run([we.apache_event(1, "l")])
    assert not any((tmp_path / "jobs").iterdir())

def test_load_error_is_returned_not_raised(tmp_path, fake_runner):
    fake_runner(tmp_path, alerts=[], canary=True, load_error="(7612): Rule ID '119000' is duplicated")
    assert "7612" in Sandbox(tmp_path, timeout=5).run([we.apache_event(1, "l")], "<rule/>").load_error

# test_sandbox_runner.py: nạp wazuh/sandbox/runner.py bằng importlib theo đường dẫn
def test_rejects_bad_job_names(runner): assert not runner.valid_job("../x") and runner.valid_job("0123456789ab")
def test_load_problems_catches_warnings(runner):
    assert runner.load_problems(0, "WARNING: (7612): Rule ID '109010' is duplicated") and not runner.load_problems(0, "ok")
    assert runner.load_problems(1, "")
def test_sync_rules_copies_live_then_candidate(runner, tmp_path):
    live, dst = tmp_path / "live", tmp_path / "dst"; live.mkdir(); dst.mkdir()
    (live / "ai.xml").write_text("a"); (live / "x.tmp").write_text("t"); (dst / "old.xml").write_text("o")
    runner.sync_rules(live, dst, "<rule/>")
    assert sorted(p.name for p in dst.iterdir()) == ["ai.xml", "zz-candidate.xml"]
```

- [ ] **Step 3: Chạy test, phải thất bại**

  Run: `cd server && $PY -m pytest tests/test_wazuh_events.py tests/test_sandbox.py tests/test_sandbox_runner.py -q`
  Expected: FAIL, thiếu module.

- [ ] **Step 4: Viết bốn file mới, sửa compose, settings, wazuh_coverage**

  Runner xử lý mỗi job:
  1. `sync_rules(/live-dynamic, /var/ossec/etc/rules-dynamic, candidate)`.
  2. `wazuh-analysisd -t`. Mã thoát khác 0, hoặc đầu ra có `(7612)|(7617)|(7619)`, thì ghi `load_error` (20 dòng đầu) và bỏ bơm.
  3. `wazuh-control restart`, chờ file state cập nhật.
  4. Làm rỗng `alerts.json`.
  5. Gửi event + canary syscheck 554 (`_message("syscheck", …)` của `wazuh_rule_test`) qua `/var/ossec/queue/sockets/queue`, theo vòng gửi của `SENDER`.
  6. Chờ `events_processed` đứng yên 3 lần × 5 giây.
  7. Chép alert ra job.

  Mỗi job tối đa 200.000 event, quá thì trả `load_error="quá nhiều event"`.

- [ ] **Step 5: Chạy lại test đơn vị, phải qua; chạy test tích hợp**

  Run: `cd server && $PY -m pytest tests/test_wazuh_events.py tests/test_sandbox.py tests/test_sandbox_runner.py -q`
  Expected: PASS.

  Run: `AI_SANDBOX_PATH=$PWD/../.sandbox docker compose -p p4sbx --profile ai up -d wazuh-sandbox && SANDBOX_IT_DIR=../.sandbox $PY -m pytest tests/test_sandbox_it.py -q`
  Expected: PASS, gồm:
  - canary đúng;
  - một ca Windows trong `0998-stock-real-alerts.yml` ra đúng rule gốc của nó;
  - một `candidate.xml` một rule (id 119000) bắt đúng event của chính nó.

  Xong thì `docker compose -p p4sbx down -v`.

- [ ] **Step 6: Commit**

```bash
git add wazuh/sandbox server/siem/ai/wazuh_events.py server/siem/ai/sandbox.py server/siem/settings.py docker-compose.yml tools/wazuh_coverage.py server/tests/test_wazuh_events.py server/tests/test_sandbox*.py
git commit -m "feat(ai): sandbox Wazuh cô lập và log thô từ dataset (Task 20)"
```

---

### Task 21: Cổng Wazuh cho rule AI mới; khoảng trống tính trên Wazuh

**Files:**
- Create: `server/siem/ai/wazuh_gate.py`
- Modify:
  - `server/siem/ai/validate.py`: `validate_new_rule` nhận thêm `gate: WazuhGate | None` và `raw: dict[int, RawEvent]`. Bỏ check "trùng rule sẵn có" (YAML). Đổi tên check replay thành "ước lượng alert khi replay (Python)" (R74).
  - `server/siem/ai/worker.py`:
    - `GENERATOR_REVISION = "11"`;
    - `dataset_gaps` lấy từ `gate.baseline`;
    - truyền `gate`/`raw` vào `validate_new_rule`;
    - `_recheck_stale` chạy cổng cho đề xuất pending chưa có khối `wazuh`;
    - sandbox lỗi thì ghi `summary["errors"]` và bỏ nhánh khoảng trống của chu kỳ.
- Test: `server/tests/test_wazuh_gate.py`. Sửa `server/tests/test_ai.py` chỗ gọi `dataset_gaps` / `validate_new_rule`.

**Interfaces:**
- Consumes:
  - `wazuh_xml.emit/LEVEL/EMITTER_VERSION` (Task 19);
  - `Sandbox.run`, `RawEvent`, `golden_events`, `GENERIC`, `SandboxError` (Task 20);
  - `validate.Check`, `validate.Validation`.
- Produces:
  - `CANDIDATE_BASE = 119000`, `DETECT_LEVEL = 7`.
  - `class WazuhGate: __init__(self, sandbox: Sandbox, raw: dict[int, RawEvent])`
  - `WazuhGate.baseline(self, docs: list[dict]) -> dict[int, list[Hit]]`: theo `id(doc)`, chạy job không có ứng viên, nhớ kết quả trong chu kỳ.
  - `WazuhGate.gaps(self, docs: list[dict]) -> list[dict]`: doc không có Hit nào `level >= DETECT_LEVEL` từ rule ngoài `GENERIC`.
  - `WazuhGate.check(self, tree: dict, *, domain: str, level: int, title: str, techniques: list[str], train: list[dict], test: list[dict], normal: list[dict]) -> tuple[list[Check], dict]`: trả checks + metrics `wazuh_*`.
  - Khối lưu vào đề xuất (Task 22 đọc): `proposal["wazuh"] = {"emitter": EMITTER_VERSION, "domain": str, "level": int, "rules": int, "validated_at": iso}`. Cây đã có ở `proposal["proposal"]["condition"]`.

- [ ] **Step 1: Viết test thất bại**

  Dùng `FakeSandbox(results: list[SandboxResult])` trả lần lượt từng kết quả và ghi lại `candidate_xml` đã nhận.

```python
def test_gaps_ignore_generic_and_low_level(gate_with):
    g = gate_with(baseline={1: [Hit(92032, 10)], 2: [Hit(92213, 12)], 3: [Hit(60103, 5)], 4: []})
    assert [d["n"] for d in g.gaps(DOCS[1:5])] == [1, 3, 4]          # 92032 nằm trong GENERIC

def test_gate_passes_good_candidate(gate_with):
    g = gate_with(baseline={}, candidate={11: [Hit(119000, 7)], 12: [Hit(119000, 7)]})   # test = 11..14
    checks, m = g.check(TREE, domain="windows", level=7, title="t", techniques=["T1059"],
                        train=TRAIN, test=TEST4, normal=NORMAL1000)
    assert all(c.ok for c in checks if c.blocking) and m["wazuh_test_recall"] == 0.5 and m["wazuh_normal_hits"] == 0

def test_gate_fails_low_recall(gate_with):          # 1/4 = 25% < 30%
    ...assert not next(c for c in checks if c.name == "bắt mẫu nghi vấn (Wazuh)").ok

def test_gate_fails_false_positives(gate_with):     # 2/1000 = 0,2% > 0,1%
    ...assert not next(c for c in checks if c.name == "báo nhầm (Wazuh)").ok

def test_gate_blocks_candidate_that_steals_stock_alert(gate_with):
    g = gate_with(baseline={21: [Hit(92213, 12)]}, candidate={21: [Hit(119000, 10)]})   # 21 là mẫu bình thường
    checks, m = g.check(TREE, ..., normal=[DOC21])
    c = next(c for c in checks if c.name == "không che rule khác")
    assert c.blocking and not c.ok and "92213" in c.detail and m["wazuh_stolen"] == 1

def test_gate_fails_on_load_error(gate_with):
    ... candidate=SandboxResult({}, "(7612): ...", 1.0) ...
    assert not next(c for c in checks if c.name == "Wazuh nạp được rule").ok

def test_gate_reports_python_wazuh_mismatch(gate_with):
    # cây Python khớp mẫu 13 nhưng Wazuh không ra 119000 cho 13
    c = next(c for c in checks if c.name == "khớp Python")
    assert not c.blocking and m["wazuh_python_only"] == 1

def test_cycle_records_error_when_sandbox_unavailable(worker_with_gate_raising):
    s = worker_with_gate_raising(SandboxError("canary")).run_cycle()
    assert any("sandbox" in e for e in s["errors"]) and s["created"] == []

def test_generator_revision_is_11():
    assert worker.GENERATOR_REVISION == "11"

def test_new_rule_proposal_carries_wazuh_block(...):
    assert p["wazuh"]["emitter"] == wazuh_xml.EMITTER_VERSION and p["wazuh"]["rules"] >= 1
```

- [ ] **Step 2: Chạy test, phải thất bại**

  Run: `cd server && $PY -m pytest tests/test_wazuh_gate.py -q`
  Expected: FAIL, thiếu `siem.ai.wazuh_gate`.

- [ ] **Step 3: Viết `wazuh_gate.py`, sửa `validate.py`, `worker.py`**

  `check` emit với `first_id=CANDIDATE_BASE`, `shadow_since=None`. Job chỉ gồm event của `train + test + normal` có trong `raw`. Các check, tất cả chặn trừ "khớp Python":
  - "Wazuh nạp được rule";
  - "bắt mẫu nghi vấn (Wazuh)" ≥ 30%;
  - "báo nhầm (Wazuh)" ≤ 0,1%;
  - "không che rule khác": mẫu mà baseline có Hit `level >= 7` từ rule không phải ứng viên, sang job ứng viên thì mất;
  - "khớp Python" (không chặn);
  - "có log thô": thiếu event thô cho `test` hoặc `normal` thì không đạt.

  `validate_new_rule` chỉ gọi cổng khi mọi check chặn của Python đã đạt, để tránh tốn sandbox cho ứng viên hỏng.

- [ ] **Step 4: Chạy test, phải qua; chạy cả bộ**

  Run: `cd server && $PY -m pytest tests/test_wazuh_gate.py tests/test_ai.py tests/test_ai_hardening.py -q && $PY -m pytest -q`
  Expected: PASS.

- [ ] **Step 5: Chạy thử thật một chu kỳ trên project test**

  Run: `docker compose -p p4gate --profile ai up -d` (cần Ollama và model `qwen3.5:9b`), rồi kích chu kỳ AI như AI-README §9.10.
  Expected:
  - `summary.errors` không có lỗi sandbox;
  - ít nhất một đề xuất mới có khối `wazuh` và các check `(Wazuh)`.

  Ghi kết quả (số khoảng trống, đạt / loại, thời gian sandbox) vào "Kết quả đo P4". Xong thì `down -v`.

- [ ] **Step 6: Commit**

```bash
git add server/siem/ai/wazuh_gate.py server/siem/ai/validate.py server/siem/ai/worker.py server/tests/test_wazuh_gate.py server/tests/test_ai.py
git commit -m "feat(ai): kiểm định rule AI trên Wazuh sandbox, khoảng trống theo alert Wazuh (Task 21)"
```

---

### Task 22: Duyệt, bật chính thức, gỡ rule AI vào `ai.xml`

**Files:**
- Modify: `server/siem/ai/deploy.py`:
  - bỏ `_need_engine`, `target_file`, `_write`, `_MODE_LINE` của nhánh rule mới;
  - thêm `render_ai_file`, `next_ids`, khóa `_lock = threading.Lock()`;
  - `approve/promote/rollback` bỏ tham số `rules_dir`, thêm `api`.
- Modify: `server/siem/manager/api.py`:
  - route promote đổi thành `POST /api/v1/ai/proposals/{pid}/promote`, xóa `/api/v1/rules/{rule_id}/promote`;
  - mọi route AI truyền `wazuh_rules.WazuhApi.from_settings()`.
- Modify: `server/siem/manager/static/console.html`: nút "Bật chính thức" gọi route mới bằng mã đề xuất.
- Test: `server/tests/test_ai_deploy_xml.py`. Sửa test của deploy và endpoint trong `test_ai_endpoint.py`.

**Interfaces:**
- Consumes:
  - `wazuh_xml.emit/unshadow/LEVEL/EMITTER_VERSION` (Task 19);
  - khối `proposal["wazuh"]` (Task 21);
  - `wazuh_rules.write_dynamic(name, xml_text, api)`, `wazuh_rules.WazuhRuleError`.
- Produces:
  - `AI_FILE = "ai.xml"`, `AI_FIRST, AI_LAST = 109000, 109999`
  - `render_ai_file(deployed: list[dict]) -> str`: header comment + mỗi đề xuất một `<group name="siem,ai,ai_<pid>,">` + `wazuh.deployed_xml` + `</group>`, theo thứ tự `deployed_at`.
  - `next_ids(deployed: list[dict], n: int) -> list[int]`: `max(id đã dùng) + 1 …`. Vượt `AI_LAST` thì `DeployError(409, "hết dải id rule AI (109000–109999)")`.
  - `approve(es, pid, analyst, api, now="") -> dict`
  - `promote(es, pid, who, api, now="") -> dict`
  - `rollback(es, pid, analyst, reason, api, now="") -> dict`
  - `shadow_stats(es, rule_ids: list[str], since, now="") -> dict`: `terms` trên `rule.id`, giá trị `WZH-<id>`.
  - Trường lưu: `wazuh.ids: list[int]`, `wazuh.deployed_xml: str`, `wazuh.code: "AI-<id % 1000:03d>"`, `file: "rules-dynamic/ai.xml"`.

- [ ] **Step 1: Viết test thất bại**

  Dùng `FakeES` theo kiểu test deploy hiện có, và `FakeApi` như `test_wazuh_rules.py`. `tmp_path` làm `DYNAMIC_DIR` (monkeypatch `wazuh_rules.DYNAMIC_DIR`).

```python
def test_approve_writes_shadow_block(env):
    p = env.pending(kind="new_rule", level="high")
    out = deploy.approve(env.es, p["id"], "an", env.api, now="2026-11-20T08:00:00+00:00")
    text = (env.dyn / "ai.xml").read_text()
    assert f'<group name="siem,ai,ai_{p["id"]},">' in text and 'id="109000"' in text and 'level="10"' in text
    assert "shadow_since=2026-11-20" in text and out["status"] == "approved" and out["wazuh"]["ids"][0] == 109000
    assert env.api.reloads == 1

def test_second_approval_allocates_next_ids(env): ...assert second["wazuh"]["ids"][0] == first["wazuh"]["ids"][-1] + 1

def test_approve_rejects_changed_emitter(env):
    p = env.pending(wazuh={"emitter": "0"})
    with pytest.raises(deploy.DeployError) as e: deploy.approve(env.es, p["id"], "an", env.api)
    assert e.value.code == 409 and "kiểm định lại" in str(e.value)

def test_reload_failure_keeps_proposal_pending(env):
    env.api.fail_reload = True
    with pytest.raises(deploy.DeployError): deploy.approve(env.es, env.pending()["id"], "an", env.api)
    assert env.es.get_proposal(...)["status"] == "pending" and not (env.dyn / "ai.xml").exists()

def test_promote_checks_stats_then_unshadows(env):
    p = env.approved(since="2026-11-01")
    env.alerts(rule_ids=[f"WZH-{i}" for i in p["wazuh"]["ids"]], per_day=1, fp=0)
    deploy.promote(env.es, p["id"], "de", env.api, now="2026-11-10T00:00:00+00:00")
    assert "shadow" not in (env.dyn / "ai.xml").read_text().split("<group>")[1]

def test_promote_too_early_is_409(env): ...                              # 3 ngày < 7

def test_rollback_removes_block(env):
    a, b = env.approved(), env.approved()
    deploy.rollback(env.es, a["id"], "an", "báo nhầm", env.api)
    text = (env.dyn / "ai.xml").read_text()
    assert f"ai_{a['id']}" not in text and f"ai_{b['id']}" in text

def test_concurrent_approvals_keep_both_blocks(env):
    p1, p2 = env.pending(), env.pending()
    ts = [threading.Thread(target=deploy.approve, args=(env.es, p["id"], "an", env.api)) for p in (p1, p2)]
    [t.start() for t in ts]; [t.join() for t in ts]
    text = (env.dyn / "ai.xml").read_text()
    assert f"ai_{p1['id']}" in text and f"ai_{p2['id']}" in text

def test_id_range_exhausted(env): ...next_ids([{"wazuh": {"ids": [109999]}}], 1) raises 409

def test_ai_routes_no_longer_409(client, env): ...POST /api/v1/ai/proposals/{pid}/approve -> 200
```

- [ ] **Step 2: Chạy test, phải thất bại**

  Run: `cd server && $PY -m pytest tests/test_ai_deploy_xml.py -q`
  Expected: FAIL.

- [ ] **Step 3: Viết lại nhánh rule mới của `deploy.py`, sửa route và nút console**

  Thứ tự trong `_lock`:
  1. đọc mọi đề xuất `status ∈ {approved, promoted}` (kind `new_rule`) từ ES;
  2. tính file mới;
  3. `write_dynamic`;
  4. lỗi → `DeployError(409, …)` và KHÔNG lưu đề xuất; thành công → lưu đề xuất (seq/term như `_save`).

  Approve:
  - kiểm `wazuh.emitter == EMITTER_VERSION`;
  - emit lại từ `proposal.condition` với `first_id = next_ids(...)[0]`, `code`, `shadow_since = ngày(now)`;
  - `level = LEVEL[proposal.level]`.

  Promote: `deployed_xml = unshadow(deployed_xml)`, sau khi `promotion_problems(shadow_stats(...))` rỗng.

  Nhánh ngoại lệ thuộc Task 23, không sửa ở đây.

- [ ] **Step 4: Chạy test, phải qua; chạy cả bộ**

  Run: `cd server && $PY -m pytest tests/test_ai_deploy_xml.py tests/test_ai_endpoint.py -q && $PY -m pytest -q`
  Expected: PASS.

- [ ] **Step 5: Thử trên project test**

  Duyệt một đề xuất có khối `wazuh` qua console của `p4dep`. Kiểm:
  - `docker compose -p p4dep exec wazuh-manager grep -c 'ai_' /var/ossec/etc/rules-dynamic/ai.xml` ≥ 1;
  - thư viện rule hiện rule 109000 ở chế độ bóng.

- [ ] **Step 6: Commit**

```bash
git add server/siem/ai/deploy.py server/siem/manager/api.py server/siem/manager/static/console.html server/tests/test_ai_deploy_xml.py server/tests/test_ai_endpoint.py
git commit -m "feat(ai): duyệt / bật chính thức / gỡ rule AI qua rules-dynamic/ai.xml, bỏ chặn 409 (Task 22)"
```

---

### Task 23: Ngoại lệ AI cho rule Wazuh ồn

**Files:**
- Modify:
  - `server/siem/ai/worker.py`: nhánh 1 duyệt `ds.evidence()` theo `rule.id` dạng `WZH-<số>` có ≥ `AI_MIN_FALSE_POSITIVES` báo nhầm, thay cho `load_rules()`.
  - `server/siem/ai/validate.py`: thêm `validate_exception_wazuh`.
  - `server/siem/ai/prompts.py`: prompt ngoại lệ chỉ liệt kê trường ánh xạ được.
  - `server/siem/ai/deploy.py`: nhánh `kind == "exception"` của approve / rollback.
- Test: `server/tests/test_ai_exceptions_wazuh.py`.

**Interfaces:**
- Consumes:
  - `wazuh_exceptions.add(rule: str, conditions: list[dict], reason: str, by: str, api, root=None) -> dict`, trả item có `id`, `status: "pending"`;
  - `wazuh_exceptions.remove(eid: int, by: str, reason: str, api, root=None) -> dict`;
  - `wazuh_fields.exception_rule` (ném `ValueError` khi không ánh xạ được);
  - `RuleEvidence.fp/tp` (`ai/dataset.py`).
- Produces:
  - `EXCEPTION_FIELDS = ("process.command_line", "source.ip", "destination.ip", "user.name", "url.original", "file.path")`
  - `validate_exception_wazuh(rule_id: str, conditions: list[dict], fp: list[dict], tp: list[dict], recent: list[dict]) -> Validation`. Các check:
    - "ánh xạ được sang Wazuh";
    - "mỗi trường một lần";
    - "khớp báo nhầm" ≥ 50%;
    - "không chặn alert đúng": 0 TP bị khớp;
    - "ước lượng alert bị chặn": không chặn, số alert `recent` bị khớp.
    - So khớp bằng `==` phân biệt hoa thường, như `literal`.
  - Đề xuất ngoại lệ: `target = "exception:WZH-<id>"`, `required_approvals = 1`. Khi duyệt, lưu `exception_id`.

- [ ] **Step 1: Viết test thất bại**

```python
def test_noisy_targets_come_from_wazuh_evidence(worker_env):
    worker_env.evidence({"WZH-5710": fp(5), "WZH-31103": fp(1)})
    assert worker_env.exception_targets() == ["exception:WZH-5710"]

def test_exact_case_sensitive_match():
    v = validate_exception_wazuh("WZH-5710", [{"field": "user.name", "value": "svc_backup"}],
                                 fp=[doc(user="svc_backup")] * 4 + [doc(user="SVC_BACKUP")], tp=[], recent=[])
    assert next(c for c in v.checks if c.name == "khớp báo nhầm").ok                # 4/5 = 80%

def test_condition_that_hits_true_positive_fails():
    v = validate_exception_wazuh("WZH-5710", [{"field": "user.name", "value": "root"}],
                                 fp=[doc(user="root")] * 3, tp=[doc(user="root")], recent=[])
    assert not v.passed

def test_unmappable_field_is_invalid():
    v = validate_exception_wazuh("WZH-5710", [{"field": "process.parent.name", "value": "x"}], fp=[doc()] * 3, tp=[], recent=[])
    assert not next(c for c in v.checks if c.name == "ánh xạ được sang Wazuh").ok

def test_approve_exception_creates_pending_wazuh_exception(env, monkeypatch):
    calls = []
    monkeypatch.setattr(wazuh_exceptions, "add", lambda *a, **k: calls.append((a, k)) or {"id": 110003, "status": "pending"})
    out = deploy.approve(env.es, env.pending(kind="exception", target="exception:WZH-5710")["id"], "an", env.api)
    assert calls[0][0][0] == "WZH-5710" and calls[0][0][3] == "an" and out["exception_id"] == 110003

def test_rollback_exception_removes_it(env, monkeypatch): ...wazuh_exceptions.remove called with 110003

def test_prompt_lists_only_mappable_fields():
    assert set(re.findall(r"`([a-z_.]+)`", prompts.exception_fields_text())) == set(EXCEPTION_FIELDS)
```

- [ ] **Step 2: Chạy test, phải thất bại**

  Run: `cd server && $PY -m pytest tests/test_ai_exceptions_wazuh.py -q`
  Expected: FAIL.

- [ ] **Step 3: Viết code**

  - Mô tả rule đưa vào prompt lấy từ doc `WZH-<id>` của index thư viện rule (`rules_catalog`): `description`, `level`, `groups`.
  - Trường `decoder` của điều kiện `process.command_line` lấy như form ngoại lệ trên console đang gửi. Xem model `conditions` ở `manager/api.py` gần dòng 893.

- [ ] **Step 4: Chạy test, phải qua; chạy cả bộ**

  Run: `cd server && $PY -m pytest tests/test_ai_exceptions_wazuh.py tests/test_ai.py -q && $PY -m pytest -q`
  Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add server/siem/ai/worker.py server/siem/ai/validate.py server/siem/ai/prompts.py server/siem/ai/deploy.py server/tests/test_ai_exceptions_wazuh.py
git commit -m "feat(ai): đề xuất ngoại lệ cho rule Wazuh ồn qua wazuh_exceptions (Task 23)"
```

---

### Task 24: SigmaHQ lô 1 → `0966-sigmahq.xml`

> **Tên file:** kế hoạch ban đầu ghi `0108-sigmahq.xml`. Khi làm Task 24, Wazuh bỏ mọi rule của file đó (7617 / 7619) vì cha 61603
> (`0595-win-sysmon_rules.xml`) và các cha gom nhóm 92025 / 92028 / 92042 / 92069 (`0800-sysmon_id_1.xml`) nạp sau theo tên file.
> File đổi thành `0966-sigmahq.xml`, dải 108000–108999 giữ nguyên (R76). Mọi chỗ `0108` trong kế hoạch này đã sửa theo (Task 26).

**Files:**
- Create (chép từ WIP `.claude/worktrees/coverage-batch1`, sao lưu ở `D:\GSANM\BTL\backup\coverage-batch1-wip-2026-11-01\`): `tools/sigmahq_import.py`, `server/tests/test_sigmahq_import.py`. CHỈ chép hai file này. Các file sửa khác của WIP (base 544d985) đã cũ, bỏ.
- Create (do tool sinh): `wazuh/manager/rules/0966-sigmahq.xml`, `wazuh/manager/tests/cases/0966-sigmahq.yml`.
- Modify: `server/siem/wazuh_rules.py`: chỉ khi `ID_RANGES` chưa có `0966-sigmahq.xml`.

**Interfaces:**
- Consumes:
  - `wazuh_xml.emit` (Task 19);
  - `wazuh_events.sysmon_event/apache_event` (Task 20), để dựng ca;
  - `tools/wazuh_coverage.load_items/run_wazuh/match_alerts`, để biết mẫu nào đã được phủ (Hit `level >= 7`, không thuộc `GENERIC`), chạy trên manager tạm của `tools/wazuh_noise.start`;
  - `sigma.compile_rule` (strict).
- Produces:
  - file XML 30 rule, id `108000 + k`, mã `SHQ-NNN`, nhóm `siem,sigmahq,shadow,`, `shadow_since=<ngày ghi>`, `info` `sigmahq_id=<uuid>` và `author=<tác giả>`. Đầu file: chú thích giấy phép DRL 1.1 và nguồn SigmaHQ;
  - ca test: mỗi rule một ca dương (`rule: <id>`) và một ca âm (`none: [<id>]`), định dạng `eventchannel` / `apache` của `tools/wazuh_rule_test.py`.

Phạm vi lô 1: SigmaHQ `process_creation` Windows và `webserver`, status stable/test, level ≥ medium, kỹ thuật có case playbook riêng (giữ điều kiện của WIP). Linux hoãn: theo R68 rule Linux nhắm `siem-proc`, mà `wazuh_coverage` còn dựng mẫu Linux dạng auditd.

- [ ] **Step 1: Viết test thất bại (sửa `test_sigmahq_import.py` cho đầu ra XML)**

```python
def test_writes_xml_and_cases(tmp_path, three_sigma_rules):
    out = sigmahq_import.write_batch(three_sigma_rules, rules_file=tmp_path / "0966-sigmahq.xml",
                                     cases_file=tmp_path / "0966-sigmahq.yml", first_id=108000, today="2026-11-20")
    rules = ET.fromstring((tmp_path / "0966-sigmahq.xml").read_text()).findall(".//rule")
    ids = {int(r.get("id")) for r in rules}
    cases = yaml.safe_load((tmp_path / "0966-sigmahq.yml").read_text())
    assert min(ids) == 108000 and all("shadow" in r.findtext("group") for r in rules)
    assert {c["rule"] for c in cases if "rule" in c} == ids and {c["none"][0] for c in cases if "none" in c} == ids

def test_skips_rules_already_imported(tmp_path, three_sigma_rules): ...sigmahq_id có trong file -> bỏ, id đánh tiếp
def test_license_header(tmp_path, three_sigma_rules): ...assert "DRL 1.1" in đầu file
```

- [ ] **Step 2: Chạy test, phải thất bại**

  Run: `cd server && $PY -m pytest tests/test_sigmahq_import.py -q`
  Expected: FAIL, `write_batch` chưa có / còn ghi YAML.

- [ ] **Step 3: Viết lại phần ghi và phần đo độ phủ của `tools/sigmahq_import.py`**

  Bỏ import `detection.lint`, `detection.ruletest`, `detection.rules.load_rules`. Chọn tham lam theo số mẫu tấn công MỚI bắt được: cây Python khớp mẫu chưa có Hit Wazuh `level >= 7`, và không khớp mẫu bình thường nào.

- [ ] **Step 4: Chạy test, phải qua; sinh lô 1; chạy các bước của CI `wazuh-rules` trên máy**

  Run: `cd server && $PY -m pytest tests/test_sigmahq_import.py -q`, sau đó `$PY ../tools/sigmahq_import.py --write`.

  Run tiếp (giống CI):
  1. `$PY tools/wazuh_rule_lint.py`;
  2. dựng manager tạm `p4shq` với rule của nhánh;
  3. grep ossec.log không có `(7612)|(7617)|(7619)`;
  4. `$PY tools/wazuh_stock_reach.py stock-rules`;
  5. `$PY tools/wazuh_rule_test.py --url https://localhost:<port> --insecure wazuh/manager/tests/cases`.

  Expected:
  - lint 0 lỗi;
  - mọi ca qua, kể cả `0998-stock-real-alerts.yml` và `0997-stock-if-group.yml` (rule bóng mới không cướp alert thật);
  - ghi số mẫu mới bắt được vào "Kết quả đo P4".

- [ ] **Step 5: Commit**

```bash
git add tools/sigmahq_import.py server/tests/test_sigmahq_import.py wazuh/manager/rules/0966-sigmahq.xml wazuh/manager/tests/cases/0966-sigmahq.yml
git commit -m "feat(rules): nhập lô 1 SigmaHQ (30 rule, chạy bóng) thành 0966-sigmahq.xml (Task 24)"
```

- [ ] **Step 6: Hỏi chủ dự án rồi mới xóa worktree `coverage-batch1`**

  Lệnh: `git worktree remove --force .claude/worktrees/coverage-batch1`, sau đó `git branch -D feature/coverage-batch1`. Có bản sao lưu WIP, nhưng vẫn phải được đồng ý.

---

### Task 25: Xóa engine YAML

**Files:**
- Create: `server/siem/ai/condition.py`: chuyển NGUYÊN `Condition`, `Rule`, `RuleException`, `_eval`, `_leaf`, `_lower`, `regex_risk` từ `detection/rules.py`. AI vẫn dùng chúng làm bộ tìm (R66).
- Modify:
  - `server/siem/detection/alerts.py`: nhận `SEVERITY_SCORE`. Sửa import ở `soar/engine.py`, `soar/health.py`, `soar/retrohunt.py`, `soar/risk.py`, `rules_catalog.py`.
  - Import của `ai/benchmark.py`, `ai/deploy.py`, `ai/golden.py`, `ai/validate.py`, `ai/worker.py`, `tools/wazuh_coverage.py` và `server/tests/test_wazuh_xml.py` → `siem.ai.condition`.
  - `server/siem/analyzer.py`: bỏ `RuleEngine` / `load_rules` / `rules_fingerprint` / nhánh `RULE_ENGINE_ENABLED`.
  - `server/siem/rules_catalog.py`: bỏ phần doc YAML, `covers`, `lint`, `EXCEPTIONS_DIR`, `SKIP_DIRS`.
  - `server/siem/manager/kpi.py`: độ phủ chỉ từ catalog Wazuh (R49).
  - `server/siem/manager/api.py`: chỗ gọi `load_rules` gần dòng 790 và route của nó.
  - `server/siem/manager/static/console.html`: phần giao diện của route đó.
  - `server/siem/detection/wazuh.py`: bỏ `covered_by`.
  - `server/siem/settings.py`: bỏ `RULE_ENGINE_ENABLED`, `RULES_DIR` và các hằng chỉ engine dùng.
  - `docker-compose.yml`: bỏ mount `./server/rules…` của manager và AI.
  - `install.sh` + `server/tests/test_install_sh.py` (nếu tạo thư mục `server/rules`).
  - `.github/workflows/ci.yml`: bỏ job `rules`.
  - `tools/e2e_test.py`: bước nào còn dựa vào rule YAML.
- Delete:
  - `server/siem/detection/rules.py`, `server/siem/detection/lint.py`, `server/siem/detection/ruletest.py`;
  - `tools/rule_lint.py`;
  - `server/rules/` (`*.yml`, `cases/`, `ai/`, `exceptions/`);
  - test của các phần đã xóa.
- Test: cả bộ.

**Interfaces:**
- Produces: `siem.ai.condition.{Condition, Rule, RuleException, regex_risk}`, chữ ký giữ nguyên như ở `detection/rules.py`. `siem.detection.alerts.SEVERITY_SCORE`.

- [ ] **Step 1: Kiểm nhánh của phiên khác**

  Run: `git log --oneline origin/main..origin/fix/ui-test-rule-search`, rồi `git diff --stat origin/main...origin/fix/ui-test-rule-search`.

  Nhánh đó sửa phần thử rule YAML trên console, nên sẽ xung đột. Dừng và hỏi chủ dự án: bỏ nhánh, hay gộp nó trước.

- [ ] **Step 2: Chuyển `condition.py` và `SEVERITY_SCORE`, sửa import, chạy cả bộ**

  Run: `cd server && $PY -m pytest -q`
  Expected: PASS, chưa xóa gì.

- [ ] **Step 3: Xóa phần còn lại theo danh sách Files, sửa test hỏng vì phần đã xóa**

- [ ] **Step 4: Kiểm không còn tham chiếu**

  Run: `git grep -nE "detection\.rules|detection\.lint|ruletest|load_rules|RuleEngine|rules_fingerprint|RULE_ENGINE_ENABLED|server/rules|rule_lint\.py|covered_by" -- server tools docker-compose.yml install.sh .github`
  Expected: không có dòng nào, trừ chú thích lịch sử trong tài liệu (tài liệu sửa ở Task 26).

- [ ] **Step 5: Chạy cả bộ, CI và E2E trên project test**

  Run: `cd server && $PY -m pytest -q`. Push nhánh, chờ 5 job CI còn lại xanh. Chạy `$PY tools/e2e_test.py` trên project `p4e2e` (xem `Test.md` §0).
  Expected: PASS. E2E đạt đủ, số bước mới ghi vào `Test.md`.

- [ ] **Step 6: Commit**

```bash
git add -A server tools docker-compose.yml install.sh .github
git commit -m "refactor: xóa engine rule YAML, giữ bộ đánh giá điều kiện cho AI ở siem.ai.condition (Task 25)"
```

---

### Task 26: Tài liệu, phán quyết, triển khai thử

**Files:**
- Modify:
  - `RULES.md`: viết lại mục 1–8. Nội dung: cơ chế XML, dải id, quy trình detection-as-code (lint → ca → stock_reach), chạy bóng bằng nhóm `shadow`, bảng `legacy_map`, SigmaHQ `0966`, rule AI `ai.xml`.
  - `README.md` §3.
  - `SOC-OPERATIONS.md` mục 4: bật chính thức rule AI trên console, tiêu chí 7 ngày / 5 alert / 30%.
  - `AI-README.md`: đầu ra XML, sandbox, cổng Wazuh, kết quả chạy thử của Task 21, mục mới §9.11.
  - `DEPLOY-VM.md`: service `wazuh-sandbox`, volume `ai_sandbox`, RAM thêm. Trên Linux, `wazuh/manager/rules` cần quyền 644/755 (S2).
  - `ROADMAP.md` §6, `Test.md` §0.
  - `docs/wazuh-ruleset-decisions.md`: thêm R66–R74.
  - `docs/superpowers/plans/2026-10-31-wazuh-unified-ruleset.md`: tiêu đề P4 trỏ sang file này.

- [ ] **Step 1: Sửa tài liệu theo danh sách trên.** Mỗi số liệu phải lấy từ "Kết quả đo P4", không ghi số chưa đo.

- [ ] **Step 2: Kiểm link và mục lục**

  Run: `git grep -nE "server/rules/|RULE_ENGINE_ENABLED|engine YAML" -- "*.md"`
  Expected: chỉ còn trong đoạn lịch sử (ghi rõ "đã xóa ở Task 25").

- [ ] **Step 3: Commit**

```bash
git add *.md docs
git commit -m "docs: rule AI và SigmaHQ ra Wazuh XML, sandbox, R66–R74 (Task 26)"
```

- [ ] **Step 4: Triển khai lên stack thật. Chỉ làm khi chủ dự án đã gộp PR và yêu cầu triển khai**
  1. Sao lưu: volume vào `D:\GSANM\BTL\backup\stack-<ngày>\`, rồi `python tools/es_snapshot.py now`.
  2. Build image theo `DEPLOY-VM.md` §9.
  3. `docker compose --profile demo up -d --no-build --remove-orphans`.
  4. Profile `ai` (Ollama + sandbox, khoảng 6,6 GB model + 1 GB manager) chỉ bật khi chủ dự án đồng ý.
  5. `python tools/e2e_test.py` phải đạt đủ.

---

## Ngoài phạm vi

- **Đổi model AI** (mục tiêu thứ 4 ban đầu). Sau Task 21, `tools/bench_ai_models.py` chạy qua cổng Wazuh để so các model ứng viên (`ai/benchmark.py` đo rule YAML, đã xóa ở Task 25, R78). Chọn model là việc của chủ dự án.
- SigmaHQ Linux (`siem-proc`), EVTX mẫu không có log thô, và bơm lại `siem-events` thật vào sandbox (R74).

## Kết quả đo P4

Gom ở Task 26 từ báo cáo Task 19 đến 25 (`.superpowers/sdd/2026-11-06-p4-ai-wazuh-xml/`). Wazuh manager 4.14.8, manager tạm / sandbox
không nối mạng, không đụng stack thật.

**S3 (Task 19, bộ dịch trên Wazuh thật):**
- Lookahead pcre2 `(?i)^(?=[\s\S]*?abc)(?![\s\S]*?xyz)` trên `commandLine` khớp đúng ("xx abc yy" ra 119010; "abc xyz" và "zzz" không ra).
- `(?:'|%27)` trong `<url type="pcre2">` khớp cả dạng thô lẫn mã hóa (`/a?id=1'` và `/a?id=1%27` ra 119020, `/a?id=1` không ra).
- `<protocol>` và `<id>` nhận pcre2: chỉ POST 404 ra 119021.
- Hai anh em 119000 (level 7) và 119001 (level 10) dưới 61603 cùng khớp một event: alert là 119001 (xác nhận R70).

**Task 19b / 21 (eventchannel và cha Windows):**
- Eventchannel nhân đôi dấu `\` trong `win.eventdata.*`: một dấu `\` không khớp, hai dấu thì khớp. Bộ dịch viết `\` thành
  `(?:\x5c){1,2}`, `EMITTER_VERSION` 2.
- Rule gom level 0 92025 / 92028 / 92042 / 92069 (`0800-sysmon_id_1.xml`) nuốt event Sysmon 1 trước anh em dưới 61603. Cha Windows
  thành `61603,92025,92028,92042,92069` (R75). Đo lại: reg add, PowerShell chạy script, netsh, cha WmiPrvSE, image thường đều ra ứng
  viên; `reg save HKLM\SAM` vẫn ra 92026 (level 14), ứng viên level 10 không cướp.

**S4 (Task 20, sandbox):**
- `wazuh-control restart` tới khi file state cập nhật: 13,4 / 14,2 / 11,1 giây (11–14 giây); job IT 3 event khoảng 36 giây.
- Header `(sbx-<ident>)`: alert có `agent.name = sbx-<ident>`, `location` chỉ còn đường dẫn; hai dòng giống hệt khác ident ra hai alert riêng.
- 50.000 event: vòng gửi cũ (không chờ hàng đợi) rơi 7.591/50.000 (15%); thêm chờ khi hàng đợi analysisd > 20%: 50.000 event 73 giây,
  0 rơi. `golden_events` toàn dataset: 29.323 event cho 30.186 mẫu (apache 25.088, eventchannel 2.889, siem-proc 1.346), dựng 5,8 giây.

**Task 21 Step 5 (chu kỳ thật, project `p4gate`, GPU, `qwen3.5:9b`):**
- `errors: []`; 5 đề xuất: 2 qua cổng: linux-T1552.001 (bắt 19/19 mẫu kiểm tra, báo nhầm 0/200, che 0) và web `csic2010:backup-file`
  (bắt 1.190/1.307, báo nhầm 0/10.000, che 0); 3 invalid (windows-T1548.002 do Wazuh: 0/16, 20 mẫu chỉ Python khớp vì lỗi `\`;
  windows-T1547.001 và linux-T1059.004 do Python).
- 4 job sandbox: nền 29.323 event 55 giây (đo lại, không có máy ngủ chen giữa), ứng viên 36–50 giây (Linux 36,2, Windows 37,2, web 49,9).
- Khoảng trống: 16.882/19.315 mẫu tấn công chưa được Wazuh bắt (có log thô: web 13.604/15.088, Windows 2.144/2.218, Linux 1.134/1.146);
  863 mẫu Splunk không có log thô không tính.

**Task 24 Step 4 (SigmaHQ lô 1):**
- 30 rule Windows 108000–108029, 60 ca 0 sai trên manager tạm; lint 0 lỗi, `ossec.log` sạch, `wazuh_stock_reach.py` 0 lỗi.
- 188 mẫu tấn công mới chỉ SigmaHQ bắt trên 17.306 mẫu Windows + web (cây Python ước 186), không event bị bỏ. Lô không có rule web.
- Rule Windows có `>`, `<`, `&` bị bỏ: Wazuh giữ thực thể XML trong `win.eventdata.*` (108017), Task 19c hoãn (R77).

**Task 26 (kiểm tra cuối, project `p4e2e` cách ly, 08/11/2026):** unit test 660 đạt / 34 bỏ qua; lint 11 file 0 lỗi; E2E 43/43;
`ai.xml` do `emit` + `render_ai_file` sinh nạp được vào wazuh-manager thật và ra alert bóng `WZH-109001` / `WZH-109003` từ event thật
của agent; gỡ tới file rỗng bị Wazuh từ chối (`Group 'group' without any rule.`), chưa sửa. `GET /rules` không liệt kê
`rules-dynamic/` (R83).
