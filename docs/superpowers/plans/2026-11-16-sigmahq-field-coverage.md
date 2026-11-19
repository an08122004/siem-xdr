# Mở rộng độ phủ SigmaHQ bằng trường Sysmon: kế hoạch triển khai

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cho bộ dịch Sigma→Wazuh XML ánh xạ thêm các trường Sysmon EventID 1 (OriginalFileName, Description, Product, Company), sửa lỗi đếm mẫu của `sigmahq_import`, rồi nhập lại lô SigmaHQ và đo số rule / mẫu tấn công mới thật sự thêm được.

**Architecture:**
- Bộ dịch có hai tầng: `sigma.py` (`_PROC`, `FIELDS`) ánh xạ **tên trường Sigma → trường ECS** cho cây điều kiện Python; `wazuh_xml.py` (`FIELDS["windows"]`) ánh xạ **trường ECS → `win.eventdata.*`** cho pcre2. Thêm trường = thêm một mục ở cả hai tầng, theo đúng khuôn `CurrentDirectory` đã có.
- Mẫu Windows của dataset chỉ có 7 trường (không có OriginalFileName), nên lúc chuẩn hóa mẫu Sysmon EventID 1 phải **suy ra** `OriginalFileName = tên file của Image` để rule OriginalFileName kiểm định được.
- `sigmahq_import.pick()` đang đếm "mẫu mới" chỉ so với rule gốc Wazuh, bỏ sót rule 108xxx đã ghi của lô trước → lô 2+ đếm thừa và sinh ca dương không thỏa. Sửa để trừ cả mẫu đã bị 108xxx bắt.
- Cuối cùng chạy lại tool trên manager tạm, đo, ghi lô mới (nếu có) + ca test, tài liệu.

**Tech Stack:** Python 3.12 (CI) / 3.14 (máy dev), Wazuh 4.14.8 (eventchannel `win.eventdata.*`), scikit-learn/numpy (không đổi), dataset `datasets/processed/`.

**Spec:** không có tài liệu riêng — chủ dự án chọn hướng 2 sau phân tích ba hướng (ghi trong hội thoại 16/11). Quyết định thiết kế dưới đây là của controller.

## Bối cảnh (đo 16/11/2026)

- 598/1324 rule process_creation đủ điều kiện dùng trường ngoài 6 trường đang ánh xạ. Thống kê: **OriginalFileName 505**, Description 68, Product 43, Hashes 38, IntegrityLevel 28, Company 18, còn lại ~10.
- Ánh xạ thêm 3 trường (OriginalFileName, Description, Product) gỡ cổng "trường" cho 508/598; thêm 6 → 588.
- Trường Wazuh thật (rule gốc đang dùng): `win.eventdata.originalFileName`, `win.eventdata.description`, `win.eventdata.integrityLevel` (xác nhận trên manager). Hashes là chuỗi ghép ("SHA256=…,MD5=…"), IntegrityLevel/Company dataset không có giá trị thật → **ngoài phạm vi lô này** (lợi thấp).
- **Giới hạn thật còn lại:** mẫu Atomic dựng lại từ dòng lệnh, OriginalFileName suy ra = tên file Image (không có mẫu "đổi tên file"). Nên rule OriginalFileName kiểm định được, nhưng **số rule NHẬP THÊM thật có thể thấp** vì nhiều rule OriginalFileName trùng việc với rule Image (gate "bắt mẫu mới" vẫn loại). Task 4 đo con số thật; kế hoạch KHÔNG hứa số lượng.

## Quyết định thiết kế

| # | Quyết định | Lý do |
|---|---|---|
| F1 | Ánh xạ 4 trường: OriginalFileName, Description, Product, Company. Hashes / IntegrityLevel hoãn | 4 trường này có trường ECS/Wazuh sạch và dataset có / suy ra được; Hashes ghép phức tạp, IntegrityLevel/Company mẫu toàn giá trị giả |
| F2 | ECS cho trường mới theo khuôn `CurrentDirectory`: `winlog.event_data.<Field>` (giữ hoa) | Không ép vào ECS chuẩn (process.pe.*) cho gọn và nhất quán với mục đã có |
| F3 | Chuẩn hóa mẫu Sysmon EventID 1: nếu không có OriginalFileName thì suy ra = `basename(Image)` (cắt theo `\` hoặc `/`) | Dataset không mang trường này; đây là giá trị đúng cho binary KHÔNG đổi tên (trường hợp mẫu có) |
| F4 | `pick()` đếm mẫu mới = mẫu chưa bị rule gốc Wazuh **và chưa bị rule 108xxx đã ghi** bắt; ca dương chọn mẫu rule bắt mà 108xxx cũ chưa bắt | Lỗi hiện tại làm lô 2+ đếm thừa + ca dương bị rule 108xxx cũ che → thất bại CI |
| F5 | Task 19c (`< > &`) tách thành task riêng, đo trên Wazuh thật trước; bỏ nếu không khớp được | Phụ thuộc hành vi Wazuh giữ thực thể XML, chưa chắc; không chặn phần còn lại |

## Global Constraints

- Python chạy cả 3.12 (CI) và 3.14 (máy dev); không cú pháp/hành vi lệch. Chạy test đổi trong container `python:3.12-slim` trước khi commit.
- Không thêm dependency.
- Trường Wazuh (xác nhận trên manager 4.14.8): `win.eventdata.originalFileName`, `win.eventdata.description`, `win.eventdata.product`, `win.eventdata.company` (camelCase chữ đầu thường).
- Thử nghiệm KHÔNG đụng stack thật `siem-xdr-*`; manager tạm tên riêng, `--network none`, cổng không trùng 55000; secrets tạm bằng `tools/init_secrets.py`, không in/commit `secrets/`.
- Giữ ngữ nghĩa bộ dịch: trường mới chỉ thêm, các test Task 19/19b/19c hiện có phải vẫn xanh. `EMITTER_VERSION` tăng khi đổi đầu ra XML (thêm trường = có đổi → tăng lên "3").
- Thông điệp/tài liệu tiếng Việt có dấu; chi tiết ghi AI-README, RULES; README chỉ tóm tắt.

## Review Focus

1. **Rule OriginalFileName dịch ra pcre2 khớp giá trị thật của Wazuh.** `win.eventdata.originalFileName` của Sysmon là tên file (vd `reg.exe`), không có đường dẫn; rule `OriginalFileName|endswith: \reg.exe` phải vẫn khớp (dấu `\` đầu). Test ở Task 1.
2. **Suy ra OriginalFileName không ghi đè khi mẫu đã có.** Mẫu thật (nếu có OriginalFileName) phải giữ nguyên; chỉ suy ra khi thiếu. Test ở Task 1.
3. **`pick()` sau sửa không còn sinh ca dương bị rule 108xxx cũ che.** Mẫu ca dương phải là mẫu rule mới bắt mà mọi rule 108xxx đã ghi chưa bắt. Test ở Task 2.
4. **Giá trị có `\` nhân đôi của Windows áp cho trường mới.** OriginalFileName hiếm có `\`, nhưng nếu có thì theo R (19b) `(?:\x5c){1,2}`. Test ở Task 1.
5. **Trường mới đi qua lint và nạp được trên Wazuh** (ca eventchannel của rule OriginalFileName ra alert). Đo ở Task 4.

---

### Task 1: Ánh xạ thêm trường Sysmon trong bộ dịch

**Files:**
- Modify: `server/siem/ai/sigma.py` (`FIELDS["windows"]`, `_PROC`), `server/siem/ai/wazuh_xml.py` (`FIELDS["windows"]`), `server/siem/pipeline/normalize.py` (suy ra OriginalFileName cho doc Sysmon EventID 1).
- Test: `server/tests/test_sigma.py`, `server/tests/test_wazuh_xml.py`, `server/tests/test_pipeline.py`.

**Interfaces:**
- Produces (bộ dịch sau khi thêm):
  - `sigma._PROC` thêm: `"OriginalFileName": "winlog.event_data.OriginalFileName"`, `"Description": "winlog.event_data.Description"`, `"Product": "winlog.event_data.Product"`, `"Company": "winlog.event_data.Company"`.
  - `sigma.FIELDS["windows"]` thêm 4 khóa đó với mô tả tiếng Việt ngắn (đưa vào prompt).
  - `wazuh_xml.FIELDS["windows"]` thêm: `"winlog.event_data.OriginalFileName": ("win.eventdata.originalFileName", "")`, `…Description → ("win.eventdata.description", "")`, `…Product → ("win.eventdata.product", "")`, `…Company → ("win.eventdata.company", "")`.
  - `normalize`: doc Sysmon EventID 1 (có `winlog.event_data.Image` hoặc `process.executable`, không có `winlog.event_data.OriginalFileName`) được đặt `winlog.event_data.OriginalFileName = basename` (tên sau `\` hoặc `/` cuối của Image).

- [ ] **Step 1: Viết test thất bại**

```python
# test_sigma.py
def test_compile_maps_original_file_name():
    tree, notes = sigma.compile_rule(
        {"detection": "sel:\n  OriginalFileName|endswith: \\reg.exe\ncondition: sel\n"}, "windows")
    leaves = [l for l in _leaves(tree)]
    assert any(l["field"] == "winlog.event_data.OriginalFileName" for l in leaves)
    assert all("not recorded" not in n for n in notes)

def test_description_product_company_mapped():
    for f, ecs in [("Description", "winlog.event_data.Description"), ("Product", "winlog.event_data.Product"),
                   ("Company", "winlog.event_data.Company")]:
        tree, notes = sigma.compile_rule({"detection": f"sel:\n  {f}: X\ncondition: sel\n"}, "windows")
        assert any(l["field"] == ecs for l in _leaves(tree)) and not notes

# test_wazuh_xml.py
def test_emit_original_file_name_to_wazuh_field():
    tree = {"field": "winlog.event_data.OriginalFileName", "op": "endswith", "value": "\\reg.exe"}
    r, = rules(wx.emit(tree, **{**KW, "domain": "windows"}).xml)
    f = r.find("field")
    assert f.get("name") == "win.eventdata.originalFileName"
    py = re.compile(f.text.replace(r"\z", r"\Z"))
    assert py.search("reg.exe") and py.search("REG.EXE")          # Wazuh lưu tên file, không đường dẫn
    assert wx.EMITTER_VERSION == "3"

# test_pipeline.py
def test_sysmon_derives_original_file_name_when_missing():
    doc = normalize({"event_type": "...eventchannel...", ..."Image": "C:\\Windows\\System32\\reg.exe"...})
    assert get(doc, "winlog.event_data.OriginalFileName") == "reg.exe"

def test_sysmon_keeps_real_original_file_name():
    doc = normalize({...Image "...\\xcopy.exe", OriginalFileName "robocopy.exe"...})
    assert get(doc, "winlog.event_data.OriginalFileName") == "robocopy.exe"   # KHÔNG ghi đè
```

  Helper `_leaves(tree)` duyệt cây điều kiện lấy các lá `{"field","op","value"}` (đã có trong test_sigma hiện tại hoặc viết tại chỗ). `KW`, `rules(...)` dùng như test_wazuh_xml hiện có.

- [ ] **Step 2: Chạy test, phải thất bại**
  Run: `cd server && $PY -m pytest tests/test_sigma.py tests/test_wazuh_xml.py tests/test_pipeline.py -q -k "original or description or product or company or sysmon_derive or sysmon_keep"`
  Expected: FAIL (field "not recorded" / KeyError / thiếu trường suy ra).

- [ ] **Step 3: Thêm ánh xạ và suy ra trường**
  - sigma.py: thêm 4 khóa vào `_PROC` và `FIELDS["windows"]`.
  - wazuh_xml.py: thêm 4 mục vào `FIELDS["windows"]`; tăng `EMITTER_VERSION` lên `"3"`.
  - normalize.py: ở chỗ dựng doc Sysmon EventID 1, nếu chưa có `winlog.event_data.OriginalFileName` thì đặt = phần sau dấu `\`/`/` cuối của Image (dùng `rsplit`), chỉ khi có Image.

- [ ] **Step 4: Chạy test, phải qua; cả bộ; container 3.12**
  Run: `cd server && $PY -m pytest tests/test_sigma.py tests/test_wazuh_xml.py tests/test_pipeline.py -q && $PY -m pytest -q`, rồi chạy 3 file đó trong `python:3.12-slim`.
  Expected: PASS; test Task 19/19b cũ vẫn xanh.

- [ ] **Step 5: Commit**
  `git add server/siem/ai/sigma.py server/siem/ai/wazuh_xml.py server/siem/pipeline/normalize.py server/tests/ && git commit -m "feat(ai): ánh xạ trường Sysmon OriginalFileName/Description/Product/Company sang Wazuh XML"`

---

### Task 2: Sửa đếm mẫu của `sigmahq_import.pick()`

**Files:**
- Modify: `tools/sigmahq_import.py` (`pick()` và chỗ sinh ca dương).
- Test: `server/tests/test_sigmahq_import.py`.

**Interfaces:**
- Consumes: `pick(cands, items, covered, batch)` hiện có (`covered: set[int]` = chỉ số mẫu đã bị rule gốc Wazuh bắt).
- Produces: `pick` nhận thêm thông tin mẫu đã bị **rule 108xxx đã ghi** bắt và loại chúng khỏi "mẫu mới"; ca dương của mỗi rule chọn mẫu rule đó bắt mà không mẫu nào trong `covered ∪ (mẫu 108xxx cũ bắt)` có.

- [ ] **Step 1: Viết test thất bại** (`test_sigmahq_import.py`)

```python
def test_pick_excludes_samples_won_by_written_batch_rules():
    # rule A (108000 đã ghi) bắt mẫu {1,2}; ứng viên B bắt {2,3}; chỉ mẫu 3 là MỚI
    picked = imp.pick([candB], ITEMS, covered=set(), batch=30, already={2})
    assert picked and picked[0].hits_new == {3} and picked[0].pos["i"] == 3   # ca dương KHÔNG dùng mẫu 2

def test_pick_drops_candidate_fully_shadowed_by_batch():
    assert imp.pick([candB], ITEMS, covered=set(), batch=30, already={2, 3}) == []
```

  `already: set[int]` = chỉ số mẫu đã bị rule 108xxx đã ghi bắt; bên gọi (`main`) tính bằng cách chạy ruleset hiện có (gồm 0966) trên mẫu và lấy mẫu có Hit 108xxx.

- [ ] **Step 2: Chạy test, phải thất bại**
  Run: `cd server && $PY -m pytest tests/test_sigmahq_import.py -q -k "shadowed or won_by"`
  Expected: FAIL (`pick` chưa có tham số `already` / `hits_new`).

- [ ] **Step 3: Sửa `pick` và chỗ gọi**
  - `pick(..., already: set[int] = frozenset())`: "mẫu mới" của một ứng viên = mẫu nó bắt trừ `covered` trừ `already`. Rule không còn mẫu mới thì bỏ. Ca dương chọn từ mẫu mới.
  - `main`: trước khi chọn lô kế, chạy ruleset hiện tại (có 0966 của lô trước) để biết mẫu nào đã bị 108xxx bắt, truyền `already`.

- [ ] **Step 4: Chạy test, phải qua; cả bộ**
  Run: `cd server && $PY -m pytest tests/test_sigmahq_import.py -q && $PY -m pytest -q`
  Expected: PASS.

- [ ] **Step 5: Commit**
  `git commit -m "fix(sigmahq): pick() trừ mẫu đã bị rule 108xxx đã ghi bắt, ca dương không bị lô cũ che"`

---

### Task 3 (tùy chọn): Task 19c — hỗ trợ `< > &` trong trường Windows

Làm sau Task 1. Nếu đo cho thấy không khớp được thì DỪNG và ghi lại, không chặn Task 4.

**Files:** `server/siem/ai/wazuh_xml.py` (`_map_leaf` / `_win_lit`), `server/tests/test_wazuh_xml.py`, `docs/wazuh-ruleset-decisions.md`.

- [ ] **Step 1: Đo trên Wazuh thật** — manager tạm (`shqf-spike`, `--network none`), rule thăm dò `<field name="win.eventdata.commandLine" type="pcre2">`, bơm event có `CommandLine` chứa `> nul`, `a & b`, `x < y` qua `wazuh_coverage.run_wazuh`. Ghi: Wazuh lưu các ký tự đó thành `&gt; &amp; &lt;` hay giữ nguyên `> & <`. Nếu giữ thực thể: mẫu pcre2 phải khớp dạng thực thể.
- [ ] **Step 2–4:** bỏ việc từ chối `< > &` ở domain windows; thay bằng: ký tự `>` → `(?:>|&gt;)`, `<` → `(?:<|&lt;)`, `&` → `(?:&|&amp;)` (theo kết quả đo). Test: giá trị Windows có `> nul` sinh mẫu khớp cả hai dạng; cập nhật R77. Giữ `EMITTER_VERSION` "3" (đã tăng ở Task 1).
- [ ] **Step 5:** Commit `fix(ai): trường Windows có < > & khớp cả dạng thực thể XML của Wazuh (Task 19c)`. Nếu DỪNG ở Step 1: chỉ commit ghi chú đo vào decisions.

---

### Task 4: Nhập lại lô, đo, tài liệu

**Files:** `wazuh/manager/rules/0966-sigmahq.xml`, `wazuh/manager/tests/cases/0966-sigmahq.yml` (do tool sinh), `AI-README.md`, `RULES.md`, `docs/wazuh-ruleset-decisions.md`.

- [ ] **Step 1: Chạy dry-run** `python tools/sigmahq_import.py` trên manager tạm (tên riêng, cổng 55300) — in số ứng viên mới mở ra nhờ trường mới, và lô đề xuất. Ghi lại.
- [ ] **Step 2: Nhập lô** `--write --batch 30` từng lô tới khi một lô thêm < 5 rule hoặc < 10 mẫu mới, hoặc đạt 120 rule tổng. Sau mỗi lô chạy bước CI `wazuh-rules` (lint; ossec.log không 7612/7617/7619; `wazuh_stock_reach`; ca 0966/0997/0998) và `--measure` (exit 0).
- [ ] **Step 3: Đo** số rule nhập thêm, số mẫu tấn công mới (so mốc lô 1 = 186), và trong đó bao nhiêu nhờ OriginalFileName. Ghi vào AI-README (mục SigmaHQ) và RULES.
- [ ] **Step 4: Commit + PR.** Nếu nhập được 0 rule: vẫn commit Task 1–2 (năng lực bộ dịch + sửa lỗi) và ghi kết luận đo; KHÔNG ghi rule rác.

## Ngoài phạm vi

- Hashes, IntegrityLevel, Company nếu dataset không có giá trị thật (lợi thấp).
- Thu / dựng dataset Windows giàu trường hơn (Hashes thật, binary đổi tên) — đây mới là nút mở độ phủ lớn, nhưng là dự án dữ liệu riêng.
- Rule Linux (siem-proc), rule logsource khác (registry_set, image_load…).
