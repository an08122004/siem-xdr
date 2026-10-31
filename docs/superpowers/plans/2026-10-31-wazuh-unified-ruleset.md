# Bộ rule thống nhất trên Wazuh (phương án A) — kế hoạch triển khai

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Mục tiêu:** mọi phát hiện chạy trong `wazuh-analysisd`. Gồm ruleset gốc Wazuh 4.14.8 (4.515 rule, 168 file) cộng rule riêng dạng XML. Rule riêng chỉ viết khi ruleset gốc chưa bắt được: chuyển từ 41 rule YAML, từ SigmaHQ và từ AI. Analyzer chỉ còn chuẩn hóa, lưu, làm giàu và chuyển cảnh báo Wazuh thành alert.

**Kiến trúc:**
- Rule riêng nằm trong repo (`wazuh/manager/rules/`, `wazuh/manager/decoders/`), mount thẳng vào `/var/ossec/etc/`.
- Rule do console sinh ra (AI, ngoại lệ) nằm trong volume riêng `wazuh_dynamic_rules`.
- Mỗi lần đổi rule chỉ cần `PUT /manager/analysisd/reload` (đã có trong API 4.14.8), không khởi động lại manager.
- Cảnh báo `alerts.json` → analyzer (`detection/wazuh.py`) → `siem-alerts` + Kafka `siem.alerts` → SOAR, giữ nguyên đường đi hiện tại.
- Chạy bóng = rule có nhóm `shadow`.
- Chuyển đổi kiểu chạy song song: rule XML vào ở chế độ bóng, rule YAML vẫn bật. Chỉ tắt engine YAML khi rule XML đã bắt đủ các ca của rule cũ.

**Công nghệ:** Wazuh manager 4.14.8 (rule XML, PCRE2, CDB list, API logtest/reload), Python 3.12 (CI) / 3.14 (venv máy dev), pytest, GitHub Actions.

**Spec:** không có file spec riêng. Quyết định lấy từ hội thoại 31/10/2026 (người dùng chọn phương án A: "tận dụng hơn 3000 rules có sẵn và chuyển các rules khác sang định dạng XML để dùng chung luôn nếu cần") và mục *Quyết định* bên dưới.

## Hiện trạng (đo 31/10/2026)

| Nguồn | Số rule | Engine | Ghi chú |
|---|---|---|---|
| Rule tự viết `server/rules/*.yml` | 41: 30 khớp mẫu, 10 đếm ngưỡng (4 rule đếm giá trị khác nhau), 1 chuỗi | analyzer | FIM-001 đang chạy bóng |
| SigmaHQ lô 1 `server/rules/sigmahq/lo-01.yml` | 30 `SHQ-`, chạy bóng | analyzer | chỉ có ở nhánh `feature/coverage-batch1`, chưa commit |
| Rule AI `rules/ai/` | 0 đã triển khai | analyzer | đề xuất sinh dạng Sigma |
| Ruleset gốc + `local_rules.xml` | 4.515 + 2 (100100, 100101) | wazuh-analysisd | chỉ chuyển thành `WZH-<id>` khi thuộc nhóm syscheck/rootcheck/vulnerability/virustotal/yara và level ≥ 7, hoặc level ≥ 12 |

Rule cũ phụ thuộc trường đã chuẩn hóa ECS (`url.decoded`, `process.command_line`, `source.ip_scope`, `threat.matched`). Wazuh chỉ thấy trường của decoder (`url`, `win.eventdata.commandLine`, `srcip`...) và **không giải mã URL**.

## Quyết định

Các quyết định mình tự chọn được đánh dấu *(Claude)*, người dùng có thể đổi.

1. **Một engine phát hiện:** wazuh-analysisd. Không giữ engine YAML sau khi chuyển xong (Task 18, 23).
2. **"Nếu cần" = chỉ viết rule riêng khi rule gốc không bắt được.** Mỗi rule cũ được xét bằng harness (Task 5):
   - Rule gốc báo đủ mọi ca dương và không báo ca âm → dùng rule gốc. Ghi vào `legacy_map.yml`, chỉnh level/ngưỡng bằng `overwrite="yes"` trong `0190-tuning.xml` nếu cần.
   - Ngược lại → viết rule XML riêng.
3. **Dải id rule riêng:** mỗi file một dải (bảng ở Task 1). `overwrite="yes"` chỉ được dùng trong `0190-tuning.xml` (lint chặn).
4. **Mã alert:** `WZH-<id Wazuh>` cho mọi alert. Rule chuyển từ YAML giữ mã cũ ở đầu `<description>` (vd `WEB-001 Tấn công SQL Injection`) và ở nhóm `legacy_WEB-001`. *(Claude)*
5. **Mức độ:** level ≥ 12 → critical, ≥ 10 → high, ≥ 7 → medium (`detection/wazuh.py:severity_for`, giữ nguyên). Khi chuyển: critical → 12, high → 10, medium → 7. Level < 7 chỉ là event, không thành alert.
6. **Cầu nối:** mọi rule level ≥ `WAZUH_ALERT_MIN_LEVEL` (7) thành alert, không còn lọc theo nhóm. Rule riêng (id ≥ 100000) luôn chuyển. *(Claude; Task 2 đo số alert trên tập bình thường trước khi bật)*
7. **Chống trùng:** làm ở cầu nối. Cùng `(rule.id, srcip hoặc agent.id)` trong `WAZUH_ALERT_SUPPRESS` giây (mặc định 60) thì chỉ ra 1 alert. Không dùng thuộc tính `ignore` của Wazuh, vì `ignore` chặn theo cả rule: kẻ tấn công thứ hai sẽ bị bỏ sót. *(Claude)*
8. **Chạy bóng:** nhóm `shadow` + `<info type="text">shadow_since=YYYY-MM-DD</info>`. Cầu nối đặt `alert.shadow=true`, SOAR bỏ qua như hiện nay. Bật chính thức = bỏ nhóm `shadow` rồi reload.
9. **Ngoại lệ:** rule con level 0 (`<if_sid>` + ít nhất một điều kiện trường) trong `exceptions.xml` của volume động.
10. **Threat intel:** MISP xuất ra CDB list `etc/lists/malicious-ioc/malicious-ip` (đã khai báo sẵn trong `ossec.conf`). TI-001 thành rule `<list>`.
11. **AI vẫn sinh Sigma.** Bộ biên dịch Sigma hiện có (`ai/sigma.py`) thêm đầu ra XML (Task 19). Kiểm định chạy trên Wazuh thật (Task 20).
12. **Lịch:** P0–P3 trước đóng băng 09/11, cổng chuyển 08/11 (Task 18). Chưa đạt thì demo 10/11 chạy YAML bật + XML bóng, chuyển sau nghiệm thu. P4 (AI, SigmaHQ, xóa engine YAML) sau v1.0. *(Claude — chờ người dùng xác nhận)*

## Global Constraints

- Wazuh manager `4.14.8`. Agent ≤ manager. Agent Windows/Linux giữ 4.14.7. Agent OPNsense 4.14.8.
- Dải id riêng 100000–110999. Id gốc < 100000 chỉ được sửa bằng `overwrite="yes"` trong `wazuh/manager/rules/0190-tuning.xml`.
- Mọi rule riêng: `<description>` bắt đầu bằng mã (`WEB-001`, `SHQ-013`, `AI-077`...), có `<mitre><id>`, nhóm chứa `siem`.
- Regex dùng `type="pcre2"`. Không lồng lượng từ (`(a+)+`), giống điều kiện của `tools/rule_lint.py` hiện tại.
- Đổi rule không khởi động lại manager: trước khi reload phải kiểm cú pháp (Task 1), rồi gọi `PUT /manager/analysisd/reload`.
- Không đổi: tên lệnh agent `siem-xdr`, `event.module`, index `siem-*`, topic `siem.*`.
- Đóng băng 09/11/2026, demo 10/11, nghiệm thu 13–16/11 (ROADMAP.md).

## Review Focus

1. **URL mã hóa** (`%27`, `%2527`, `+`, `%u0027`): rule web phải bắt như bản giải mã. Ca test ở Task 9.
2. **Reload với file XML hỏng** (AI hoặc ngoại lệ ghi sai): analysisd phải giữ ruleset cũ, console báo lỗi, không mất event. Ca test ở Task 1 (`test_reload_rejects_invalid_xml`) và Task 16.
3. **Bão alert khi bỏ lọc nhóm** (hàng nghìn rule level ≥ 7 trên log Windows bình thường): đo trên `realdata_normal` + tập bình thường. Ngưỡng ở Task 2: ≤ 1 alert / 100 event bình thường, rule ồn đưa vào tuning.
4. **Ngoại lệ chặn nhầm cả rule cha** (rule level 0 chỉ có `<if_sid>`): validator từ chối. Ca test ở Task 16.
5. **Trùng id hoặc vô tình ghi đè rule gốc** (copy rule gốc mà quên đổi id): lint chặn. Ca test ở Task 4.

---

## P0 — Thử trước (01/11, 1 ngày)

### Task 0: Spike 5 câu hỏi kỹ thuật (bỏ đi sau khi xong, chỉ giữ kết quả)

Làm trên project tạm `wzh-spike` (như cách thử 4.14.8: chép volume, `--no-deps`). Kết quả ghi vào mục *Kết quả P0* cuối file này. Câu nào trả lời "không" thì sửa task liên quan trước khi làm tiếp.

- [ ] **S1 — reload:** gửi 10.000 dòng syslog qua agent demo-web trong lúc gọi `PUT /manager/analysisd/reload` 3 lần.
  - Đạt: số event trong `archives.json` = số đã gửi, rule mới thêm có hiệu lực sau reload.
  - Thử thêm: reload với một file XML hỏng. Đạt: ruleset cũ vẫn chạy, API trả lỗi.
- [ ] **S2 — thư mục rule:** bind mount `./wazuh/manager/rules` → `/var/ossec/etc/rules` (ro) và thêm `<rule_dir>etc/rules-dynamic</rule_dir>` trỏ vào volume.
  - Đạt: analysisd đọc được cả hai (quyền đọc của user `wazuh` trên bind mount từ Windows lẫn Linux).
  - Container `manager` (uid 10001) ghi được vào volume động, `wazuh` đọc được.
- [ ] **S3 — API logtest:** `PUT /logtest` với `log_format` syslog / json / apache, giữ `token` qua nhiều dòng (rule `frequency`).
  - Đạt: rule đếm ngưỡng báo ở đúng dòng thứ N.
  - Windows `eventchannel`: ghi nhận logtest có giải mã được không. Ghi chú 06/10: `wazuh-logtest` 4.14 không chạy DecodeWinevt, nên `tools/wazuh_coverage.py` phải bơm vào hàng đợi analysisd.
- [ ] **S4 — đếm giá trị khác nhau:** thử `<different_url/>`, `<same_field>`, `<not_same_field>` và các thẻ `different_*` khác (`different_srcip`, `different_dstport`...) với `frequency`.
  - Câu hỏi: 4.14.8 có rule kiểu "≥ 20 cổng đích khác nhau từ cùng một nguồn" không. Liên quan NET-001, NET-005, AUTH-003, LNX-005.
  - Không có thì 4 rule này dùng xấp xỉ "≥ N event cùng nguồn" kèm ghi chú giới hạn trong RULES.md.
- [ ] **S5 — giải mã URL:** gửi dòng access log có `%27`, `%2527`, `+`, `%u0027` qua logtest, xem trường `url` ra gì.
  - Nếu ra nguyên dạng mã hóa (dự kiến): Task 9 viết regex bắt cả dạng mã hóa, và ca test có cả hai dạng.

---

## P1 — Nền tảng (02–03/11)

### Task 1: Thư mục rule riêng, volume động, user API `siem-rules`, nạp lại an toàn

**Files:**
- Create: `wazuh/manager/rules/0100-platform.xml` (chuyển 100100, 100101 từ `local_rules.xml`), `wazuh/manager/decoders/` (rỗng, có `.gitkeep`)
- Delete: `wazuh/manager/local_rules.xml`
- Modify: `docker-compose.yml` (wazuh-manager: mount `./wazuh/manager/rules:/var/ossec/etc/rules:ro`, `./wazuh/manager/decoders:/var/ossec/etc/decoders:ro`, volume `wazuh_dynamic_rules:/var/ossec/etc/rules-dynamic`; manager: `wazuh_dynamic_rules:/app/wazuh-rules`, secret `wazuh_rules_api_password`), `wazuh/manager/ossec.conf` (`<rule_dir>etc/rules-dynamic</rule_dir>`), `wazuh/manager/entrypoint/siem_api_user.py` (user `siem-rules`: `manager:read`, `manager:restart`, `rules:read`, `logtest:run`), `tools/init_secrets.py`, `install.sh` (chown volume động như `rules/ai`)
- Create: `server/siem/wazuh_rules.py`
- Test: `server/tests/test_wazuh_rules.py`

Dải id theo file (lint ở Task 4 đọc bảng này từ `wazuh_rules.ID_RANGES`):

| File | Dải |
|---|---|
| `0100-platform.xml` | 100000–100999 |
| `0101-auth.xml` | 101000–101999 |
| `0102-linux.xml` | 102000–102999 |
| `0103-network.xml` | 103000–103999 |
| `0104-web.xml` | 104000–104999 |
| `0105-windows.xml` | 105000–105999 |
| `0106-fim.xml` | 106000–106999 |
| `0107-ti.xml` | 107000–107999 |
| `0108-sigmahq.xml` | 108000–108999 |
| `rules-dynamic/ai.xml` | 109000–109999 |
| `rules-dynamic/exceptions.xml` | 110000–110999 |
| `0190-tuning.xml` | chỉ `overwrite="yes"` trên id < 100000 |

**Interfaces:**
- Produces:
  - `wazuh_rules.ID_RANGES: dict[str, tuple[int, int]]`
  - `wazuh_rules.parse(xml_text: str) -> list[dict]`: mỗi rule một dict `{id:int, level:int, description:str, groups:list[str], mitre:list[str], info:list[str], overwrite:bool, if_sid:list[int]}`; lỗi cú pháp → `WazuhRuleError`
  - `wazuh_rules.write_dynamic(name: str, xml_text: str, api, root: Path = DYNAMIC_DIR) -> None` (`DYNAMIC_DIR = Path("/app/wazuh-rules")`): parse → ghi file tạm → `logtest` 1 dòng mẫu để buộc nạp → đổi tên → `api.reload()`; lỗi thì giữ file cũ, raise `WazuhRuleError`
  - `class WazuhApi`: `request()` như `soar/wazuh.py`, cộng `reload()`, `logtest(event, log_format, location, token=None) -> dict`, `rules(offset, limit) -> dict`. Đăng nhập bằng user `siem-rules`.

- [ ] **Step 1: Viết test hỏng**

```python
def test_parse_reads_id_level_groups_mitre():
    r = wazuh_rules.parse(XML_100100)[0]
    assert r["id"] == 100100 and r["level"] == 10 and "siem" in r["groups"]

def test_parse_rejects_broken_xml():
    with pytest.raises(wazuh_rules.WazuhRuleError):
        wazuh_rules.parse("<group name='x'><rule id='109001'>")

def test_reload_rejects_invalid_xml(tmp_path):
    api = FakeApi()
    (tmp_path / "ai.xml").write_text(GOOD)
    with pytest.raises(wazuh_rules.WazuhRuleError):
        wazuh_rules.write_dynamic("ai.xml", "<rule", api, root=tmp_path)
    assert (tmp_path / "ai.xml").read_text() == GOOD and api.reloads == 0
```

- [ ] **Step 2:** `cd server && python -m pytest tests/test_wazuh_rules.py -q` → FAIL (chưa có module)
- [ ] **Step 3:** viết `server/siem/wazuh_rules.py`. Wazuh file rule không có thẻ gốc duy nhất, nên bọc trong `<root>` rồi parse bằng `xml.etree.ElementTree`. Riêng việc hiểu `level`, `overwrite` thì không cần thư viện ngoài.
- [ ] **Step 4:** chạy test → PASS. `docker compose up -d --no-deps wazuh-manager` → healthy, `wazuh-control status` đủ tiến trình, rule 100100 vẫn báo (tạo file trong htdocs của demo-web như lần thử 4.14.8).
- [ ] **Step 5:** commit `wazuh: thư mục rule riêng, volume rule động, user API siem-rules`

### Task 2: Cầu nối mọi cảnh báo Wazuh, chạy bóng bằng nhóm, chống trùng

**Files:**
- Modify: `server/siem/detection/wazuh.py` (`should_bridge`, `to_alert`), `server/siem/settings.py` (`WAZUH_ALERT_GROUPS` mặc định rỗng = mọi nhóm, thêm `WAZUH_ALERT_SUPPRESS=60`), `server/siem/detection/alerts.py:from_wazuh` (đặt `alert.shadow`, `rule.legacy_id` từ nhóm `legacy_*`)
- Create: `tools/wazuh_noise.py` (đếm alert theo rule trên tập bình thường, tái dùng `tools/wazuh_coverage.run_wazuh`)
- Test: `server/tests/test_wazuh.py`

**Interfaces:**
- Consumes: định dạng `alerts.json` hiện tại.
- Produces:
  - `should_bridge(rule: dict, groups=None, min_level=None, any_level=None) -> bool` (giữ chữ ký)
  - `class Suppressor: seen(key: tuple, now: float) -> bool`
  - alert có `alert.shadow: bool`, `rule.legacy_id: str | None`

- [ ] **Step 1: Viết test hỏng**

```python
def test_any_group_level7_bridged_by_default():
    assert should_bridge({"id": "60122", "level": 10, "groups": ["windows", "authentication_failures"]})

def test_level6_not_bridged():
    assert not should_bridge({"id": "31101", "level": 5, "groups": ["web"]})

def test_shadow_group_marks_alert_shadow():
    a = to_alert(wazuh_alert_doc(rule={"id": "104001", "level": 10, "groups": ["siem", "web", "shadow", "legacy_WEB-001"]}))
    assert a["alert"]["shadow"] is True and a["rule"]["legacy_id"] == "WEB-001"

def test_same_rule_same_source_suppressed_60s():
    s = Suppressor(60)
    assert not s.seen(("WZH-104001", "203.0.113.5"), 0) and s.seen(("WZH-104001", "203.0.113.5"), 30)
    assert not s.seen(("WZH-104001", "198.51.100.7"), 30) and not s.seen(("WZH-104001", "203.0.113.5"), 61)
```

- [ ] **Step 2:** chạy → FAIL
- [ ] **Step 3:** sửa code. Khóa chống trùng = `(rule.id, data.srcip or agent.id)`. `Suppressor` xóa khóa quá hạn mỗi lần gọi để không phình bộ nhớ.
- [ ] **Step 4:** chạy test → PASS. Chạy `python tools/wazuh_noise.py --normal`, ghi top 20 rule ồn vào mục *Kết quả P0/P1*. Đạt khi ≤ 1 alert / 100 event bình thường. Không đạt thì đưa các rule ồn vào Task 12.
- [ ] **Step 5:** commit `detection/wazuh: chuyển mọi cảnh báo level>=7, chạy bóng theo nhóm, chống trùng`

### Task 3: Ca test dạng log gốc + bộ chạy qua Wazuh + job CI

**Files:**
- Create: `wazuh/manager/tests/cases/` (một file YAML mỗi file rule), `tools/wazuh_rule_test.py`, `server/tests/test_wazuh_rule_test.py`
- Modify: `.github/workflows/ci.yml` (job `wazuh-rules`: chạy `wazuh/wazuh-manager:4.14.8` mount repo, rồi `python tools/wazuh_rule_test.py --url https://localhost:55000`)

Định dạng ca test:

```yaml
- rule: 104001            # id phải báo (hoặc `none: [104001]` cho ca âm)
  legacy: WEB-001
  log_format: apache      # syslog | json | apache | eventchannel
  location: /var/log/apache2/access.log
  events:                 # nhiều dòng = cùng session logtest (rule đếm ngưỡng)
    - '203.0.113.5 - - [31/Oct/2026:10:00:00 +0700] "GET /p.php?id=1%27%20or%201=1-- HTTP/1.1" 200 12 "-" "curl/8"'
```

**Interfaces:**
- Consumes: `WazuhApi.logtest` (Task 1).
- Produces:
  - `wazuh_rule_test.run(cases: list[dict], api) -> list[Failure]`. `Failure = (file, index, expected, got_ids)`
  - Ca `eventchannel` chạy bằng chế độ bơm hàng đợi của `tools/wazuh_coverage.run_wazuh`, nếu S3 xác nhận logtest không giải mã được.

- [ ] **Step 1:** test hỏng với API giả: ca dương thiếu id → 1 Failure; ca âm có id → 1 Failure; 5 dòng cùng session → rule `frequency=5` báo ở dòng 5.
- [ ] **Step 2:** chạy → FAIL
- [ ] **Step 3:** viết bộ chạy. Thoát mã 1 khi có Failure, in bảng `file:index expected got`.
- [ ] **Step 4:** chạy test → PASS. Chạy thật trên stack với ca của 100100 → 0 Failure. Push nhánh, job `wazuh-rules` xanh.
- [ ] **Step 5:** commit `tests: ca test log gốc chạy qua wazuh logtest + job CI wazuh-rules`

### Task 4: Lint rule XML

**Files:**
- Create: `tools/wazuh_rule_lint.py`, `server/tests/test_wazuh_rule_lint.py`
- Modify: `.github/workflows/ci.yml` (job `wazuh-rules` chạy lint trước test)

**Interfaces:**
- Consumes: `wazuh_rules.parse`, `wazuh_rules.ID_RANGES`.
- Produces: `wazuh_rule_lint.check(files: dict[str, str], cases: list[dict]) -> list[str]` (mỗi lỗi một dòng).

- [ ] **Step 1:** test hỏng cho từng luật:
  - id ngoài dải của file
  - id trùng giữa hai file
  - `overwrite="yes"` ngoài `0190-tuning.xml`
  - id < 100000 không có `overwrite`
  - thiếu mã ở đầu `description`
  - thiếu `<mitre>` (trừ file tuning)
  - thiếu nhóm `siem`
  - rule riêng không có ít nhất 1 ca dương + 1 ca âm
  - regex lồng lượng từ (tái dùng `detection.rules.regex_risk`)
  - rule level 0 không có điều kiện trường ngoài `if_sid`
- [ ] **Step 2–4:** chạy FAIL → viết → PASS. Chạy trên `wazuh/manager/rules/` → 0 lỗi.
- [ ] **Step 5:** commit `tools: lint rule XML của Wazuh`

---

## P2 — Chuyển rule (03–06/11)

### Task 5: Đối chiếu 41 rule cũ với ruleset gốc

**Files:**
- Create: `tools/cases_to_raw.py` (một lần: ca ECS trong `server/rules/cases/*.yml` → log gốc theo nguồn), `wazuh/manager/tests/legacy_map.yml`, `wazuh/manager/tests/cases/legacy-*.yml`
- Modify: `RULES.md` (bảng đối chiếu)

Cách đổi ca ECS sang log gốc:
- Apache access line, sshd syslog, filterlog CSV, `eve.json`: dựng chuỗi trực tiếp từ trường ECS.
- Sysmon / auditd: dùng `wazuh_coverage.sysmon_message` / `audit_message`.
- Tiến trình Linux: dòng `siem-proc: pid=… cmd=…` (định dạng `_SIEM_PROC` trong `pipeline/normalize.py`).

**Interfaces:**
- Produces: `legacy_map.yml`: `{WEB-001: {wazuh: [31103, 31152], decision: builtin|convert|approx, note: str}}`. Task 6–11 đọc trường `decision`.

- [ ] **Step 1:** `python tools/cases_to_raw.py` sinh ca gốc. Chạy `tools/wazuh_rule_test.py --report legacy` trên ruleset gốc (chưa có rule riêng): mỗi ca dương thì những id nào báo, mỗi ca âm có id nào báo không.
- [ ] **Step 2:** ghi `decision`:
  - `builtin`: ruleset gốc báo đủ mọi ca dương (cho phép nhiều id) và không báo ca âm.
  - `approx`: có rule gốc gần đúng, cần chỉnh ngưỡng/level ở Task 12.
  - `convert`: còn lại.
- [ ] **Step 3:** kiểm `legacy_map.yml` có đủ 41 mã. Ca nào không đổi được sang log gốc thì ghi rõ lý do trong `note` (ví dụ TI-001 phụ thuộc MISP).
- [ ] **Step 4:** commit `rules: đối chiếu 41 rule YAML với ruleset Wazuh 4.14.8`

### Task 6–11: Rule XML theo lĩnh vực, ở chế độ bóng

Mỗi task một file, cùng một quy trình. Chỉ chuyển các mã có `decision: convert`, theo `legacy_map.yml`.

| Task | File | Mã cũ được xét | Điểm cần chú ý |
|---|---|---|---|
| 6 | `0101-auth.xml` | AUTH-001..006 | AUTH-002 có thể là rule gốc 40112 (`if_matched_group` + `same_source_ip`). AUTH-003 theo kết quả S4. |
| 7 | `0102-linux.xml` + `decoders/0102-siem-procs.xml` | LNX-001..006 | Decoder cho dòng `siem-proc:` (ra trường `pid`, `ppid`, `uid`, `name`, `parent`, `exe`, `cmd`). Chỉ áp cho `location` khớp `siem-procs`, giống `_SIEM_PROC_LOC`, để chặn telemetry giả. |
| 8 | `0103-network.xml` | NET-001..005 | filterlog qua decoder `pf`. NET-003 dùng `<srcip negate="yes">` dải nội bộ. NET-004 là rule con của nhóm Suricata, lọc `alert.severity`. NET-001, NET-005 theo S4. |
| 9 | `0104-web.xml` | WEB-001..009 | Regex bắt cả dạng mã hóa (S5). Ca test mỗi rule có ≥ 1 dạng thô + ≥ 1 dạng `%xx`. |
| 10 | `0105-windows.xml` | WIN-001..013 | Trường `win.eventdata.*` (camelCase). WIN-005 giữ ngoại lệ lớp vỏ Ansible/WinRM. WIN-013 giữ giới hạn schtasks. |
| 11 | `0106-fim.xml`, `0107-ti.xml` + `tools/misp_to_cdb.py` | FIM-001, TI-001 | FIM là con của 550/554 lọc theo đường dẫn. TI: SOAR xuất IOC MISP ra `etc/lists/malicious-ioc/malicious-ip` mỗi chu kỳ đồng bộ, rồi reload. |

Mỗi rule mới có nhóm `siem,<lĩnh vực>,shadow,legacy_<mã>,` và `<info type="text">shadow_since=<ngày></info>`.

- [ ] **Step 1:** viết ca dương/âm vào `wazuh/manager/tests/cases/<file>.yml`. Lấy từ ca `legacy-*.yml` của Task 5, cộng ca mã hóa (web) hoặc ca biên.
- [ ] **Step 2:** `python tools/wazuh_rule_test.py wazuh/manager/tests/cases/<file>.yml` → FAIL (chưa có rule)
- [ ] **Step 3:** viết rule XML
- [ ] **Step 4:** test → PASS, lint → 0 lỗi. Chạy `tools/wazuh_noise.py --normal --rules <file>` → 0 alert trên tập bình thường.
- [ ] **Step 5:** commit `rules: <lĩnh vực> dạng XML (chạy bóng)`

### Task 12: `0190-tuning.xml`

**Files:** Create `wazuh/manager/rules/0190-tuning.xml`, `wazuh/manager/tests/cases/tuning.yml`

- Sửa 2 lỗi đo ngày 06/10:
  - 92041: regex khớp mọi `reg add /d`.
  - 92021: thiếu `\b`, khớp nhầm `-Uri`.
- Thêm các rule `approx` của Task 5 và các rule ồn của Task 2.

- [ ] **Step 1:** ca âm `reg add HKCU\Software\X /d 1` → không báo 92041; ca dương của 92041 lấy từ dataset vẫn báo.
- [ ] **Step 2–4:** FAIL → viết `overwrite="yes"` → PASS. `tools/wazuh_noise.py --normal` đạt ngưỡng của Task 2.
- [ ] **Step 5:** commit `rules: chỉnh rule gốc (92041, 92021, rule ồn)`

### Task 13: Báo cáo chạy song song

**Files:** Create `tools/parity_report.py`, `server/tests/test_parity_report.py`

**Interfaces:**
- Consumes: alert trong `siem-alerts` (YAML có `rule.id` = mã cũ; XML có `rule.legacy_id`).
- Produces: `parity(alerts: list[dict], since: str) -> dict[legacy_id, {yaml: int, xml: int, only_yaml: list[event.id], only_xml: list[event.id]}]`, in bảng Markdown.

- [ ] **Step 1:** test với 3 alert giả: 1 cặp khớp theo `event.id`, 1 chỉ có ở YAML, 1 chỉ có ở XML → đếm đúng.
- [ ] **Step 2–4:** FAIL → viết → PASS. Chạy trên stack sau E2E + 24 giờ log lab → lưu `build/parity.md`.
- [ ] **Step 5:** commit `tools: báo cáo đối chiếu alert YAML với XML`

---

## P3 — Các phần phụ thuộc rule (06–08/11)

### Task 14: Thư viện rule đọc từ Wazuh

**Files:** Modify `server/siem/rules_catalog.py` (thêm `wazuh_rule_docs(api, alert_stats) -> list[dict]`, giữ `rule_docs` tới Task 23), `server/siem/manager/api.py` (vòng `catalog_loop` gọi thêm); Test `server/tests/test_rules_catalog.py`

- Lấy toàn bộ rule qua `GET /rules` (phân trang 500, khoảng 4.5k rule). Mỗi rule thành một doc `siem-rules`: id `WZH-<id>`, level → severity, nhóm, MITRE, file, `shadow`, `legacy_id`, số alert 7 ngày.
- Rule có trạng thái `disabled` vẫn liệt kê, đánh dấu tắt.

- [ ] **Step 1:** test với trang API giả gồm 2 trang (rule gốc, rule riêng có `shadow`) → đủ doc, `severity`, `shadow`, `legacy_id` đúng.
- [ ] **Step 2–4:** FAIL → viết → PASS. E2E mục 5 (Thư viện rule) đổi số kỳ vọng thành tổng rule từ API.
- [ ] **Step 5:** commit `rules_catalog: thư viện rule lấy từ Wazuh API`

### Task 15: SOAR chọn playbook theo nhóm Wazuh

**Files:** Modify `server/siem/soar/engine.py` (điều kiện `when.groups`), `server/siem/soar/cases.py` (bước chọn case playbook: mã → kỹ thuật → **nhóm** → tag → PB-00), `server/config/playbooks.yml`, `server/config/case_playbooks.yml`; Test `server/tests/test_pipeline.py`

- Map hiện tại → mới:
  - `WEB-*` (chặn IP) → `groups: [sql_injection, web_scan, attack]` + `rule_ids: [WZH-1040*]`
  - `AUTH-001/003, WIN-001` → `groups: [authentication_failures]` + `min_severity: high`
  - `LNX-00x` / `WIN-00x` (kill) → `rule_ids` của rule XML tương ứng (từ `legacy_map.yml`)
- Giữ mục cũ tới Task 18 để playbook vẫn chạy với rule YAML.

- [ ] **Step 1:** test: alert Wazuh nhóm `sql_injection` level 10 → playbook chặn IP. Alert `shadow=true` → không playbook nào.
- [ ] **Step 2–4:** FAIL → viết → PASS.
- [ ] **Step 5:** commit `soar: chọn playbook theo nhóm rule Wazuh`

### Task 16: Ngoại lệ dạng rule level 0

**Files:** Modify `server/siem/manager/api.py` (luồng duyệt ngoại lệ ghi XML qua `wazuh_rules.write_dynamic("exceptions.xml", …)`); Create `server/siem/wazuh_fields.py` (ECS → trường Wazuh: `source.ip→srcip`, `user.name→dstuser`, `url.original→url`, `process.command_line→win.eventdata.commandLine` / `cmd` cho siem-procs, `file.path→file`); Test `server/tests/test_api.py`, `server/tests/test_wazuh_fields.py`

**Interfaces:**
- Produces:
  - `wazuh_fields.to_wazuh(ecs_field: str, decoder: str | None) -> str` (không có ánh xạ thì `KeyError`)
  - `exception_rule(parent_id: int, conditions: list[dict], new_id: int, reason: str) -> str` (XML 1 rule)

- [ ] **Step 1:** test:
  - ngoại lệ `{rule: WZH-31103, source.ip: 10.10.40.50}` → rule 110000 level 0, `<if_sid>31103</if_sid><srcip>10.10.40.50</srcip>`
  - ngoại lệ chỉ có rule cha, không có điều kiện → API trả 400
  - XML hỏng → giữ file cũ (Review Focus 2, 4)
- [ ] **Step 2–4:** FAIL → viết → PASS. Chạy thật: thêm ngoại lệ cho IP host trên WEB SQLi → E2E SQLi không còn chặn IP host, gỡ ngoại lệ → chặn lại.
- [ ] **Step 5:** commit `manager: ngoại lệ thành rule Wazuh level 0`

### Task 17: KPI độ phủ ATT&CK từ thư viện rule

**Files:** Modify `server/siem/manager/api.py:compute_kpi`, `server/siem/manager/kpi.py` (độ phủ kỹ thuật ưu tiên tính từ doc `siem-rules` nguồn Wazuh, không tính rule `shadow`), `tools/rule_lint.py --layer` → chuyển sang `tools/wazuh_rule_lint.py --layer` (ATT&CK Navigator layer từ rule đang bật); Test `server/tests/test_kpi.py`

- [ ] **Step 1:** test: 3 doc rule (T1190 bật, T1486 bóng, T1110 bật) → kỹ thuật được phủ = {T1190, T1110}.
- [ ] **Step 2–4:** FAIL → viết → PASS.
- [ ] **Step 5:** commit `kpi: độ phủ tính từ rule Wazuh đang bật`

### Task 18: Cổng chuyển (08/11)

Điều kiện, đo bằng `build/parity.md` (Task 13) + CI + E2E:
- (a) mọi mã `convert` có `only_yaml` = 0 trên ca test và 24 giờ log lab
- (b) `tools/wazuh_noise.py --normal` đạt ngưỡng Task 2
- (c) E2E 44/44 với SOAR theo playbook mới

**Đạt:**
- [ ] bỏ nhóm `shadow` ở các file 0101–0107 (trừ rule có `shadow_since` < 7 ngày, giữ đúng tiêu chí chạy bóng của SOC-OPERATIONS mục 4)
- [ ] `RULE_ENGINE_ENABLED=false` (biến mới trong `settings.py`, analyzer không chạy engine của `detection/rules.py`) + test `test_engine_disabled_no_yaml_alerts`
- [ ] xóa mục playbook theo mã YAML
- [ ] E2E 44/44, commit `chuyển phát hiện sang Wazuh: tắt engine YAML`

**Không đạt:** giữ YAML bật + XML bóng cho demo 10/11. Ghi mã chưa đạt vào ROADMAP.md, chuyển sau 16/11.

---

## P4 — Sau v1.0 (từ 17/11)

Mỗi task dưới đây viết kế hoạch chi tiết riêng khi tới lượt. Chúng phụ thuộc kết quả P2 (định dạng ca test, `wazuh_fields`).

- **Task 19 — Sigma → XML:** `server/siem/ai/wazuh_xml.py: emit(sigma_rule: dict, rule_id: int) -> str`, dùng cây điều kiện của `sigma.py` và `wazuh_fields`. Mỗi vế OR của DNF thành một rule con cùng mã. `not` → `negate="yes"`. Không ánh xạ được trường → `SigmaError`. Test: 20 rule SigmaHQ process_creation/webserver đã biên dịch được (theo AI-README §9.5) → XML qua lint + logtest khớp ca của chính rule đó.
- **Task 20 — Kiểm định AI trên Wazuh:** `ai/validate.py` thay `replay` bằng bơm tập train/test/bình thường vào manager tạm (cách `tools/wazuh_coverage.py`), giữ các ngưỡng recall/báo nhầm hiện có. Tăng `GENERATOR_REVISION`.
- **Task 21 — Triển khai / chạy bóng / gỡ rule AI dạng XML:** `ai/deploy.py` `approve`/`promote`/`rollback` ghi `rules-dynamic/ai.xml` qua `write_dynamic`, dải 109000–109999. `shadow_stats` giữ nguyên (đếm alert theo `rule.id`).
- **Task 22 — SigmaHQ → XML:** `tools/sigmahq_import.py` (của phiên SigmaHQ, nhánh `feature/coverage-batch1`) xuất `0108-sigmahq.xml` qua `emit`. Lô 1 (30 rule) chạy bóng.
- **Task 23 — Xóa engine YAML:** engine trong `server/siem/detection/rules.py`, `detection/lint.py`, `detection/ruletest.py` + `server/rules/*.yml` + `server/rules/cases/` + `tools/rule_lint.py` + `covered_by`, sửa test liên quan.
- **Task 24 — Tài liệu:**
  - RULES.md viết lại (cơ chế XML, dải id, quy trình detection-as-code, bảng `legacy_map`)
  - README §3
  - SOC-OPERATIONS mục 4 (chạy bóng bằng nhóm)
  - AI-README (đầu ra XML)
  - DEPLOY-VM (mount rule)

## Kết quả P0 / P1

Task 0 đo ngày 31/10/2026 trên project `wzhdev` (bản chép volume Wazuh thật, manager 4.14.8, agent demo-web 4.14.7). Chạy trên mạng riêng `wzhdev-soc`: mạng `soc` của `docker-compose.yml` có tên cố định `soc-lab`, trùng mạng của stack thật. API gọi bằng một user admin tạm tạo trong container wzhdev, đã xóa sau khi đo. Phần dựng thử để ngoài repo.

### S1 — reload: đạt

- `PUT /manager/analysisd/reload` cần `manager:read` + `manager:restart` (`GET /security/actions?endpoint=PUT /manager/analysisd/reload`), trả lời trong 0,6–1 giây. `manager:restart` cũng mở `PUT /manager/restart`, không có quyền hẹp hơn.
- Ghi 10.000 dòng syslog có số thứ tự vào `/var/ossec/logs/active-responses.log` của demo-web (~330 dòng/giây). Reload ở giây 6 (thêm 109030), 14 (thêm 109031, con của 109030), 22 (bỏ 109031):
  ```
  analysisd: processed 10017, dropped 0; agentd: msg_buffer 0
  archives.json: 10000 dòng, 10000 seq khác nhau, thiếu 0, trùng 0
  theo seq: 1–1767 chưa có rule | 1768–4422 → 109030 | 4423–7033 → 109031 | 7034–10000 → 109030
  ```
  Rule có hiệu lực ngay sau reload (alert đầu 0,7 giây sau lời gọi). Không có đoạn hở giữa hai ruleset.
- Reload với file hỏng (mỗi file có thêm 1 rule tốt). HTTP luôn 200:

| Kiểu hỏng | Phản hồi | Ruleset sau đó |
|---|---|---|
| XML không đóng thẻ, thẻ lạ `<foo>`, PCRE2 sai | `error: 1`, `failed_items[0].error.code` 1914 "Failed to reload ruleset: …" | giữ nguyên ruleset cũ, rule tốt cùng file không nạp |
| trùng id | `error: 0`, `affected_items[0].msg` "(7612): Rule ID '109010' is duplicated…" | nạp, giữ bản đầu |
| `if_sid` không tồn tại | `error: 0`, msg "(7619): Empty 'if_sid' value. Rule '109022' will be ignored." | nạp, bỏ rule đó |
| file không đọc được (600) | `error: 0`, msg "(1103): Could not open file … Permission denied" | nạp, bỏ cả file |

- Reload hỏng giữa luồng 5.000 dòng: đủ 5.000, dropped 0, rule cũ báo liên tục. Reload hỏng không ghi gì vào `ossec.log`, chỉ phản hồi API cho biết.
- File hỏng còn trên đĩa thì lần khởi động sau manager không lên: `CRITICAL: (1220): Error loading the rules`, `wazuh-control start` dừng, remoted và apid cũng không chạy. `wazuh-analysisd -t` trả mã 1 khi lỗi, 0 khi sạch.
- Hệ quả:
  - Task 1 `WazuhApi.reload()`: xét `error` và `failed_items`, không xét HTTP status. `msg` khác "Ruleset reload request sent successfully." là cảnh báo; `write_dynamic` coi như lỗi (khôi phục + reload lại theo Ruling R1), vì Wazuh âm thầm bỏ rule trùng id / sai `if_sid`.
  - Task 1: khôi phục file cũ là bắt buộc. Đề nghị thêm vào `10-siem-setup.sh`: chạy `wazuh-analysisd -t` trước khi start; lỗi thì chuyển file của `rules-dynamic` sang thư mục cách ly và ghi log, để một file AI/ngoại lệ hỏng không làm sập manager.

### S2 — thư mục rule: đạt trên Windows, một phần trên Linux (mô phỏng quyền, chưa chạy máy Linux)

- Dựng: `rules:/var/ossec/etc/rules:ro`, `decoders:/var/ossec/etc/decoders:ro` (chỉ có `.gitkeep`), volume `wazuh_dynamic_rules:/var/ossec/etc/rules-dynamic`, ossec.conf thêm `<rule_dir>etc/rules-dynamic</rule_dir>`, bỏ mount `local_rules.xml`. Manager lên bình thường; `.gitkeep` không gây lỗi. analysisd chạy bằng user `wazuh` (uid/gid 999), cả lúc reload.
- Bind mount từ Windows: file trong container là `root:root 0777`. File thêm từ host khi container đang chạy có hiệu lực sau reload. File CRLF nạp bình thường.
- Linux (mô phỏng trong volume): file uid 1000 mode 644 → `wazuh` đọc được; mode 600 → "(1103) Permission denied", file bị bỏ. Checkout git với umask 022 (644/755) là đủ. Chưa thử SELinux (`:z`).
- Volume động mới tạo là `root:root 0755`: uid 10001 (image `siem-xdr-server`) ghi → `Permission denied`. Sau `chown 10001:wazuh /var/ossec/etc/rules-dynamic` (root, trong wazuh-manager): uid 10001 ghi được, file ra `10001:999 0644`, `wazuh` đọc được, reload nạp rule. Quyền giữ qua restart. (Group `siem` của image server tình cờ cũng là gid 999.)
- analysisd chỉ nạp file đuôi `.xml`, kể cả file ẩn `.ai.xml`; `ai.xml.tmp`, `ai.tmp` bị bỏ qua.
- `GET /rules`, `GET /rules/files` KHÔNG thấy rule trong `etc/rules-dynamic` (admin, đã reload): RBAC mở rộng `rule:file:*` bằng `expand_rules()` chỉ duyệt `ruleset/rules` và `etc/rules` (`wazuh/rbac/utils.py`). File thêm vào `etc/rules` thì thấy.
- Hệ quả:
  - Task 1: chown thư mục động trong `10-siem-setup.sh` mỗi lần khởi động (`install -d -o 10001 -g wazuh -m 0755 /var/ossec/etc/rules-dynamic`), không làm ở `install.sh` (volume có tên, không phải thư mục trên host).
  - Task 1: bỏ hẳn mount `local_rules.xml`. Image chép `/wazuh-config-mount/*` vào `/var/ossec` lúc khởi động, chép vào `etc/rules` chỉ đọc sẽ lỗi (đọc `0-wazuh-init`, chưa thử).
  - Task 1 `write_dynamic`: file tạm không được có đuôi `.xml` (vd `ai.xml.tmp`), cùng thư mục để `rename` nguyên tử.
  - Task 14: `GET /rules` không có `ai.xml`, `exceptions.xml`. Thư viện rule đọc thêm file trong `DYNAMIC_DIR` bằng `wazuh_rules.parse` (manager đã mount volume này).
  - Task 24 (DEPLOY-VM): trên Linux, `wazuh/manager/rules` phải đọc được với others (644/755).

### S3 — API logtest: đạt với syslog / json / apache, không đạt với eventchannel

- `PUT /logtest` `{event, log_format, location, token}`, quyền `logtest:run`. Lần đầu trả `token`; gửi lại token thì giữ trạng thái. Rule `frequency="5" timeframe="60"` (`if_matched_sid`, json/apache thêm `same_srcip`), 11 dòng cùng token:
  ```
  syslog  1–4:109040  5:109041  6–9:109040  10:109041  11:109040
  json    5:109043, 10:109043      apache  5:109045, 10:109045
  không gửi token: 6 dòng đều 109040 (mỗi dòng một session mới)
  ```
  Báo đúng dòng thứ N, sau khi báo thì đếm lại (báo tiếp ở dòng 2N).
- Session đọc ruleset trên ĐĨA lúc tạo, không phụ thuộc analysisd đã reload chưa: rule vừa ghi đã báo trong logtest khi analysisd chính chưa có. File hỏng → `messages` có "ERROR … (7311): Failure to initializing session"; cảnh báo trùng id / `if_sid` cũng hiện trong `messages`.
- Giới hạn: API mặc định `access.max_request_per_minute: 300`, bộ thử S4 (gần 300 lời gọi trong khoảng 1 phút) bị HTTP 429. `rule_test.max_sessions` là 64 → xóa session sau mỗi ca (`DELETE /logtest/sessions/{token}`).
- Windows: gửi dạng agent `{"Message","Event":<XML>}` và dạng đã đổi `{"win":{…}}`, mỗi dạng với `log_format` eventchannel và json: cả 4 ra decoder `json`, không rule Windows nào báo. Decoder `windows_eventchannel` nằm trong mã analysisd (không có trong `ruleset/decoders`), logtest không gọi tới. Bơm vào hàng đợi (`queue/sockets/queue`, `f:EventChannel:` + `wazuh_coverage.sysmon_message`) vẫn chạy trên 4.14.8: decoder `windows_eventchannel`, rule 92032 báo.
- Hệ quả:
  - Task 3: ca `eventchannel` chạy bằng bơm hàng đợi (nhánh dự phòng đã ghi trong plan), các định dạng khác qua logtest. Bộ chạy dùng token cho ca nhiều dòng, xóa session sau mỗi ca, chờ rồi thử lại khi gặp 429. Job CI mount `api.yaml` riêng nâng `access.max_request_per_minute`.
  - Logtest chỉ chứng minh file trên đĩa đúng, không chứng minh analysisd đang chạy đã nạp. Nạp thật kiểm bằng reload (S1).
  - Ruling R1: có thể dùng logtest làm bước kiểm trước reload (báo cùng lỗi như reload). Không bắt buộc, vì reload hỏng đã giữ ruleset cũ.

### S4 — đếm giá trị khác nhau: một phần

- analysisd 4.14.8 có `different_srcip/dstip/srcport/dstport/srcuser/user/url/id/location/protocol/action/status/system_name/data/extra_data/srcgeoip/dstgeoip/field` và `not_same_field` (chuỗi trong `bin/wazuh-analysisd`). Ruleset gốc chỉ dùng `different_url` (5 chỗ).
- Thử qua logtest, rule `frequency=N` + `if_matched_sid` + `same_srcip` / `same_field`:

| Rule cũ | Thẻ, N | N giá trị khác nhau | 2 giá trị xen kẽ | 1 giá trị |
|---|---|---|---|---|
| NET-001 | `different_dstport`, 20 | báo ở dòng 20 | dòng 38, 41 (60 dòng) | không báo (40 dòng) |
| NET-005 | `different_dstip`, 10 | dòng 10 | dòng 18, 21 (30 dòng) | — |
| AUTH-003 | `different_srcuser`, 5 (sshd thật, con của 5710) | dòng 5 | dòng 11 (5712, frequency 8, cũng báo trong lượt) | — |
| LNX-005 | `different_field` / `not_same_field` trên `pname`, 4 | dòng 4 | dòng 6, 9 | không báo |
| — | `different_url`, 5 (apache) | dòng 5 | dòng 8, 11 | không báo |

  Thêm: 20 cổng khác nhau nhưng từ 2 nguồn xen kẽ → không báo. Cổng 1..19, rồi 5, rồi 20 → báo ở dòng 21.
- Nghĩa là Wazuh đếm "N−1 event trước (trong timeframe) có giá trị khác giá trị của event hiện tại", không đếm số giá trị khác nhau. Giá trị phân tán (quét cổng, spraying) cho kết quả như rule cũ; vài giá trị lặp lại thì báo sau khoảng 2N event. `not_same_field` chạy y như `different_field`.
- Bẫy gặp khi thử:
  - `<field name="x">proc</field>` là regex tìm chuỗi con, khớp cả `proc2`. Phải neo `^proc$`.
  - `frequency` + `if_matched_group` chưa tái hiện được trong đợt thử này: không thấy báo, cả logtest lẫn hàng đợi thật (thêm `<if_group>` cũng không). Rule gốc 40111 (`frequency=12`, `if_matched_group authentication_failed`) cũng không báo, nhưng chỉ thử với 13 lần sai mật khẩu sshd từ một IP. `if_matched_sid` thì báo. Chưa rõ nguyên nhân (chưa tìm ra trong mã analysisd); có thể là một điều kiện còn thiếu ở ca thử, chưa kết luận Wazuh không hỗ trợ.
- Hệ quả:
  - Task 6, 7, 8: NET-001, NET-005, AUTH-003, LNX-005 viết bằng `different_*`, không cần xấp xỉ "≥ N event cùng nguồn". RULES.md ghi giới hạn: ít giá trị lặp lại vẫn báo sau ~2N event. Mỗi rule thêm ca âm "2 giá trị xen kẽ, < 2N−2 dòng".
  - Task 4: đề nghị lint cảnh báo `<field>` có giá trị là một từ mà không neo `^…$`, và `frequency` dựa trên `if_matched_group` (mức WARNING, không phải lỗi, vì chưa chứng minh được là hỏng). Rule nào dùng cấu trúc này phải có ca dương tính đạt trong harness mới được nhận.
  - Task 5, 6: AUTH-002 / 40112 (`if_group` + `if_matched_group`, không `frequency`) chưa thử ở đây; harness phải chứng minh rule gốc có báo.

### S5 — giải mã URL: Wazuh không giải mã (đúng dự kiến)

- Logtest `log_format apache`, decoder `web-accesslog`: trường `url` giữ nguyên chuỗi trong log ở mọi dạng. Rule gốc báo:

| Dạng (status 200) | Rule gốc |
|---|---|
| `id=1'%20or%20'1'='1` (dấu nháy thô) | 31100 level 0 — không phát hiện |
| `%27` | 31164 SQL injection attempt (6) |
| `%2527`, `'+or+1=1--`, `%u0027` | 31100 level 0 — không phát hiện |
| `UNION SELECT` với `%20` hoặc `+` | 31106 (6) |
| `%55NION%20%53ELECT` | 31100 level 0 — không phát hiện |
| `<script>` và `%3Cscript%3E`; `../` và `%2e%2e%2f` | 31106 (6) cả hai dạng |

- Hệ quả:
  - Task 9 giữ như plan: regex bắt cả dạng mã hóa, ca test có cả dạng thô lẫn `%xx`. Ca test nên có thêm `%2527`, `+`, `%u0027` và từ khóa mã hóa từng chữ (`%55NION`): rule gốc bỏ sót các dạng này.
  - Status 200 thì rule gốc ra 31106 (con của rule tấn công) thay cho rule tấn công cụ thể (31164 thì vẫn ra 31164); Task 5 ghi cả hai id vào `legacy_map.yml`.

### Task 2 — rule ồn

Lệnh: `python tools/wazuh_noise.py --data D:/GSANM/BTL/siem-xdr/datasets/processed` (image `wazuh/wazuh-manager:4.14.8`, `ossec.conf` + `rules/` của nhánh, `--network none`, container `wazuh-noise` xóa sau khi chạy).

Tập bình thường: web CSIC 2010 (36.000), Windows: lệnh bình thường tự soạn `baseline-endpoint` (153) + `splunk-background` (112, `realdata_normal`) + `scenario-background` (406, lệnh nền lặp ở nhiều kỹ thuật trong `realdata_scenario`), Linux: `baseline-endpoint` (152) + `scenario-background` (48). Windows dựng thành Sysmon EventID 1, Linux thành auditd EXECVE như event tấn công. analysisd xử lý 36.872, bỏ 0.

| Lĩnh vực / nguồn | Event | Alert ≥ 7 | Alert / 100 event | Cổng ≤ 1 |
|---|---|---|---|---|
| **Tổng** | 36.871 | 9 | 0,024 | đạt |
| web (csic2010) | 36.000 | 0 | 0 | đạt |
| **Windows** | 671 | 9 | **1,341** | **KHÔNG ĐẠT** |
| - windows/baseline-endpoint | 153 | 5 | 3,268 | không đạt |
| - windows/scenario-background | 406 | 4 | 0,985 | đạt (sát ngưỡng) |
| - windows/splunk-background | 112 | 0 | 0 | đạt |
| Linux | 200 | 0 | 0 | đạt |

Mỗi event tính 1 alert (rule level cao nhất khớp). Chỉ có 7 rule (không đủ 20), tất cả ở Windows:

| Rule | Level | Mô tả | Số alert |
|---|---|---|---|
| 92041 | 10 | Value added to registry key has Base64-like pattern | 3 |
| 92043 | 10 | Netsh used to add firewall rule | 1 |
| 92074 | 12 | curl.exe launched with commands to create a binary file | 1 |
| 92057 | 12 | Powershell.exe spawned a powershell process which executed a base64 encoded command | 1 |
| 61627 | 12 | Sysmon - Suspicious Process - lsass.exe is a Parent Image | 1 |
| 61640 | 12 | Sysmon - Suspicious Process - explorer.exe | 1 |
| 61618 | 12 | Sysmon - Suspicious Process - svchost.exe | 1 |

- Kết luận: web và Linux sạch; Windows **không đạt** cổng (1,34 / 100 event) nên 7 rule trên đưa vào Task 12 (chưa chỉnh gì). 92041 là regex quá rộng đã ghi ở `GENERIC` của `wazuh_coverage.py`.
- Giới hạn: tập Windows chỉ có Sysmon EventID 1 (671 event, nhỏ), chưa có đăng nhập / dịch vụ / registry bình thường. 3 rule `Suspicious Process` (61618/61627/61640) có thể do cách dựng event (ParentImage lấy từ dữ liệu ghi thật, các trường khác để trống) nên nên kiểm lại ở Task 12 trước khi sửa.
- Sửa kèm: `tools/wazuh_coverage.py` `load_items` lấy web normal chỉ từ `csic2010` (assert độ dài cũ vỡ vì dataset có thêm normal endpoint) và có tham số `extra_normal` (chỉ `wazuh_noise.py` dùng; báo cáo độ phủ giữ số liệu cũ).
