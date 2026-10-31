"""Chạy ca test LOG GỐC của rule Wazuh qua Wazuh thật (detection-as-code, SOC-OPERATIONS.md mục 4).

    python tools/wazuh_rule_test.py --url https://localhost:55000 [--insecure] [đường dẫn file/thư mục ca test]

Mặc định đọc wazuh/manager/tests/cases/*.yml, đăng nhập user `siem-rules` (secrets/wazuh_rules_api_password).
Thoát mã 1 khi có ca sai, mã 2 khi bơm hàng đợi hỏng (InjectionError) và in bảng `file:index  mong đợi  thực tế`.

Định dạng một ca (mỗi file YAML là một danh sách ca):

    - rule: 104001            # id phải báo; hoặc `none: [104001]` cho ca ÂM (id không được báo)
      legacy: WEB-001         # (tùy chọn) mã rule cũ, để tra
      log_format: apache      # syslog | json | apache | eventchannel | syscheck
      location: /var/log/apache2/access.log
      events:                 # NHIỀU DÒNG = CÙNG MỘT session logtest (rule đếm ngưỡng frequency/timeframe)
        - '203.0.113.5 - - [31/Oct/2026:10:00:00 +0700] "GET /p.php?id=1%27 HTTP/1.1" 200 12 "-" "curl/8"'

Chạy thế nào:
- syslog / json / apache: PUT /logtest, giữ `token` qua các dòng của ca, xóa session sau mỗi ca. Kết quả = mọi rule
  báo trong ca (kể cả rule trung gian). Gặp HTTP 429 thì chờ rồi thử lại.
- eventchannel / syscheck: logtest KHÔNG giải mã được (eventchannel ra decoder json; syscheck là message nội bộ của
  syscheckd) -> bơm thẳng vào hàng đợi analysisd của một wazuh-manager tạm (--network none, rule của nhánh này), qua
  wazuh_coverage.run_wazuh. Bơm KHÔNG giữ thứ tự dòng, nên ca nhiều dòng loại này (ngưỡng) chỉ nên khẳng định rule
  đã báo ÍT NHẤT MỘT LẦN, đừng dựa vào dòng nào báo. Chỉ thấy rule có alert trong alerts.json (level >= log_alert_level
  của ossec.conf); logtest thì thấy cả rule level thấp.
    eventchannel: mỗi dòng là JSON agent gửi {"Message": ..., "Event": "<Event>...</Event>"}; bộ chạy đổi
                  EventRecordID thành số riêng của ca để ghép alert với ca (phần còn lại giữ nguyên).
    syscheck:     mỗi dòng là map {path: /var/www/html/a.php, type: added|modified}; bộ chạy thêm thuộc tính file
                  mẫu, và đặt inode riêng của ca để ghép alert.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
import time
from collections import namedtuple
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import yaml  # noqa: E402
from siem.soar.wazuh import WazuhError  # noqa: E402

Failure = namedtuple("Failure", "file index expected got_ids")
INJECT = {"eventchannel", "syscheck"}
CASES_DIR = ROOT / "wazuh/manager/tests/cases"
RETRIES, WAIT = 12, 10          # HTTP 429: API mặc định 300 lời gọi / phút


def load_cases(path: Path) -> list[dict]:
    files = sorted(path.glob("*.yml")) if path.is_dir() else [path]
    cases = []
    for f in files:
        for i, c in enumerate(yaml.safe_load(f.read_text(encoding="utf-8")) or []):
            cases.append({**c, "_file": f.name, "_index": i})
    return cases


def _retry(fn):
    for attempt in range(RETRIES):
        try:
            return fn()
        except WazuhError as e:
            if "HTTP 429" not in str(e) or attempt == RETRIES - 1:
                raise
            time.sleep(WAIT)


def fired(case: dict, api) -> set[int]:
    """Id các rule đã báo cho MỘT ca (mọi dòng trong một session logtest). Chỉ gọi API, không ghi gì khác."""
    if case["log_format"] in INJECT:
        return inject([case])[0]
    ids, token = set(), None
    try:
        for ev in case["events"]:
            res = _retry(lambda: api.logtest(ev, case["log_format"], case["location"], token))
            token = res.get("token") or token
            if (rid := ((res.get("output") or {}).get("rule") or {}).get("id")):
                ids.add(int(rid))
    finally:
        if token:
            try:
                _retry(lambda: api.request("DELETE", f"/logtest/sessions/{token}"))
            except WazuhError:
                pass                # session tự hết hạn; không để lỗi dọn dẹp che kết quả
    return ids


# ---------------------------------------------------------------- bơm hàng đợi (eventchannel, syscheck)
_FILE = {"type": "file", "size": 10, "perm": "rw-r--r--", "uid": "0", "gid": "0", "user_name": "root",
         "group_name": "root", "mtime": 1767225600, "hash_md5": "d41d8cd98f00b204e9800998ecf8427e",
         "hash_sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709", "checksum": "abc",
         "hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
_BASE = {"eventchannel": 5_000_000, "syscheck": 6_000_000}


def _message(fmt: str, ev, ident: int) -> str:
    if fmt == "eventchannel":
        text, n = re.subn(r"<EventRecordID>\d+</EventRecordID>", f"<EventRecordID>{ident}</EventRecordID>", ev)
        if not n:
            raise ValueError("ca eventchannel: Event thiếu <EventRecordID>")
        return "f:EventChannel:" + text
    data = {"path": ev["path"], "mode": "scheduled", "type": ev["type"], "timestamp": 1767225600,
            "attributes": {**_FILE, "inode": ident}}
    if ev["type"] == "modified":
        data["changed_attributes"] = ["size", "mtime"]
        data["old_attributes"] = {**data["attributes"], "size": 5}
    return "8:syscheck:" + json.dumps({"type": "event", "data": data})


def _alert_ident(fmt: str, alert: dict) -> int | None:
    if fmt == "eventchannel":
        v = (((alert.get("data") or {}).get("win") or {}).get("system") or {}).get("eventRecordID")
    else:
        v = (alert.get("syscheck") or {}).get("inode_after")
    return int(v) if v else None


CANARY_IDENT, CANARY_RULE = _BASE["syscheck"] + 999_000, 554     # file mới ngoài thư mục web: rule gốc 554 luôn báo


class InjectionError(RuntimeError):
    """Bơm hàng đợi hỏng (gửi thiếu event, hoặc event canary không ra alert): KHÔNG phải rule sai."""


def inject(cases: list[dict]) -> list[set[int]]:
    """Bơm mọi ca (eventchannel / syscheck) vào một manager tạm, trả tập id rule đã báo của từng ca (cùng thứ tự).
    Kèm một event canary phải ra alert 554 và so số event đã gửi, để bơm hỏng không bị đọc thành "rule không báo"."""
    import wazuh_coverage as cov
    import wazuh_noise as noise
    items, owner = [], {}
    for n, c in enumerate(cases):
        for line, ev in enumerate(c["events"]):
            ident = _BASE[c["log_format"]] + n * 1000 + line
            owner[(c["log_format"], ident // 1000)] = n
            items.append({"msg": _message(c["log_format"], ev, ident)})
    items.append({"msg": _message("syscheck", {"path": "/etc/canary-wazuh-rule-test", "type": "added"}, CANARY_IDENT)})
    saved, cov.CONTAINER = cov.CONTAINER, noise.NAME
    try:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                noise.start(Path(tmp))
                alerts = cov.run_wazuh(items)
            finally:
                subprocess.run(["docker", "rm", "-f", noise.NAME], env=cov.ENV, capture_output=True)
        sent = cov.LAST_SENT
    finally:
        cov.CONTAINER = saved
    if sent != len(items):
        raise InjectionError(f"chỉ gửi được {sent}/{len(items)} event vào hàng đợi analysisd")
    if not any(_alert_ident("syscheck", a) == CANARY_IDENT and int(a["rule"]["id"]) == CANARY_RULE for a in alerts):
        raise InjectionError(f"event canary không ra alert {CANARY_RULE}: analysisd bỏ event hoặc chưa xử lý xong")
    out = [set() for _ in cases]
    for a in alerts:
        for fmt, base in _BASE.items():
            ident = _alert_ident(fmt, a)
            if ident and ident >= base and (fmt, ident // 1000) in owner:
                out[owner[(fmt, ident // 1000)]].add(int(a["rule"]["id"]))
    return out


# ---------------------------------------------------------------- chạy cả bộ
def run(cases: list[dict], api) -> list[Failure]:
    got: dict[int, set[int]] = {}
    batch = [i for i, c in enumerate(cases) if c["log_format"] in INJECT]
    if batch:
        for i, ids in zip(batch, inject([cases[i] for i in batch])):
            got[i] = ids
    for i, c in enumerate(cases):
        if i not in got:
            got[i] = fired(c, api)
    fails = []
    for i, c in enumerate(cases):
        want, forbidden = ([c["rule"]], []) if "rule" in c else ([], c.get("none") or [])
        bad = [r for r in want if r not in got[i]] + [r for r in forbidden if r in got[i]]
        if bad or not (want or forbidden):
            expected = str(c["rule"]) if want else "none " + ",".join(map(str, forbidden)) if forbidden else "?"
            fails.append(Failure(c.get("_file", "?"), c.get("_index", i), expected, sorted(got[i])))
    return fails


# ---------------------------------------------------------------- đối chiếu rule YAML cũ với ruleset gốc (--report)
HIGH = 7                    # alert thật: level >= 7 (dưới đó rule không thành alert của SOC, chỉ là ứng viên chỉnh level)
PROJECT_MIN_ID = 100000     # rule của repo (100100/100101...): không phải rule gốc, không tính vào đối chiếu
LEGACY_DIR = ROOT / "wazuh/manager/tests/legacy"
LEGACY_MAP = ROOT / "wazuh/manager/tests/legacy_map.yml"


def rule_info(api, ids) -> dict[int, tuple[int, list[str]]]:
    """{id: (level, groups)} từ GET /rules, 100 id một lần."""
    ids, info = sorted(ids), {}
    for i in range(0, len(ids), 100):
        part = ",".join(map(str, ids[i:i + 100]))
        for r in _retry(lambda: api.request("GET", f"/rules?rule_ids={part}&limit=500")).get("data", {}).get("affected_items", []):
            info[int(r["id"])] = (int(r["level"]), list(r.get("groups") or []))
    return info


def decide(positives: list[set[int]], negatives: list[set[int]], info: dict, skipped: str = "") -> tuple[str, list[int], str]:
    """(decision, id rule gốc, ghi chú) cho một rule cũ. `builtin`: MỖI ca dương có ít nhất một rule gốc level >= 7 (không thuộc
    nhóm sca) và không ca âm nào báo rule gốc level >= 7. `approx`: còn lại nhưng có rule gốc báo trên ca dương (kể cả level < 7,
    ứng viên nâng level). `convert`: không rule gốc nào. Rule level 0 (rule cha gom nhóm) và id >= 100000 (rule của repo) bỏ qua."""
    lv = lambda i: info.get(i, (0, []))[0]                                            # noqa: E731
    stock = lambda ids: {i for i in ids if i < PROJECT_MIN_ID and lv(i) > 0 and "sca" not in info[i][1]}  # noqa: E731
    high = lambda ids: {i for i in stock(ids) if lv(i) >= HIGH}                       # noqa: E731
    pos_high, pos_all = [high(p) for p in positives], [stock(p) for p in positives]
    neg_hit = sorted(set().union(*[{i for i in stock(n) if lv(i) >= HIGH} for n in negatives]))
    ids = sorted(set().union(*pos_all))
    low = sorted(set(ids) - set().union(*pos_high))
    notes = []
    if skipped:
        notes.append(f"không dựng được log gốc: {skipped}")
    if positives:
        notes.append(f"{sum(map(bool, pos_high))}/{len(positives)} ca dương có rule gốc level>=7")
    if low:
        notes.append(f"level<7 (ứng viên nâng level): {low}")
    if neg_hit:
        notes.append(f"ca âm báo level>=7: {neg_hit}")
    if 31106 in ids:
        notes.append("status 200 chỉ ra 31106 (rule con chung) thay vì rule tấn công cụ thể: Wazuh không giải mã URL")
    if positives and all(pos_high) and not neg_hit:
        return "builtin", ids, "; ".join(notes)
    if ids:
        return "approx", ids, "; ".join(notes)
    return "convert", [], "; ".join(notes + ([] if positives else ["không có ca dương"]) + ([] if not positives or skipped else ["không rule gốc nào báo"]))


def legacy_codes() -> list[str]:
    """Mã của mọi rule YAML cũ (server/rules/*.yml), theo thứ tự file."""
    return [r["id"] for f in sorted((ROOT / "server/rules").glob("*.yml")) for r in yaml.safe_load(f.read_text(encoding="utf-8"))]


def report(cases: list[dict], api, skipped: dict[str, str], codes: list[str] | None = None) -> dict[str, dict]:
    """Chạy MỌI ca legacy (các ca eventchannel/syscheck gộp một lần `inject`) và trả {mã: {wazuh, decision, note}}."""
    codes = codes or legacy_codes()
    missing = [c for c in codes if c not in skipped and not any(x["legacy"] == c for x in cases)]
    if missing:
        raise ValueError(f"thiếu ca và lý do bỏ qua cho: {', '.join(missing)}")
    got: dict[int, set[int]] = {}
    batch = [i for i, c in enumerate(cases) if c["log_format"] in INJECT]
    if batch:
        for i, ids in zip(batch, inject([cases[i] for i in batch])):
            got[i] = ids
    for i, c in enumerate(cases):
        if i not in got:
            got[i] = fired(c, api)
    info = rule_info(api, set().union(*got.values())) if got else {}
    out = {}
    for code in codes:
        pos = [got[i] for i, c in enumerate(cases) if c["legacy"] == code and c["kind"] == "positive"]
        neg = [got[i] for i, c in enumerate(cases) if c["legacy"] == code and c["kind"] == "negative"]
        d, ids, note = decide(pos, neg, info, skipped.get(code, ""))
        out[code] = {"wazuh": ids, "decision": d, "note": note}
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("path", nargs="?", default=str(CASES_DIR), help="file hoặc thư mục ca test")
    ap.add_argument("--url", default="https://localhost:55000")
    ap.add_argument("--user", default="siem-rules")
    ap.add_argument("--password-file", default=str(ROOT / "secrets/wazuh_rules_api_password"))
    ap.add_argument("--report", action="store_true",
                    help="đối chiếu ca legacy (mặc định tests/legacy) với ruleset đang chạy, ghi tests/legacy_map.yml")
    ap.add_argument("--out", default=str(LEGACY_MAP), help="file legacy_map.yml của --report")
    ap.add_argument("--ca", default="", help="CA ký chứng chỉ API")
    ap.add_argument("--insecure", action="store_true", help="không kiểm chứng chỉ API (manager thử, chứng chỉ tự ký)")
    a = ap.parse_args()
    from siem.wazuh_rules import WazuhApi
    api = WazuhApi(a.url, a.user, Path(a.password_file).read_text(encoding="utf-8").strip(), a.ca)
    if a.insecure:
        api.ctx.check_hostname, api.ctx.verify_mode = False, 0      # ssl.CERT_NONE
    if a.report:
        import cases_to_raw
        cases = load_cases(LEGACY_DIR if a.path == str(CASES_DIR) else Path(a.path))
        try:
            res = report(cases, api, cases_to_raw.build()[1])
        except InjectionError as e:
            print(f"LỖI BƠM HÀNG ĐỢI (không phải rule sai): {e}")
            return 2
        Path(a.out).write_text("# Đối chiếu rule YAML cũ với ruleset Wazuh gốc, sinh bởi `wazuh_rule_test.py --report`.\n"
                               + yaml.safe_dump(res, allow_unicode=True, sort_keys=False, width=10**9), encoding="utf-8", newline="\n")
        for d in ("builtin", "approx", "convert"):
            print(d, sum(r["decision"] == d for r in res.values()))
        return 0
    cases = load_cases(Path(a.path))
    try:
        fails = run(cases, api)
    except InjectionError as e:
        print(f"LỖI BƠM HÀNG ĐỢI (không phải rule sai): {e}")
        return 2
    print(f"{len(cases)} ca, {len(fails)} sai")
    for f in fails:
        print(f"  {f.file}:{f.index}  mong đợi {f.expected}  thực tế {f.got_ids}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
