"""Đo độ phủ của RULESET GỐC WAZUH trên cùng dataset công khai dùng để đo 40 rule tự viết (datasets/report.md).

Vì sao không dùng wazuh-logtest: logtest chỉ chạy decoder XML; event Windows (eventchannel) phải qua DecodeWinevt của
analysisd, nên trong logtest KHÔNG rule Windows nào khớp được (đều cần decoded_as windows_eventchannel). Vì vậy dataset
được bơm vào HÀNG ĐỢI analysisd của một wazuh-manager TẠM — đúng đường đi của event từ agent — không nối mạng, không chung
volume với hệ thống (không lẫn vào ES / dashboard, không kích hoạt SOAR):

    docker run -d --rm --name wazuh-bench --network none -v <thư mục có script tắt filebeat>:/entrypoint-scripts:ro \\
        wazuh/wazuh-manager:4.14.7
    server/.venv/Scripts/python tools/wazuh_coverage.py          # chuẩn bị -> bơm -> đọc alerts.json -> báo cáo
    docker rm -f wazuh-bench

Định dạng như agent gửi:
  web     : dòng access log Apache (CSIC 2010), hàng đợi '1', location /var/log/apache2/access.log
  windows : Sysmon EventID 1 dạng {"Message", "Event": <XML>} như agent Windows, hàng đợi 'f' (eventchannel)
  linux   : bản ghi auditd SYSCALL + EXECVE + CWD, key audit-wazuh-c (quy tắc audit Wazuh hướng dẫn để ghi lệnh root),
            hàng đợi '1', location /var/log/audit/audit.log
Ghi datasets/report_wazuh.md.
"""
from __future__ import annotations

import gzip
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server"))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
DATA = ROOT / "datasets" / "processed"
CONTAINER = os.getenv("WAZUH_BENCH", "wazuh-bench")
LEVELS = (3, 7, 10)
# Rule Wazuh khớp theo CẤU TRÚC chung chung chứ không theo hành vi tấn công (đọc định nghĩa trong ruleset 4.14.7).
# Báo cáo tính riêng cột "bỏ rule chung chung" để không thổi phồng độ phủ.
GENERIC = {
    "80792": "ghi nhận MỌI lệnh auditd có key audit-wazuh-c (89/94 lệnh bình thường cũng khớp)",
    "92032": "mọi tiến trình con có cha là `cmd.exe /c` (script, trình cài đặt cũng vậy)",
    "92036": "`net.exe` có cha là `cmd.exe /c` (con của 92032)",
    "92041": "regex `add.+\\/d\\s+(\")?(?:[A-Za-z\\d+\\/]{4})*(...)?`: mọi nhóm sau `/d` đều tùy chọn nên khớp MỌI "
             "`reg add ... /d`, không riêng giá trị Base64",
}
ENV = {**os.environ, "MSYS_NO_PATHCONV": "1"}

# chạy TRONG container bằng python của Wazuh: gửi từng event vào socket hàng đợi của analysisd (datagram)
SENDER = r'''
import json, socket, sys, time
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.connect("/var/ossec/queue/sockets/queue")
n = 0
for line in open(sys.argv[1], encoding="utf-8"):
    msg = json.loads(line)["msg"].encode()
    while True:
        try:
            s.send(msg)
            break
        except (BlockingIOError, OSError):
            time.sleep(0.05)
    n += 1
    if n % 200 == 0:
        time.sleep(0.02)            # analysisd xử lý kịp, không làm đầy hàng đợi nội bộ (sẽ bị bỏ event)
print(n)
'''


def _read(name: str):
    with gzip.open(DATA / name, "rt", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


# ---------------------------------------------------------------- dựng event như agent gửi
def sysmon_message(rid: int, image: str, cmd: str, parent: str, parent_cmd: str, user: str) -> str:
    base = re.split(r"[\\/]", image)[-1]
    fields = {"RuleName": "-", "UtcTime": "2026-02-01 00:00:01.000", "ProcessGuid": "{00000000-0000-0000-0000-000000000000}",
              "ProcessId": str(4000 + rid % 60000), "Image": image, "FileVersion": "-", "Description": "-",
              "Product": "-", "Company": "-", "OriginalFileName": base, "CommandLine": cmd, "CurrentDirectory": "C:\\",
              "User": user, "LogonGuid": "{00000000-0000-0000-0000-000000000000}", "LogonId": "0x3e7",
              "TerminalSessionId": "1", "IntegrityLevel": "High", "Hashes": "-",
              "ParentProcessGuid": "{00000000-0000-0000-0000-000000000000}", "ParentProcessId": "3999",
              "ParentImage": parent, "ParentCommandLine": parent_cmd, "ParentUser": user}
    data = "".join(f"<Data Name='{k}'>{escape(str(v))}</Data>" for k, v in fields.items())
    xml = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
           "<Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/>"
           "<EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode>"
           "<Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2026-02-01T00:00:01.000000Z'/>"
           f"<EventRecordID>{rid}</EventRecordID><Correlation/><Execution ProcessID='3000' ThreadID='4000'/>"
           "<Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>bench-win</Computer>"
           "<Security UserID='S-1-5-18'/></System><EventData>" + data + "</EventData></Event>")
    message = "Process Create:\r\n" + "\r\n".join(f"{k}: {v}" for k, v in fields.items())
    return "f:EventChannel:" + json.dumps({"Message": message, "Event": xml})


def _audit_arg(a: str) -> str:
    # auditd ghi tham số có khoảng trắng / dấu nháy / ký tự lạ dưới dạng hex
    return f'"{a}"' if a and re.fullmatch(r"[\x21-\x7e]+", a) and '"' not in a else a.encode().hex().upper()


def audit_message(aid: int, exe: str, cmd: str, ppid: int = 3999, uid: int = 0) -> str:
    try:
        args = shlex.split(cmd)
    except ValueError:
        args = cmd.split()
    args = args[:20] or [exe]
    ts = f"1767225600.{aid % 1000:03d}:{aid}"
    comm = re.split(r"/", exe)[-1][:15]
    sysc = (f'type=SYSCALL msg=audit({ts}): arch=c000003e syscall=59 success=yes exit=0 a0=55 a1=56 a2=57 a3=0 '
            f'items=2 ppid={ppid} pid={4000 + aid % 60000} auid=1000 uid={uid} gid=0 euid={uid} suid={uid} fsuid={uid} '
            f'egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="{comm}" exe="{exe}" key="audit-wazuh-c"')
    execve = f"type=EXECVE msg=audit({ts}): argc={len(args)} " + " ".join(f"a{i}={_audit_arg(a)}" for i, a in enumerate(args))
    return f"1:/var/log/audit/audit.log:{sysc} {execve} type=CWD msg=audit({ts}): cwd=\"/root\""


# ---------------------------------------------------------------- dataset
def load_items() -> list[dict]:
    """Mỗi item: domain, class (attack / normal), group, msg (gửi Wazuh), doc (đã chuẩn hóa, cho rule tự viết)."""
    from siem import settings
    from siem.ai.baseline import LINUX, WINDOWS, ordinary_processes
    from siem.ai.golden import PublicDatasets
    from siem.pipeline.normalize import get, normalize

    g = PublicDatasets.load(DATA, settings.CONFIG_DIR, max_normal=10 ** 9)
    web_attack = [x for x in g.attack if x.label.get("dataset") == "csic2010"]
    raw_attack = [r for r in _read("csic_anomalous.jsonl.gz") if r["label"].get("observable", True)]
    assert len(web_attack) == len(raw_attack), (len(web_attack), len(raw_attack))
    items: list[dict] = []
    for x, r in zip(web_attack, raw_attack):
        line = r["data"]["message"]
        assert get(x.doc, "source.ip") == line.split(" ", 1)[0]
        items.append({"domain": "web", "class": "attack", "group": g.attack_type(x), "line": line,
                      "msg": "1:/var/log/apache2/access.log:" + line, "doc": x.doc})
    web_normal = [x for x in g.normal if x.label.get("dataset") == "csic2010"]
    raw_normal = list(_read("csic_normal.jsonl.gz"))
    assert len(web_normal) == len(raw_normal)
    for x, r in zip(web_normal, raw_normal):
        line = r["data"]["message"]
        items.append({"domain": "web", "class": "normal", "group": "normal", "line": line,
                      "msg": "1:/var/log/apache2/access.log:" + line, "doc": x.doc})
    atomic = [x for x in g.attack if x.label.get("dataset") == "atomic-red-team"]
    raw_atomic = list(_read("atomic.jsonl.gz"))
    assert len(atomic) == len(raw_atomic)
    for x, r in zip(atomic, raw_atomic):
        d, lab = r["data"], r["label"]
        it = {"domain": lab["platform"], "class": "attack", "group": f"{lab['platform']}-{lab['technique'].split('.')[0]}",
              "technique": lab["technique"], "name": str(lab.get("technique_name") or "").split(": ")[0],
              "test": lab.get("guid"), "doc": x.doc}
        items.append(it)
        if lab["platform"] == "windows":
            f = d["fields"]
            it["build"] = ("windows", f["Image"], f["CommandLine"], f["ParentImage"], f.get("ParentCommandLine", ""),
                           f.get("User", ""))
        else:
            it["build"] = ("linux", d["executable"], d["command_line"])
    for platform, rows in (("windows", WINDOWS), ("linux", LINUX)):
        for (image, cmd, parent), doc in zip(rows, ordinary_processes(platform)):
            it = {"domain": platform, "class": "normal", "group": "normal", "doc": doc}
            it["build"] = (("windows", image, cmd, parent, parent, "COMPANY\\lan") if platform == "windows"
                           else ("linux", image, cmd))
            items.append(it)
    for i, it in enumerate(items):
        it["i"] = i
        b = it.pop("build", None)
        if b and b[0] == "windows":
            it["msg"] = sysmon_message(i, *b[1:])
        elif b:
            it["msg"] = audit_message(i, b[1], b[2])
    return items


# ---------------------------------------------------------------- chạy trên wazuh-manager tạm
def docker(*args: str, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], env=ENV, check=True, capture_output=True, text=True, **kw)


def analysisd_counters() -> dict[str, float]:
    out = docker("exec", CONTAINER, "cat", "/var/ossec/var/run/wazuh-analysisd.state").stdout
    return {k: float(v.strip("'")) for k, v in re.findall(r"^(\w+)='?([\d.]+)'?$", out, re.M)}


def run_wazuh(items: list[dict]) -> list[dict]:
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "events.jsonl"
        src.write_text("".join(json.dumps({"msg": it["msg"]}) + "\n" for it in items), encoding="utf-8")
        (Path(tmp) / "sender.py").write_text(SENDER, encoding="utf-8")
        docker("cp", str(src), f"{CONTAINER}:/tmp/events.jsonl")
        docker("cp", str(Path(tmp) / "sender.py"), f"{CONTAINER}:/tmp/sender.py")
        docker("exec", CONTAINER, "sh", "-c", ": > /var/ossec/logs/alerts/alerts.json")
        before = analysisd_counters()
        t0 = time.time()
        sent = docker("exec", CONTAINER, "/var/ossec/framework/python/bin/python3", "/tmp/sender.py",
                      "/tmp/events.jsonl").stdout.strip()
        # đợi analysisd xử lý hết (số event đã xử lý ngừng tăng)
        last, stable = -1.0, 0
        while stable < 3:
            time.sleep(5)
            c = analysisd_counters()
            done = c.get("events_processed", 0) - before.get("events_processed", 0)
            stable = stable + 1 if done == last else 0
            last = done
        print(f"đã gửi {sent} event, analysisd xử lý {last:.0f}, bỏ {c.get('events_dropped', 0):.0f} "
              f"({time.time() - t0:.0f}s)")
        out = Path(tmp) / "alerts.json"
        docker("cp", f"{CONTAINER}:/var/ossec/logs/alerts/alerts.json", str(out))
        return [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines() if line.strip()]


def match_alerts(items: list[dict], alerts: list[dict]) -> dict[int, dict]:
    by_line = {it["line"]: it["i"] for it in items if "line" in it}
    hits: dict[int, dict] = {}
    for a in alerts:
        win = ((a.get("data") or {}).get("win") or {}).get("system") or {}
        if win.get("eventRecordID"):
            i = int(win["eventRecordID"])
        elif (m := re.search(r"msg=audit\(\d+\.\d+:(\d+)\)", a.get("full_log") or "")):
            i = int(m.group(1))
        elif a.get("full_log") in by_line:
            i = by_line[a["full_log"]]
        else:
            continue
        r = a.get("rule") or {}
        if i not in hits or int(r.get("level", 0)) > hits[i]["level"]:
            hits[i] = {"id": str(r.get("id")), "level": int(r.get("level", 0)), "description": r.get("description", ""),
                       "groups": r.get("groups", []), "mitre": (r.get("mitre") or {}).get("id", [])}
    return hits


# ---------------------------------------------------------------- so với rule tự viết + báo cáo
def own_hits(items: list[dict]) -> dict[int, list[str]]:
    from siem import settings
    from siem.ai.golden import PublicDatasets
    from siem.detection.rules import load_rules
    match = [r for r in load_rules(settings.RULES_DIR) if r.type == "match" and not r.id.startswith("AI-")]
    return {it["i"]: ids for it in items if (ids := [r.id for r in match if PublicDatasets.event_hit(r, it["doc"])])}


def pct(a: int, b: int) -> str:
    return f"{100 * a / b:.1f}%" if b else "—"


def report(items: list[dict], hits: dict[int, dict], own: dict[int, list[str]], level: int = 3) -> str:
    from siem.ai.attack_types import TYPES
    names = {"web": "Web (CSIC 2010)", "windows": "Windows (Atomic Red Team)", "linux": "Linux (Atomic Red Team)"}
    wz = lambda it, lv=level: it["i"] in hits and hits[it["i"]]["level"] >= lv  # noqa: E731
    # "cụ thể": alert từ rule không nằm trong GENERIC — phát hiện theo hành vi
    ws = lambda it: wz(it) and hits[it["i"]]["id"] not in GENERIC  # noqa: E731
    L = ["# Độ phủ ruleset gốc Wazuh 4.14.7 so với rule tự viết", "",
         "Sinh bởi `tools/wazuh_coverage.py`: dataset được bơm vào hàng đợi analysisd của một wazuh-manager tạm (ruleset "
         "gốc, không rule tùy chỉnh), đúng định dạng agent gửi. Một event được tính là Wazuh **bắt** khi alert có level "
         "≥ ngưỡng (Wazuh tự ghi alert từ level 3; rule tấn công web của Wazuh đều ở level 6). Cột **Wazuh cụ thể** bỏ các "
         "rule khớp theo cấu trúc chung chung (bảng cuối), chỉ giữ phát hiện theo hành vi.", "",
         "## Tổng quan", "",
         "| Lĩnh vực | Mẫu tấn công | Wazuh mọi alert (≥ 3) | Wazuh ≥ 7 | **Wazuh cụ thể** | **Rule tự viết** | "
         "**Hợp (Wazuh cụ thể + tự viết)** | Báo nhầm Wazuh ≥ 3 / cụ thể | Báo nhầm tự viết |",
         "|---|---|---|---|---|---|---|---|---|"]
    for dom in ("web", "windows", "linux"):
        atk = [it for it in items if it["domain"] == dom and it["class"] == "attack"]
        nor = [it for it in items if it["domain"] == dom and it["class"] == "normal"]
        cov = {lv: sum(wz(it, lv) for it in atk) for lv in LEVELS}
        spec = sum(ws(it) for it in atk)
        o = sum(it["i"] in own for it in atk)
        u = sum(ws(it) or it["i"] in own for it in atk)
        fp3, fps = sum(wz(it, 3) for it in nor), sum(ws(it) for it in nor)
        fpo = sum(it["i"] in own for it in nor)
        L.append(f"| {names[dom]} | {len(atk):,} | {pct(cov[3], len(atk))} | {pct(cov[7], len(atk))} | "
                 f"**{pct(spec, len(atk))}** | **{pct(o, len(atk))}** | **{pct(u, len(atk))}** | "
                 f"{fp3:,}/{len(nor):,} / {fps:,}/{len(nor):,} | {fpo:,}/{len(nor):,} |")
    L += ["", "## Rule Wazuh khớp nhiều nhất", "",
          "Cột *bình thường* cho biết rule có thật sự phân biệt được tấn công hay chỉ ghi nhận mọi event cùng loại.", "",
          "| Lĩnh vực | Rule | Level | Mô tả | Mẫu tấn công | Mẫu bình thường | Chung chung? |", "|---|---|---|---|---|---|---|"]
    for dom in ("web", "windows", "linux"):
        c_atk = Counter(hits[it["i"]]["id"] for it in items if it["domain"] == dom and it["class"] == "attack"
                        and it["i"] in hits)
        c_nor = Counter(hits[it["i"]]["id"] for it in items if it["domain"] == dom and it["class"] == "normal"
                        and it["i"] in hits)
        meta = {h["id"]: h for h in hits.values()}
        for rid, n in c_atk.most_common(12):
            L.append(f"| {dom} | {rid} | {meta[rid]['level']} | {meta[rid]['description'][:90]} | {n:,} | {c_nor[rid]:,} | "
                     f"{'có' if rid in GENERIC else ''} |")
    L += ["", f"## Web theo loại tấn công (Wazuh level ≥ {level})", "",
          "| Loại | Mẫu | Wazuh | Tự viết | Hợp | Chỉ Wazuh bắt | Chỉ tự viết bắt | Rule Wazuh khớp |",
          "|---|---|---|---|---|---|---|---|"]
    groups: dict[str, list] = defaultdict(list)
    for it in items:
        if it["class"] == "attack":
            groups[it["group"]].append(it)
    for k, xs in sorted(((k, v) for k, v in groups.items() if v[0]["domain"] == "web"), key=lambda kv: -len(kv[1])):
        w, o = sum(ws(x) for x in xs), sum(x["i"] in own for x in xs)
        u = sum(ws(x) or x["i"] in own for x in xs)
        rids = Counter(hits[x["i"]]["id"] for x in xs if ws(x))
        L.append(f"| {TYPES[k].label if k in TYPES else k} (`{k}`) | {len(xs):,} | {pct(w, len(xs))} | {pct(o, len(xs))} | "
                 f"{pct(u, len(xs))} | {u - o:,} | {u - w:,} | {', '.join(f'{r} ({n})' for r, n in rids.most_common(3))} |")
    for dom in ("windows", "linux"):
        L += ["", f"## {names[dom]} theo kỹ thuật (Wazuh cụ thể, theo bài thử)", "",
              "Một bài thử được tính là bị bắt khi ít nhất 1 tiến trình của nó bị bắt.", "",
              "| Kỹ thuật | Tên | Bài thử | Wazuh | Tự viết | Hợp |", "|---|---|---|---|---|---|"]
        rows = []
        for k, xs in groups.items():
            if xs[0]["domain"] != dom:
                continue
            tests = defaultdict(list)
            for x in xs:
                tests[x["test"]].append(x)
            w = sum(any(ws(x) for x in t) for t in tests.values())
            o = sum(any(x["i"] in own for x in t) for t in tests.values())
            u = sum(any(ws(x) or x["i"] in own for x in t) for t in tests.values())
            rows.append((len(tests), k, xs[0]["name"], w, o, u))
        tot = [sum(r[i] for r in rows) for i in (0, 3, 4, 5)]
        L.append(f"| **Tổng** | {len(rows)} kỹ thuật | {tot[0]:,} | {pct(tot[1], tot[0])} | {pct(tot[2], tot[0])} | "
                 f"{pct(tot[3], tot[0])} |")
        L.append(f"| Kỹ thuật có ≥ 1 bài thử bị bắt | | | {sum(r[3] > 0 for r in rows)} | {sum(r[4] > 0 for r in rows)} | "
                 f"{sum(r[5] > 0 for r in rows)} |")
        for n, k, name, w, o, u in sorted(rows, key=lambda r: (-r[0], r[1]))[:40]:
            L.append(f"| {k.split('-', 1)[1]} | {name} | {n} | {w} | {o} | {u} |")
        if len(rows) > 40:
            L.append(f"| … | {len(rows) - 40} kỹ thuật ít bài thử hơn | | | | |")
    L += ["", "## Báo nhầm của Wazuh cụ thể trên lệnh bình thường endpoint", "",
          "| Lĩnh vực | Rule | Level | Mô tả | Lệnh bình thường bị bắt |", "|---|---|---|---|---|"]
    for it in items:
        if it["class"] == "normal" and it["domain"] != "web" and ws(it):
            h = hits[it["i"]]
            cmd = str(it["doc"].get("process", {}).get("command_line") or "").replace("|", "\\|")[:110]
            L.append(f"| {it['domain']} | {h['id']} | {h['level']} | {h['description'][:70]} | `{cmd}` |")
    L += ["", "## Rule Wazuh khớp theo cấu trúc chung chung (không tính vào cột Wazuh cụ thể)", "",
          "| Rule | Vì sao không tính là phát hiện | Mẫu tấn công | Mẫu bình thường |", "|---|---|---|---|"]
    for rid, why in GENERIC.items():
        na = sum(1 for it in items if it["class"] == "attack" and hits.get(it["i"], {}).get("id") == rid)
        nn = sum(1 for it in items if it["class"] == "normal" and hits.get(it["i"], {}).get("id") == rid)
        L.append(f"| {rid} | {why} | {na:,} | {nn:,} |")
    L += ["", "## Giới hạn của phép đo", "",
          "- Event Windows là Sysmon EventID 1 dựng lại từ lệnh của bài thử Atomic Red Team: không có hash, OriginalFileName "
          "lấy theo tên file, Description / Company để trống, không có event khác (registry, file, network, PowerShell "
          "script block) — rule Wazuh dựa trên các trường / event đó không có cơ hội khớp. Rule tự viết cũng chịu cùng giới hạn.",
          "- Linux dùng auditd với key `audit-wazuh-c` (Wazuh hướng dẫn cấu hình để ghi lệnh của root). Hệ thống hiện tại thu "
          "tiến trình Linux bằng script `siem-procs` (định dạng riêng) — ruleset gốc Wazuh không có rule nào cho định dạng đó.",
          "- Tiến trình con trong tập lệnh bình thường Windows có dòng lệnh cha là đường dẫn chương trình (gõ tay), còn tiến "
          "trình con của bài thử Atomic có cha `cmd.exe /c ...` — rule 92032 / 92036 phân biệt hai bên chỉ nhờ điểm này.",
          "- Mỗi event được xử lý độc lập; rule tần suất (nhiều lần trong khoảng thời gian) hầu như không kích hoạt vì mỗi "
          "request CSIC có IP riêng.", ""]
    return "\n".join(L)


def main() -> None:
    t0 = time.time()
    items = load_items()
    print(f"{len(items):,} event: " + ", ".join(f"{k}={v:,}" for k, v in Counter(f"{it['domain']}/{it['class']}"
                                                                            for it in items).items()))
    alerts = run_wazuh(items)
    hits = match_alerts(items, alerts)
    print(f"{len(alerts):,} alert, khớp được {len(hits):,} event")
    own = own_hits(items)
    md = report(items, hits, own)
    out = ROOT / "datasets" / "report_wazuh.md"
    out.write_text(md, encoding="utf-8", newline="\n")
    print(md[:md.find("## Rule Wazuh")])
    print(f"đã ghi {out} ({time.time() - t0:.0f}s)")


if __name__ == "__main__":
    main()
