"""Kiểm thử chịu lỗi FLT-01..FLT-09 trên stack đang chạy: gây lỗi một thành phần, sinh event đánh dấu, khôi phục,
rồi đếm trong Elasticsearch -> một dòng của bảng: Gửi | Có trong ES | Thiếu | Trùng | Phục hồi (s) | HLT báo.

    python tools/fault_test.py FLT-01 FLT-04          # chạy vài mục
    python tools/fault_test.py all --events 60 --down 120
    python tools/fault_test.py FLT-07 --down 1200     # ngắt mạng > AGENT_DOWN_MINUTES (15) để thấy HLT-001

Chạy từ thư mục mã nguồn (siem-xdr), stack chạy đủ kể cả --profile demo (từ worktree: đặt COMPOSE_PROJECT_NAME=siem-xdr).
Event sinh BÊN TRONG demo-web: curl http://127.0.0.1/?flt=<mã chạy>-<n> -> Apache access_log -> Wazuh agent -> manager ->
Vector -> Kafka -> analyzer -> siem-events-*. Nguồn 127.0.0.1: SOAR không chặn (SOAR_WHITELIST 127.0.0.0/8), ML bỏ qua
(loopback), và sinh được cả khi demo-web bị ngắt mạng (FLT-07). Mỗi dòng in kèm mốc giờ để khớp video; cột Video tự điền.

Cách đo:
  Gửi / Có trong ES / Thiếu / Trùng: số request đánh dấu / số request khác nhau có trong ES / Gửi - Có / bản ghi thừa.
  FLT-06 đếm ALERT: gửi 3 request tấn công (SQLi, XSS, path traversal); "Có trong ES" = alert SOAR ĐÃ xử lý (có trường
  soar) — alert vẫn vào ES khi SOAR dừng, điều cần đo là SOAR có xử lý bù khi bật lại không.
  Phục hồi (s): từ lúc khôi phục (bật lại / nối lại; FLT-03, 08, 09: từ lúc ra lệnh) tới khi ĐỦ event trong ES;
  "> timeout" nếu tới --timeout vẫn thiếu.
  HLT báo: alert HLT-* của SOAR (soar/health.py) từ lúc bắt đầu mục. Ngưỡng mặc định dài (agent mất kết nối 15 phút,
  nguồn im 30 phút, Kafka nghẽn 5 phút): lỗi ngắn hơn ngưỡng thì "không" là ĐÚNG thiết kế, không phải lỗi.

Tác dụng phụ (đều được dọn): FLT-06 sinh 3 alert web + case thật từ 127.0.0.1; FLT-07 thêm rồi xóa luật iptables chặn
1514/1515 trong demo-web; FLT-08 ghi rule hỏng vào rules-dynamic, manager cách ly MỌI rule động -> script trả các rule
hợp lệ về chỗ cũ, xóa rule hỏng rồi khởi động lại manager. FLT-09 khởi động lại Docker (mọi container).
Kết quả: in bảng Markdown, ghi thêm vào fault-results.csv.
"""
import argparse
import csv
import json
import platform
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")
COLS = ["Mã", "Thao tác gây lỗi", "Gửi", "Có trong ES", "Thiếu", "Trùng", "Phục hồi (s)", "HLT báo", "Video"]
DYN = "/var/ossec/etc/rules-dynamic"
QFIND = "ls -1 /var/ossec/etc/rules-dynamic.quarantine/*/flt-bad.xml 2>/dev/null | tail -n 1"   # bản cách ly mới nhất
BAD_RULE = '<group name="flt,"><rule id="109999" level="3"><match>flt</rule></group>'    # thiếu </match>: XML hỏng
ATTACKS = ["/?flt={run}-1&id=1%27%20union%20select%201,2--", "/?flt={run}-2&q=%3Cscript%3Ealert(1)%3C/script%3E",
           "/?flt={run}-3&file=../../../../etc/passwd"]


def log(msg):
    print(f"[{datetime.now():%H:%M:%S}] {msg}", flush=True)       # mốc giờ để khớp với video


def compose(*args, timeout=900, stdin=None):
    return subprocess.run(["docker", "compose", *args], capture_output=True, text=True, encoding="utf-8",
                          timeout=timeout, input=stdin)


def svc(action, service):
    log(f"docker compose {action} {service}")
    r = compose(action, service)
    if r.returncode:
        log(f"  lỗi: {r.stderr.strip()[:300]}")


def in_web(cmd, timeout=600):
    return compose("exec", "-T", "demo-web", "sh", "-c", cmd, timeout=timeout)


def in_manager(cmd):
    return compose("exec", "-T", "wazuh-manager", "sh", "-c", cmd, timeout=120)


# ------------------------------------------------------------ sinh event / đếm
def send(paths, gap):
    """Request đánh dấu từ BÊN TRONG demo-web tới chính nó; một lệnh sh cho cả loạt (không tốn docker exec mỗi event)."""
    sh = "; ".join(f'curl -s -o /dev/null "http://127.0.0.1{p}"; sleep {gap}' for p in paths)
    r = in_web(sh, timeout=len(paths) * gap + 300)
    if r.returncode:
        log(f"  gửi event lỗi: {r.stderr.strip()[:300]}")


COUNT = r'''
import json
from siem import store, settings
es = store.connect(templates=False)
run, since, kind = %r, %r, %r
idx = settings.IDX_ALERTS if kind == "alerts" else settings.IDX_EVENTS + "-*"
f = [{"wildcard": {"url.original": {"value": "*flt=" + run + "-*"}}}, {"range": {"@timestamp": {"gte": since}}}]
r = es.search(index=idx, size=0, query={"bool": {"filter": f}},
              aggs={"u": {"terms": {"field": "url.original", "size": 5000}}})
soar = es.count(index=idx, query={"bool": {"filter": f + [{"exists": {"field": "soar"}}]}})["count"] if kind == "alerts" else 0
h = es.search(index=settings.IDX_ALERTS, size=200, _source=["rule.id"], query={"bool": {"filter": [
    {"prefix": {"rule.id": "HLT-"}}, {"range": {"@timestamp": {"gte": since}}}]}})
print(json.dumps({"buckets": [b["doc_count"] for b in r["aggregations"]["u"]["buckets"]], "soar": soar,
                  "hlt": sorted({x["_source"]["rule"]["id"] for x in h["hits"]["hits"]})}))
'''


def count(run, since, kind):
    """None khi manager / Elasticsearch chưa trả lời (đang lỗi hoặc đang khởi động)."""
    try:
        r = compose("exec", "-T", "manager", "python", "-", stdin=COUNT % (run, since, kind), timeout=60)
        return json.loads(r.stdout.strip().splitlines()[-1])
    except Exception:  # noqa: BLE001
        return None


def tally(sent, buckets, processed=None):
    """buckets: số bản ghi của mỗi request khác nhau có trong ES. processed: FLT-06, số alert SOAR đã xử lý."""
    present = len(buckets) if processed is None else min(processed, len(buckets))
    return {"sent": sent, "present": present, "missing": max(sent - present, 0), "dup": sum(c - 1 for c in buckets)}


def wait_all(run, since, sent, kind, t_from, timeout):
    last = None
    while time.time() - t_from < timeout:
        if (c := count(run, since, kind)) is not None:
            last = c
            if (c["soar"] if kind == "alerts" else len(c["buckets"])) >= sent:
                return c, round(time.time() - t_from, 1)
        time.sleep(3)
    return last, None


# ------------------------------------------------------------ gây lỗi / khôi phục
def flt07_cut():
    log("demo-web: iptables chặn TCP 1514/1515 ra manager (giữ console / docker exec)")
    in_web("iptables -I OUTPUT -p tcp --dport 1514 -j DROP; iptables -I OUTPUT -p tcp --dport 1515 -j DROP")


def flt07_heal():
    log("demo-web: gỡ luật iptables chặn 1514/1515")
    in_web("iptables -D OUTPUT -p tcp --dport 1514 -j DROP; iptables -D OUTPUT -p tcp --dport 1515 -j DROP")


def flt08_break():
    log(f"ghi rule hỏng {DYN}/flt-bad.xml rồi khởi động lại wazuh-manager")
    in_manager(f"printf '%s' '{BAD_RULE}' > {DYN}/flt-bad.xml")
    svc("restart", "wazuh-manager")
    for _ in range(20):                       # entrypoint cách ly lúc khởi động, có thể chậm hơn lệnh restart vài giây
        r = in_manager(f"F=$({QFIND}); [ -n \"$F\" ] && ls -1 \"$(dirname \"$F\")\"")
        if r.stdout.strip():
            break
        time.sleep(3)
    log(f"  thư mục cách ly chứa: {', '.join(r.stdout.split()) or '(không thấy flt-bad.xml bị cách ly)'}")


def flt08_restore():
    """Entrypoint cách ly MỌI *.xml động khi ruleset hỏng: trả rule AI / ngoại lệ hợp lệ về chỗ cũ, xóa rule hỏng."""
    log("trả rule động hợp lệ về rules-dynamic, xóa flt-bad.xml, khởi động lại wazuh-manager")
    in_manager(f"rm -f {DYN}/flt-bad.xml; F=$({QFIND}); if [ -n \"$F\" ]; then Q=$(dirname \"$F\"); rm -f \"$F\"; "
               f"for x in \"$Q\"/*; do [ -e \"$x\" ] && mv \"$x\" {DYN}/; done; rmdir \"$Q\"; fi")
    svc("restart", "wazuh-manager")


def flt09_restart(cmd):
    log(f"khởi động lại Docker: {' '.join(cmd)}")
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if r.returncode:
        log(f"  lệnh lỗi ({r.returncode}): {(r.stderr or r.stdout).strip()[:300]} — dùng --docker-restart <lệnh khác>")
    end = time.time() + 600
    while time.time() < end and subprocess.run(["docker", "info"], capture_output=True).returncode:
        time.sleep(5)
    log("Docker đã trả lời lại; chờ stack tự khởi động (restart: unless-stopped)")


DOCKER_RESTART = (["docker", "desktop", "restart"] if platform.system() == "Windows"
                  else ["sudo", "systemctl", "restart", "docker"])

# mode: during = gửi đều trong suốt thời gian lỗi; after = gửi sau khi ra lệnh lỗi (FLT-08);
#       before = gửi xong rồi mới gây lỗi (FLT-09: event đang nằm trong agent / Kafka / bộ đệm analyzer); alerts = FLT-06
CASES = {
    "FLT-01": ("Dừng Analyzer vài phút rồi bật lại", lambda a: svc("stop", "analyzer"), lambda a: svc("start", "analyzer"), "during"),
    "FLT-02": ("Dừng Elasticsearch khi đang ingest", lambda a: svc("stop", "elasticsearch"), lambda a: svc("start", "elasticsearch"), "during"),
    "FLT-03": ("Restart Kafka giữ nguyên volume", lambda a: svc("restart", "kafka"), None, "during"),
    "FLT-04": ("Dừng Vector forwarder rồi bật lại", lambda a: svc("stop", "wazuh-forwarder"), lambda a: svc("start", "wazuh-forwarder"), "during"),
    "FLT-05": ("Dừng Wazuh Manager, tạo log trên endpoint", lambda a: svc("stop", "wazuh-manager"), lambda a: svc("start", "wazuh-manager"), "during"),
    "FLT-06": ("Dừng SOAR khi có alert mới", lambda a: svc("stop", "soar"), lambda a: svc("start", "soar"), "alerts"),
    "FLT-07": ("Ngắt mạng endpoint rồi nối lại", lambda a: flt07_cut(), lambda a: flt07_heal(), "during"),
    "FLT-08": ("Ghi tệp luật động sai rồi restart Manager (cách ly)", lambda a: flt08_break(), None, "after"),
    "FLT-09": ("Khởi động lại Docker host", lambda a: flt09_restart(a.docker_restart), None, "before"),
}


def run_case(code, a):
    desc, fault, restore, mode = CASES[code]
    run, t0 = f"{code}-{int(time.time())}", time.time()
    since = datetime.fromtimestamp(t0 - 60, timezone.utc).isoformat()       # lệch giờ log / ES một chút
    log(f"===== {code}: {desc} (mã chạy {run})")
    if mode == "alerts":
        paths, gap = [p.format(run=run) for p in ATTACKS], 2.0
    else:
        paths, gap = [f"/?flt={run}-{i}" for i in range(1, a.events + 1)], max(0.1, a.down / a.events)
    if mode == "before":
        log(f"gửi {len(paths)} event trước khi gây lỗi")
        send(paths, 0.1)
        fault(a)
        t_from = time.time()
    elif mode == "after":
        fault(a)
        t_from = time.time()
        log(f"gửi {len(paths)} event sau khi manager khởi động lại")
        send(paths, 0.2)
    else:
        sender = threading.Thread(target=send, args=(paths, gap))
        if mode == "alerts":
            t_fault = time.time()
            fault(a)
            log(f"gửi {len(paths)} request tấn công trong lúc SOAR dừng")
            sender.start()
        else:
            log(f"gửi {len(paths)} event trong {len(paths) * gap:.0f} giây, gây lỗi sau 3 giây")
            sender.start()
            time.sleep(3)
            t_fault = time.time()
            fault(a)
        time.sleep(max(0.0, a.down - (time.time() - t0)))
        sender.join()
        if restore:
            restore(a)
        t_from = time.time() if restore else t_fault
    log("chờ event vào Elasticsearch...")
    c, rec = wait_all(run, since, len(paths), "alerts" if mode == "alerts" else "events", t_from, a.timeout)
    if code == "FLT-08":
        flt08_restore()
    c = c or {"buckets": [], "soar": 0, "hlt": []}
    t = tally(len(paths), c["buckets"], c["soar"] if mode == "alerts" else None)
    row = [code, desc, t["sent"], t["present"], t["missing"], t["dup"],
           rec if rec is not None else f"> {a.timeout}", ", ".join(c["hlt"]) or "không", ""]
    log("kết quả: " + " | ".join(str(x) for x in row))
    return row


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("cases", nargs="+", help="FLT-01 ... FLT-09 hoặc all")
    p.add_argument("--events", type=int, default=60, help="số event đánh dấu mỗi mục (mặc định 60)")
    p.add_argument("--down", type=float, default=120, help="giây giữ trạng thái lỗi (mặc định 120)")
    p.add_argument("--timeout", type=float, default=900, help="giây chờ đủ event sau khôi phục (mặc định 900)")
    p.add_argument("--docker-restart", nargs="+", default=DOCKER_RESTART, help="lệnh khởi động lại Docker (FLT-09)")
    p.add_argument("--out", default="fault-results.csv")
    a = p.parse_args()
    codes = list(CASES) if a.cases == ["all"] else [c.upper() for c in a.cases]
    if (bad := [c for c in codes if c not in CASES]):
        p.error(f"không có mục {bad}; chọn trong {list(CASES)}")
    if count("preflight", datetime.now(timezone.utc).isoformat(), "events") is None:
        sys.exit("manager / Elasticsearch chưa trả lời: bật stack (kể cả --profile demo) rồi chạy lại")
    rows = []
    for code in codes:
        rows.append(run_case(code, a))
        with open(a.out, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([datetime.now().isoformat(timespec="seconds"), *rows[-1]])
    print("\n| " + " | ".join(COLS) + " |\n|" + "---|" * len(COLS))
    for r in rows:
        print("| " + " | ".join(str(x) for x in r) + " |")


if __name__ == "__main__":
    main()
