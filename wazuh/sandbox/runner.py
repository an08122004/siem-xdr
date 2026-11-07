"""Runner job của sandbox Wazuh (R67). Chạy TRONG container wazuh-sandbox bằng python của Wazuh, chỉ stdlib, dưới s6
(entrypoint/10-sandbox.sh tạo dịch vụ):

    /var/ossec/framework/python/bin/python3 /sandbox-runner/runner.py watch /sandbox

Giao thức, thư mục /sandbox/jobs/<12 hex>/ (client: server/siem/ai/sandbox.py):
  - worker ghi events.jsonl ({"msg": ...} mỗi dòng, msg = message hàng đợi analysisd), có thể kèm candidate.xml, rồi
    ghi `ready` CUỐI CÙNG;
  - runner ghi result.json {"sent", "processed", "dropped", "canary", "seconds", "load_error"} (+ "error" khi chính runner
    lỗi), alerts.jsonl (alert của job, bỏ alert canary), rồi `done`;
  - worker đọc xong thì xóa job; job cũ hơn 1 giờ (worker chết giữa chừng) runner tự xóa.
Mỗi job: chép rule động thật (/live-dynamic, chỉ đọc) + ứng viên vào rules-dynamic -> `wazuh-analysisd -t` -> restart
manager -> làm rỗng alerts.json -> bơm event + canary syscheck (rule 554) -> chờ analysisd đứng yên -> chép alert.
Thư mục job là ranh giới tin cậy với ai-worker: tên job phải đúng 12 hex, bỏ qua symlink, file kết quả tạo mới bằng
O_EXCL (không ghi xuyên symlink worker đặt sẵn).
"""
from __future__ import annotations

import errno
import json
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

OSSEC = Path("/var/ossec")
LIVE = Path("/live-dynamic")
DYNAMIC = OSSEC / "etc/rules-dynamic"
STATE = OSSEC / "var/run/wazuh-analysisd.state"
ALERTS = OSSEC / "logs/alerts/alerts.json"
QUEUE = str(OSSEC / "queue/sockets/queue")
CANDIDATE = "zz-candidate.xml"            # nạp SAU mọi file rule khác (if_sid tới rule thật được)
MAX_EVENTS = 200_000
JOB_TTL = 3600
# Đo S4 (06/11/2026): gửi theo nhịp tools/wazuh_coverage.SENDER (~8.000 event/s) làm đầy hàng đợi 16384 của analysisd,
# bỏ 7.591/50.000 event; analysisd xử lý ~960 event/s. Nên chờ khi hàng đợi nào quá 20% (state cập nhật mỗi giây, đặt ở
# entrypoint): 50.000 event, 0 bỏ, 93 giây cả job.
BACKLOG_MAX = 0.2
BACKLOG_WAIT = 120                         # giây hàng đợi không vơi thì coi như analysisd treo
CANARY_IDENT, CANARY_RULE = 6_999_000, "554"   # file mới ngoài thư mục web: rule gốc 554 luôn báo (như wazuh_rule_test)
_JOB = re.compile(r"[0-9a-f]{12}")
_LOAD = re.compile(r"\((7612|7617|7619)\)")    # id trùng / if_sid / if_group sai: analysisd vẫn chạy nhưng bỏ rule
_FILE = {"type": "file", "size": 10, "perm": "rw-r--r--", "uid": "0", "gid": "0", "user_name": "root",
         "group_name": "root", "mtime": 1767225600, "hash_md5": "d41d8cd98f00b204e9800998ecf8427e",
         "hash_sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709", "checksum": "abc",
         "hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}


def log(msg: str) -> None:
    print(f"[sandbox-runner] {msg}", flush=True)


def valid_job(name: str) -> bool:
    return bool(_JOB.fullmatch(name))


def load_problems(rc: int, out: str) -> str | None:
    """Lỗi nạp ruleset theo `wazuh-analysisd -t`: mã thoát khác 0 hoặc cảnh báo (7612)/(7617)/(7619). 20 dòng đầu."""
    if rc == 0 and not _LOAD.search(out):
        return None
    return "\n".join([line for line in out.splitlines() if line.strip()][:20]) or f"wazuh-analysisd -t thoát mã {rc}"


def sync_rules(live: Path, dst: Path, candidate: str | None) -> None:
    """dst = đúng các file *.xml của live (không sổ cái exceptions.json, không file tạm) + ứng viên nếu có."""
    for p in dst.iterdir():
        p.unlink()
    for p in sorted(live.glob("*.xml")):
        if p.is_file():
            shutil.copyfile(p, dst / p.name)
    if candidate:
        (dst / CANDIDATE).write_text(candidate, encoding="utf-8")


def parse_state(text: str) -> dict[str, float]:
    return {k: float(v) for k, v in re.findall(r"^(\w+)='?([\d.]+)'?$", text, re.M)}


def counters() -> dict[str, float]:
    return parse_state(STATE.read_text(encoding="utf-8"))


def backlog(c: dict[str, float]) -> float:
    """Tỉ lệ đầy lớn nhất trong các hàng đợi của analysisd (decode, winevt, rule matching...)."""
    return max((v for k, v in c.items() if k.endswith("_queue_usage")), default=0.0)


def canary_message() -> str:
    data = {"path": "/etc/canary-wazuh-sandbox", "mode": "scheduled", "type": "added", "timestamp": 1767225600,
            "attributes": {**_FILE, "inode": CANARY_IDENT}}
    return "8:syscheck:" + json.dumps({"type": "event", "data": data})


def is_canary(alert: dict) -> bool:
    return (str((alert.get("rule") or {}).get("id")) == CANARY_RULE
            and str((alert.get("syscheck") or {}).get("inode_after")) == str(CANARY_IDENT))


def restart() -> None:
    t = time.time()
    p = subprocess.run([str(OSSEC / "bin/wazuh-control"), "restart"], capture_output=True, text=True, timeout=300)
    deadline = time.time() + 120
    while not (STATE.exists() and STATE.stat().st_mtime > t):
        if time.time() > deadline:
            raise RuntimeError("wazuh-analysisd không lên sau restart: " + " | ".join(p.stdout.splitlines()[-3:]))
        time.sleep(0.2)


def send(msgs: list[str]) -> int:
    """Gửi từng event vào socket hàng đợi analysisd (datagram), vòng gửi như wazuh_coverage.SENDER + chờ hàng đợi vơi."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.connect(QUEUE)
    sent = 0
    try:
        for n, msg in enumerate(msgs, 1):
            data = msg.encode("utf-8", "replace")
            for _ in range(600):
                try:
                    s.send(data)
                    sent += 1
                    break
                except OSError as e:
                    if e.errno == errno.EMSGSIZE:
                        break                   # quá cỡ datagram: không gửi được, bên gọi thấy sent < số event
                    time.sleep(0.05)
            else:
                raise RuntimeError("hàng đợi analysisd không nhận event suốt 30 giây")
            if n % 200 == 0:
                time.sleep(0.02)
            if n % 500 == 0:
                deadline = time.time() + BACKLOG_WAIT
                while backlog(counters()) > BACKLOG_MAX:
                    if time.time() > deadline:
                        raise RuntimeError(f"hàng đợi analysisd không vơi sau {BACKLOG_WAIT} giây")
                    time.sleep(0.2)
    finally:
        s.close()
    return sent


def wait_idle(before: dict[str, float]) -> dict[str, float]:
    """Chờ events_processed đứng yên 3 lần x 5 giây (như wazuh_coverage.run_wazuh)."""
    last, stable, c = -1.0, 0, before
    while stable < 3:
        time.sleep(5)
        c = counters()
        done = c.get("events_processed", 0) - before.get("events_processed", 0)
        stable = stable + 1 if done == last else 0
        last = done
    return c


def run_job(job: Path) -> dict:
    msgs: list[str] = []
    with (job / "events.jsonl").open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                if len(msgs) >= MAX_EVENTS:
                    return {"load_error": "quá nhiều event"}
                msgs.append(str(json.loads(line)["msg"]))
    cand = job / "candidate.xml"
    sync_rules(LIVE, DYNAMIC, cand.read_text(encoding="utf-8") if cand.is_file() else None)
    p = subprocess.run([str(OSSEC / "bin/wazuh-analysisd"), "-t"], capture_output=True, text=True, timeout=300)
    if err := load_problems(p.returncode, p.stdout + p.stderr):
        return {"load_error": err}
    restart()
    ALERTS.write_text("", encoding="utf-8")         # bỏ alert lúc khởi động (502...), chỉ giữ alert của job
    before = counters()
    sent = send(msgs)
    send([canary_message()])                         # sau cùng: canary ra alert = analysisd đã đọc tới cuối job
    after = wait_idle(before)
    canary = False
    with ALERTS.open(encoding="utf-8", errors="replace") as src, open(job / "alerts.jsonl", "x", encoding="utf-8") as dst:
        for line in src:
            if line.strip():
                if is_canary(json.loads(line)):
                    canary = True
                else:
                    dst.write(line)
    return {"sent": sent, "canary": canary,
            "processed": int(after.get("events_processed", 0) - before.get("events_processed", 0)),
            "dropped": int(after.get("events_dropped", 0) - before.get("events_dropped", 0))}


def handle(job: Path) -> None:
    t0 = time.time()
    res = {"sent": 0, "processed": 0, "dropped": 0, "canary": False, "load_error": None}
    try:
        res.update(run_job(job))
    except Exception as e:  # noqa: BLE001 - lỗi nào cũng phải thành kết quả, không để worker chờ tới hết giờ
        res["error"] = f"{type(e).__name__}: {e}"
    res["seconds"] = round(time.time() - t0, 1)
    with open(job / "result.json", "x", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False)
    open(job / "done", "x").close()
    log(f"job {job.name}: {json.dumps(res, ensure_ascii=False)[:300]}")


def step(jobs: Path) -> None:
    for d in sorted(jobs.iterdir(), key=lambda p: p.lstat().st_mtime):
        if not valid_job(d.name) or d.is_symlink() or not d.is_dir():
            continue
        if time.time() - d.lstat().st_mtime > JOB_TTL:
            shutil.rmtree(d, ignore_errors=True)
            log(f"xóa job cũ {d.name}")
        elif (d / "ready").exists() and not (d / "done").exists():
            handle(d)


def watch(root: Path) -> None:
    jobs = root / "jobs"
    log(f"chờ job ở {jobs}")
    while True:
        try:
            step(jobs)
        except Exception as e:  # noqa: BLE001 - job bị worker xóa giữa chừng, thư mục chưa có...: thử lại vòng sau
            log(f"lỗi: {type(e).__name__}: {e}")
        time.sleep(1)


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "watch":
        sys.exit("cách dùng: runner.py watch /sandbox")
    watch(Path(sys.argv[2]))
