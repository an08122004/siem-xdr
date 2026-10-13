"""Sao lưu Elasticsearch (snapshot SLM hằng ngày, security/setup.sh) và DIỄN TẬP KHÔI PHỤC (SOC-OPERATIONS.md mục 5).

    python tools/es_snapshot.py status           # chính sách, lần chạy gần nhất, danh sách snapshot
    python tools/es_snapshot.py now              # chụp ngay một snapshot theo chính sách daily-snapshots
    python tools/es_snapshot.py verify           # khôi phục snapshot mới nhất sang index tạm restore-test-*,
                                                 # so số bản ghi với snapshot, rồi xóa index tạm (không đụng dữ liệu thật)

Chạy từ thư mục gốc của project khi stack đang chạy. Lệnh đi qua `docker compose exec elasticsearch curl` bằng tài
khoản elastic (mật khẩu nằm sẵn trong container), nên không cần CA hay mật khẩu trên máy chạy lệnh.
Khôi phục THẬT sau sự cố (ghi đè index đang có) làm tay theo SOC-OPERATIONS.md, không làm tự động ở đây.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time

REPO, POLICY = "siem-backup", "daily-snapshots"
VERIFY = ["siem-cases", "siem-alerts", "console-users"]      # index nhỏ, quan trọng nhất cho điều tra / pháp lý


def es(method: str, path: str, body: dict | None = None) -> dict:
    cmd = ["docker", "compose", "exec", "-T", "elasticsearch", "sh", "-c",
           'curl -s --cacert config/certs/ca/ca.crt -u "elastic:$(cat config/certs/bootstrap/elastic_password)" '
           f'-H "Content-Type: application/json" -X {method} "https://localhost:9200{path}" --data-binary @-']
    r = subprocess.run(cmd, input=json.dumps(body or {}), capture_output=True, text=True, encoding="utf-8")
    if r.returncode != 0:
        sys.exit(f"lệnh docker compose lỗi ({r.returncode}): {r.stderr.strip()[:500]}")
    try:
        out = json.loads(r.stdout or "{}")
    except json.JSONDecodeError:
        sys.exit(f"Elasticsearch trả về không phải JSON: {r.stdout[:300]}")
    if isinstance(out, dict) and out.get("error"):
        sys.exit(f"Elasticsearch báo lỗi ở {method} {path}: {json.dumps(out['error'], ensure_ascii=False)[:600]}")
    return out


def ts(ms: int | None) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ms / 1000)) if ms else "chưa có"


def status() -> None:
    pol = es("GET", f"/_slm/policy/{POLICY}").get(POLICY) or {}
    p = pol.get("policy") or {}
    print(f"Chính sách {POLICY}: lịch '{p.get('schedule')}' (UTC), giữ {((p.get('retention') or {}).get('expire_after'))}")
    print(f"  thành công gần nhất: {ts((pol.get('last_success') or {}).get('time'))} "
          f"{(pol.get('last_success') or {}).get('snapshot_name') or ''}")
    if pol.get("last_failure"):
        print(f"  thất bại gần nhất:   {ts(pol['last_failure'].get('time'))}: {pol['last_failure'].get('details', '')[:300]}")
    print(f"  lần chạy kế tiếp:    {ts(pol.get('next_execution_millis'))}")
    snaps = es("GET", f"/_snapshot/{REPO}/_all").get("snapshots") or []
    print(f"\n{len(snaps)} snapshot trong repository {REPO}:")
    for s in snaps[-15:]:
        print(f"  {s['snapshot']:<40} {s['state']:<8} {ts(s.get('start_time_in_millis'))}  {len(s.get('indices', []))} index")


def now() -> None:
    r = es("POST", f"/_slm/policy/{POLICY}/_execute")
    print(f"đã yêu cầu chụp snapshot: {r.get('snapshot_name')} (xem tiến độ: python tools/es_snapshot.py status)")


def verify() -> int:
    snaps = [s for s in es("GET", f"/_snapshot/{REPO}/_all").get("snapshots") or [] if s.get("state") == "SUCCESS"]
    if not snaps:
        print("chưa có snapshot thành công nào: chạy `python tools/es_snapshot.py now` rồi thử lại")
        return 1
    snap = snaps[-1]
    indices = [i for i in VERIFY if i in snap.get("indices", [])]
    print(f"thử khôi phục {snap['snapshot']} ({ts(snap.get('start_time_in_millis'))}): {', '.join(indices)}")
    es("DELETE", "/restore-test-*?ignore_unavailable=true")
    t0 = time.time()
    res = es("POST", f"/_snapshot/{REPO}/{snap['snapshot']}/_restore?wait_for_completion=true", {
        "indices": ",".join(indices), "rename_pattern": "(.+)", "rename_replacement": "restore-test-$1",
        "include_global_state": False, "include_aliases": False,
        "index_settings": {"index.number_of_replicas": 0}, "ignore_index_settings": ["index.lifecycle.name"]})
    shards = (res.get("snapshot") or {}).get("shards") or {}
    ok = shards.get("failed", 1) == 0
    print(f"  khôi phục xong sau {time.time() - t0:.1f} giây, shard: {shards}")
    for i in indices:
        n = es("GET", f"/restore-test-{i}/_count").get("count")
        live = es("GET", f"/{i}/_count").get("count")
        print(f"  {i:<16} bản sao lưu: {n:>8}   hiện tại: {live:>8}")
        ok = ok and n is not None
    es("DELETE", "/restore-test-*")
    print(("ĐẠT" if ok else "KHÔNG ĐẠT") + ": đã xóa index tạm restore-test-*. Ghi kết quả diễn tập vào biên bản (RTO đo được ở trên).")
    return 0 if ok else 1


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["status", "now", "verify"])
    a = ap.parse_args()
    if a.command == "status":
        status()
    elif a.command == "now":
        now()
    else:
        return verify()
    return 0


if __name__ == "__main__":
    sys.exit(main())
