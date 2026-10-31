"""Đo độ ồn của ruleset Wazuh (ruleset gốc + rule trong nhánh này) trên tập event BÌNH THƯỜNG (R21).

Dựng một wazuh-manager tạm (không nối mạng, không chung volume với hệ thống thật), mount ossec.conf + rules của repo,
bơm event bình thường của tools/wazuh_coverage.py (CSIC normal + lệnh endpoint bình thường), đếm alert level >= 7 theo rule.
Đạt khi <= 1 alert / 100 event bình thường (cổng của kế hoạch).

    python tools/wazuh_noise.py --data D:/.../datasets/processed [--rules wazuh/manager/rules/0100-platform.xml]

--rules: chỉ báo cáo rule (id) khai báo trong file đó (dùng khi kiểm từng file rule mới). Mỗi event tính 1 alert (rule
level cao nhất đã khớp event đó, như wazuh_coverage.match_alerts).
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import wazuh_coverage as cov  # noqa: E402

ROOT = cov.ROOT
IMAGE = "wazuh/wazuh-manager:4.14.8"
NAME = "wazuh-noise"
MIN_LEVEL = 7
GATE = 1.0          # alert / 100 event bình thường
# thay entrypoint của repo (cần secrets/chứng chỉ): chỉ tắt filebeat + tạo thư mục rule động như entrypoint thật
SETUP = ("#!/bin/bash\nprintf '#!/bin/sh\\nexec sleep infinity\\n' > /etc/services.d/filebeat/run\n"
         "install -d -o root -g wazuh -m 0755 /var/ossec/etc/rules-dynamic\n")


def start(tmp: Path) -> None:
    (tmp / "10-setup.sh").write_text(SETUP, encoding="utf-8", newline="\n")
    cov.docker("run", "-d", "--rm", "--name", NAME, "--network", "none",
               "-v", f"{tmp}:/entrypoint-scripts:ro",
               "-v", f"{ROOT / 'wazuh/manager/rules'}:/var/ossec/etc/rules:ro",
               "-v", f"{ROOT / 'wazuh/manager/decoders'}:/var/ossec/etc/decoders:ro",
               "-v", f"{ROOT / 'wazuh/manager/ossec.conf'}:/wazuh-config-mount/etc/ossec.conf:ro", IMAGE)
    for _ in range(60):
        time.sleep(3)
        r = subprocess.run(["docker", "exec", NAME, "/var/ossec/bin/wazuh-control", "status"], env=cov.ENV,
                           capture_output=True, text=True)
        if "wazuh-analysisd is running" in r.stdout:
            time.sleep(5)
            return
    raise SystemExit("wazuh-analysisd không lên")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--data", default=str(ROOT / "datasets" / "processed"))
    ap.add_argument("--rules", help="file XML: chỉ báo cáo rule khai báo trong file này")
    ap.add_argument("--normal", action="store_true", help="(mặc định, giữ cho khớp lệnh trong kế hoạch)")
    a = ap.parse_args()
    cov.DATA, cov.CONTAINER = Path(a.data), NAME
    only = set(re.findall(r'<rule\s+id="(\d+)"', Path(a.rules).read_text(encoding="utf-8"))) if a.rules else None
    items = [it for it in cov.load_items() if it["class"] == "normal"]
    with tempfile.TemporaryDirectory() as tmp:
        try:
            start(Path(tmp))
            alerts = cov.run_wazuh(items)
        finally:
            subprocess.run(["docker", "rm", "-f", NAME], env=cov.ENV, capture_output=True)
    alerts = [x for x in alerts if int((x.get("rule") or {}).get("level", 0)) >= MIN_LEVEL
              and (only is None or str((x.get("rule") or {}).get("id")) in only)]
    hits = cov.match_alerts(items, alerts)
    meta = {h["id"]: h for h in hits.values()}
    count = Counter(h["id"] for h in hits.values())
    total, n = len(items), sum(count.values())
    per100 = 100 * n / total if total else 0.0
    print(f"\nevent bình thường: {total:,} | alert level >= {MIN_LEVEL}: {n:,} | {per100:.3f} alert / 100 event "
          f"(cổng <= {GATE}: {'ĐẠT' if per100 <= GATE else 'KHÔNG ĐẠT'})")
    print("| Rule | Level | Mô tả | Số alert |\n|---|---|---|---|")
    for rid, c in count.most_common(20):
        print(f"| {rid} | {meta[rid]['level']} | {meta[rid]['description'][:80]} | {c:,} |")


if __name__ == "__main__":
    main()
