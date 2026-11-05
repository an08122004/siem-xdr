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
import os
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
# đổi tên khi nhiều bản chạy song song trên cùng máy (container tạm bị `docker rm -f` theo tên)
NAME = os.getenv("WAZUH_NOISE_NAME", "wazuh-noise")
MISP_LISTS = {"siem-misp-ip": "240.0.0.0:empty\n", "siem-misp-domain": "placeholder.invalid:empty\n",
              "siem-misp-hash": "0" * 32 + ":empty\n"}      # tên -> dòng giữ chỗ (cùng giá trị 10-siem-setup.sh bước 8b)
MIN_LEVEL = 7
GATE = 1.0          # alert / 100 event bình thường
# thay entrypoint của repo (cần secrets/chứng chỉ): chỉ tắt filebeat + tạo thư mục rule động như entrypoint thật
SETUP = ("#!/bin/bash\nprintf '#!/bin/sh\\nexec sleep infinity\\n' > /etc/services.d/filebeat/run\n"
         "install -d -o root -g wazuh -m 0755 /var/ossec/etc/rules-dynamic\n"
         "install -d -m 0755 /var/log/siem-console\n"
         + "".join(f"install -m 0660 -o wazuh -g wazuh /entrypoint-scripts/{n} /var/ossec/etc/lists/{n}\n" for n in MISP_LISTS))   # ossec.conf có <localfile> console: giữ ossec.log sạch cảnh báo logcollector


def start(tmp: Path, lists: dict[str, str] | None = None) -> None:
    """lists: {tên: nội dung} của danh sách siem-misp-* (ossec.conf khai báo chúng; thiếu file thì rule dùng nó bị bỏ). Tên thiếu = dòng giữ chỗ của entrypoint."""
    (tmp / "10-setup.sh").write_text(SETUP, encoding="utf-8", newline="\n")
    for n, placeholder in MISP_LISTS.items():
        (tmp / n).write_text((lists or {}).get(n, placeholder), encoding="utf-8", newline="\n")
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
    items = [it for it in cov.load_items(extra_normal=True) if it["class"] == "normal"]
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

    def verdict(k: int, t: int) -> str:
        return f"{k:,} alert / {t:,} event = {100 * k / t if t else 0:.3f} / 100 event (cổng <= {GATE}: " f"{'ĐẠT' if t and 100 * k / t <= GATE else 'KHÔNG ĐẠT'})"

    print(f"\nTỔNG: {verdict(n, total)}")
    src = lambda it: it.get("dataset") or ("csic2010" if it["domain"] == "web" else "baseline-endpoint")  # noqa: E731
    for label, key in (("Theo lĩnh vực", lambda it: it["domain"]), ("Theo nguồn", lambda it: f"{it['domain']}/{src(it)}")):
        print(f"\n{label}:")
        for k in sorted({key(it) for it in items}):
            xs = [it for it in items if key(it) == k]
            print(f"- {k}: {verdict(sum(it['i'] in hits for it in xs), len(xs))}")
    print("\n| Rule | Level | Mô tả | Số alert | Lĩnh vực |\n|---|---|---|---|---|")
    for rid, c in count.most_common(20):
        doms = Counter(it["domain"] for it in items if hits.get(it["i"], {}).get("id") == rid)
        print(f"| {rid} | {meta[rid]['level']} | {meta[rid]['description'][:80]} | {c:,} | "
              f"{', '.join(f'{d} {v}' for d, v in doms.items())} |")

if __name__ == "__main__":
    main()
