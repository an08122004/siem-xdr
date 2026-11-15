"""Mô phỏng người dùng BÌNH THƯỜNG cho lab ML (chạy trên máy client của lab, Python 3 stdlib + sshpass).

Mỗi người dùng có một IP riêng (alias trên card mạng), một User-Agent cố định và nhịp hoạt động riêng. Họ duyệt website
trên máy WEB như trình duyệt thật (trang + css/js/ảnh, thời gian đọc giữa các trang), thỉnh thoảng vào /portal (Basic Auth,
đôi khi gõ sai mật khẩu), tải tài liệu, gõ nhầm URL (404); người dùng vai trò admin thỉnh thoảng SSH vào máy WEB.
Nhịp theo giờ trong ngày (giờ máy client): ban ngày dày, tối thưa, đêm rất ít.

Mọi hành động ghi vào --log (JSON mỗi dòng) làm NHÃN "bình thường" khi đánh giá ML (tools/ml_eval.py).

    python3 simulate_users.py --web 10.10.1.132 --users /opt/labsim/users.txt --ips 10.10.1.40-59 --dev ens37
"""
from __future__ import annotations

import argparse
import base64
import http.client
import ipaddress
import json
import math
import random
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path

UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
]
PAGES = ["/", "/news/", "/docs/"] + [f"/news/tin-{i}.html" for i in range(1, 31)]
PORTAL = ["/portal/"] + [f"/portal/reports/bao-cao-{i}.html" for i in range(1, 13)]
DOCS = [f"/docs/tai-lieu-{i}.pdf" for i in range(1, 9)]
ASSETS = ["/assets/site.css", "/assets/site.js"]
TYPOS = ["/new/", "/tin-tuc", "/docs/tai-lieu.pdf", "/portal/report/", "/favicon.ico", "/index.php"]
LOCK = threading.Lock()
STEP = 60                     # giây giữa hai lần quyết định mở phiên mới của một người dùng


def hour_rate(h: int) -> float:
    """Số phiên trung bình mỗi giờ của một người dùng 'chuẩn' theo giờ trong ngày."""
    if 8 <= h < 12 or 13 <= h < 18:
        return 2.0
    if 12 <= h < 13 or 18 <= h < 23:
        return 0.8
    return 0.08


def ssh_hour_rate(h: int) -> float:
    """Số phiên SSH quản trị mỗi giờ của một admin theo giờ (nhịp cao hơn người dùng web để model auth có đủ cửa sổ:
    ~6/giờ ban ngày với 2 admin -> ~12 cửa sổ auth/giờ, đủ 200 cửa sổ trong vài giờ làm việc)."""
    if 8 <= h < 12 or 13 <= h < 18:
        return 6.0
    if 12 <= h < 13 or 18 <= h < 23:
        return 2.0
    return 0.5


class User:
    def __init__(self, name: str, password: str, role: str, ip: str, rng: random.Random, a: argparse.Namespace):
        self.name, self.password, self.role, self.ip, self.a = name, password, role, ip, a
        self.rng = random.Random(rng.random())
        self.ua = self.rng.choice(UAS)
        self.activity = self.rng.uniform(0.5, 2.0)       # người siêng / người ít dùng

    # ------------------------------------------------------------------ ghi nhãn
    def log(self, action: str, **kw) -> None:
        rec = {"ts": datetime.now().astimezone().isoformat(timespec="seconds"), "ip": self.ip, "user": self.name,
               "action": action, **kw}
        with LOCK, open(self.a.log, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    # ------------------------------------------------------------------ HTTP
    def get(self, conn: http.client.HTTPConnection, path: str, auth: str | None = None) -> int:
        headers = {"User-Agent": self.ua, "Accept": "*/*", "Connection": "keep-alive"}
        if auth:
            headers["Authorization"] = "Basic " + base64.b64encode(auth.encode()).decode()
        for attempt in (1, 2):
            try:
                conn.request("GET", path, headers=headers)
                r = conn.getresponse()
                r.read()
                return r.status
            except (http.client.RemoteDisconnected, http.client.CannotSendRequest, ConnectionResetError,
                    BrokenPipeError):
                # Apache đóng kết nối keep-alive sau vài giây rảnh (lúc người dùng đọc trang): trình duyệt thật mở
                # kết nối mới và gửi lại, ở đây cũng vậy (HTTPConnection tự kết nối lại sau close())
                conn.close()
                if attempt == 2:
                    raise
        return 0

    def view(self, conn, path: str, auth: str | None = None) -> int:
        st = self.get(conn, path, auth)
        if st == 200 and path.endswith((".html", "/")):
            for asset in ASSETS + [f"/assets/img{self.rng.randint(1, 6)}.jpg" for _ in range(self.rng.randint(0, 3))]:
                self.get(conn, asset, auth if asset.startswith("/portal") else None)
        return st

    def think(self) -> None:
        time.sleep(min(180.0, self.rng.lognormvariate(math.log(8), 0.9)))

    def session(self) -> None:
        conn = http.client.HTTPConnection(self.a.web, 80, timeout=20, source_address=(self.ip, 0))
        try:
            pages = 1 + int(self.rng.expovariate(1 / 5))
            visited = []
            for _ in range(pages):
                path = self.rng.choice(PAGES)
                st = self.view(conn, path)
                visited.append([path, st])
                self.think()
            if self.rng.random() < 0.4:                                   # vào cổng nội bộ
                cred = f"{self.name}:{self.password}"
                if self.rng.random() < 0.05:                              # gõ sai mật khẩu một lần
                    st = self.view(conn, "/portal/", f"{self.name}:{self.password[:-1]}x")
                    visited.append(["/portal/", st])
                    time.sleep(self.rng.uniform(3, 10))
                for path in ["/portal/"] + self.rng.sample(PORTAL[1:], self.rng.randint(1, 4)):
                    st = self.view(conn, path, cred)
                    visited.append([path, st])
                    self.think()
            if self.rng.random() < 0.15:                                  # tải tài liệu
                path = self.rng.choice(DOCS)
                visited.append([path, self.get(conn, path)])
            if self.rng.random() < 0.03:                                  # gõ nhầm URL
                path = self.rng.choice(TYPOS)
                visited.append([path, self.get(conn, path)])
            self.log("web_session", requests=visited)
        except (OSError, http.client.HTTPException) as e:
            self.log("web_error", error=str(e)[:200])
        finally:
            conn.close()

    def ssh(self) -> None:
        acct = f"lab_{self.name}"
        cmds = self.rng.sample(["uptime", "df -h /", "free -m", "systemctl is-active apache2", "tail -n 5 /var/log/apache2/error.log",
                                "ls /var/www/html/news | wc -l"], self.rng.randint(1, 3))
        wrong = self.rng.random() < 0.05
        for pw in ([self.password[:-1] + "x"] if wrong else []) + [self.password]:
            r = subprocess.run(["sshpass", "-p", pw, "ssh", "-b", self.ip, "-o", "StrictHostKeyChecking=no",
                                "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10", "-o", "LogLevel=ERROR",
                                f"{acct}@{self.a.web}", "; ".join(cmds)], capture_output=True, text=True, timeout=60)
            self.log("ssh", account=acct, ok=r.returncode == 0, commands=cmds)
            if r.returncode == 0:
                break
            time.sleep(self.rng.uniform(4, 12))

    # ------------------------------------------------------------------ vòng đời
    def _do(self, fn) -> None:
        try:
            fn()
        except Exception as e:  # noqa: BLE001 - mô phỏng không được chết vì một lỗi lẻ
            self.log("error", error=f"{type(e).__name__}: {e}"[:200])

    def run(self) -> None:
        time.sleep(self.rng.uniform(0, STEP))
        while True:
            # quá trình Poisson theo giờ: mỗi bước STEP giây quyết định ĐỘC LẬP có mở phiên web / phiên SSH không,
            # theo nhịp CỦA GIỜ HIỆN TẠI. (Bản đầu tính trước thời gian ngủ tới 6 giờ theo nhịp ban đêm -> sáng hôm
            # sau vẫn "ngủ", và máy host tạm dừng VM thì thời gian chờ không trôi.)
            time.sleep(STEP)
            h = datetime.now().hour
            web_rate = hour_rate(h) * self.activity * self.a.scale                   # phiên web / giờ
            if self.rng.random() < 1 - math.exp(-web_rate * STEP / 3600):
                self._do(self.session)
            # admin SSH vào máy chủ để kiểm tra (nguồn DUY NHẤT sinh event đăng nhập trong lab, tách riêng khỏi nhịp
            # web để model auth đủ cửa sổ thoát giai đoạn học). Phiên web của admin KHÔNG còn bị SSH thay thế.
            if self.role == "admin":
                ssh_rate = ssh_hour_rate(h) * self.a.scale                           # phiên SSH / giờ
                if self.rng.random() < 1 - math.exp(-ssh_rate * STEP / 3600):
                    self._do(self.ssh)


def ip_range(spec: str) -> list[str]:
    base, _, last = spec.rpartition("-")
    first = ipaddress.ip_address(base)
    return [str(first + i) for i in range(int(last) - int(base.rsplit(".", 1)[1]) + 1)]


def ensure_aliases(ips: list[str], dev: str) -> None:
    have = subprocess.run(["ip", "-4", "-o", "addr", "show", "dev", dev], capture_output=True, text=True).stdout
    for ip in ips:
        if f" {ip}/" not in have:
            subprocess.run(["ip", "addr", "add", f"{ip}/24", "dev", dev], check=True)


def load_users(path: str) -> list[tuple[str, str, str]]:
    out = []
    for line in Path(path).read_text(encoding="utf-8").replace("\r", "").splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            name, pw, role = [x.strip() for x in line.split("|")]
            out.append((name, pw, role))
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--web", required=True)
    ap.add_argument("--users", required=True)
    ap.add_argument("--ips", required=True, help="dải IP alias, vd 10.10.1.40-59 (mỗi người dùng một IP)")
    ap.add_argument("--dev", required=True)
    ap.add_argument("--log", default="/var/log/labsim/actions.jsonl")
    ap.add_argument("--seed", type=int, default=20261114)
    ap.add_argument("--scale", type=float, default=1.0, help="nhân nhịp hoạt động (1 = như thiết kế)")
    a = ap.parse_args()
    users, ips = load_users(a.users), ip_range(a.ips)
    if len(ips) < len(users):
        raise SystemExit(f"cần {len(users)} IP, dải chỉ có {len(ips)}")
    ensure_aliases(ips, a.dev)
    Path(a.log).parent.mkdir(parents=True, exist_ok=True)
    rng = random.Random(a.seed)
    threads = [threading.Thread(target=User(n, p, r, ip, rng, a).run, daemon=True, name=n)
               for (n, p, r), ip in zip(users, ips)]
    for t in threads:
        t.start()
    print(f"labsim: {len(threads)} người dùng -> http://{a.web}/ từ {ips[0]}..{ips[len(threads) - 1]}", flush=True)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
