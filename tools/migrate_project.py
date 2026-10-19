"""Đổi tên project Docker Compose từ siem-xdr sang soc-platform mà vẫn giữ dữ liệu.

Docker Compose gắn tên project vào trước tên volume, container, network. Bản trước 14/10/2026 không khai báo `name:` nên
project lấy tên thư mục (siem-xdr): dữ liệu nằm trong volume siem-xdr_esdata, siem-xdr_wazuh_etc... Nay docker-compose.yml
đặt `name: soc-platform`. Nếu chạy thẳng `docker compose up` trên hệ thống cũ, Compose sẽ tạo volume mới RỖNG
(Elasticsearch trống, agent phải enroll lại). Dữ liệu cũ vẫn còn nhưng không được dùng. Chạy công cụ này một lần trước khi `up`:

  python tools/migrate_project.py               # xem hiện trạng và kế hoạch, không thay đổi gì
  python tools/migrate_project.py --apply       # dừng hệ thống cũ, chép từng volume sang tên mới (kiểm số file)
  python tools/migrate_project.py --keep-name   # không chép gì: ghi COMPOSE_PROJECT_NAME=siem-xdr vào .env (giữ tên cũ)

--apply KHÔNG xóa volume cũ. Chạy hệ thống mới, kiểm tra thấy đủ dữ liệu rồi mới xóa bằng lệnh mà công cụ in ra ở cuối.
Image server tên cố định siem-xdr-server (không theo tên project); công cụ không gắn tag image nào, sau khi chuyển chạy
`docker compose up -d --build` để chắc image được build từ mã hiện tại. Chạy từ thư mục mã nguồn (nơi có docker-compose.yml và .env).
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import Callable

OLD, NEW = "siem-xdr", "soc-platform"
APP_IMAGE = "siem-xdr-server:latest"                 # image: trong docker-compose.yml, đang dùng: không phải image cũ
ROOT = Path(__file__).resolve().parent.parent
PROJECT = "com.docker.compose.project"
VOLUME = "com.docker.compose.volume"
Run = Callable[..., str]


class MigrateError(RuntimeError):
    pass


def docker(*args: str) -> str:
    p = subprocess.run(["docker", *args], capture_output=True, text=True, encoding="utf-8", errors="replace")
    if p.returncode != 0:
        raise MigrateError(f"docker {' '.join(args[:2])}: {(p.stderr or p.stdout).strip()[:400]}")
    return p.stdout


def _rows(out: str) -> list[list[str]]:
    return [line.split("\t") for line in out.splitlines() if line.strip()]


def get_env(path: Path, key: str) -> str | None:
    if not path.exists():
        return None
    vals = [m.group(1).strip() for m in re.finditer(rf"^{key}=(.*)$", path.read_text(encoding="utf-8"), re.M)]
    return vals[-1] if vals else None


def set_env(path: Path, key: str, value: str) -> None:
    """Sửa dòng KEY=... (kể cả dòng đang bị comment "# KEY=") hoặc thêm mới, giữ nguyên các dòng khác."""
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    line = f"{key}={value}"
    if re.search(rf"^{key}=", text, re.M):
        text = re.sub(rf"^{key}=.*$", line, text, flags=re.M)
    elif re.search(rf"^# *{key}=", text, re.M):
        text = re.sub(rf"^# *{key}=.*$", line, text, count=1, flags=re.M)
    else:
        text += ("" if not text or text.endswith("\n") else "\n") + line + "\n"
    path.write_text(text, encoding="utf-8", newline="\n")


class Migrator:
    def __init__(self, run: Run = docker, env_file: Path = ROOT / ".env", out=print):
        self.run, self.env_file, self.out = run, env_file, out

    def volumes(self, project: str) -> dict[str, str]:
        """{khóa volume trong docker-compose.yml: tên volume Docker} của một project."""
        rows = _rows(self.run("volume", "ls", "--filter", f"label={PROJECT}={project}",
                              "--format", '{{.Name}}\t{{.Label "%s"}}' % VOLUME))
        return {(r[1] if len(r) > 1 and r[1] else r[0].removeprefix(project + "_")): r[0] for r in rows}

    def containers(self, project: str) -> list[list[str]]:
        """[[id, tên, trạng thái]] mọi container (kể cả đã dừng) của project."""
        return _rows(self.run("ps", "-a", "--filter", f"label={PROJECT}={project}",
                              "--format", "{{.ID}}\t{{.Names}}\t{{.State}}"))

    def networks(self, project: str) -> list[list[str]]:
        return _rows(self.run("network", "ls", "--filter", f"label={PROJECT}={project}", "--format", "{{.ID}}\t{{.Name}}"))

    def images(self) -> set[str]:
        return {r[0] for r in _rows(self.run("image", "ls", "--format", "{{.Repository}}:{{.Tag}}"))}

    def plan(self) -> dict:
        try:
            self.run("version", "--format", "{{.Server.Version}}")
        except (MigrateError, OSError) as e:
            raise MigrateError(f"không gọi được Docker (Docker Desktop / dockerd đã chạy chưa?): {e}") from e
        imgs = self.images()
        return {"old": self.volumes(OLD), "new": self.volumes(NEW), "old_containers": self.containers(OLD),
                "new_containers": self.containers(NEW), "old_networks": self.networks(OLD),
                "env": get_env(self.env_file, "COMPOSE_PROJECT_NAME"), "images": imgs,
                "old_images": sorted(i for i in imgs if i.startswith(OLD + "-") and not i.endswith(":<none>")
                                     and i != APP_IMAGE)}

    def report(self, p: dict) -> None:
        self.out(f"COMPOSE_PROJECT_NAME trong .env: {p['env'] or '(không đặt -> dùng name: trong docker-compose.yml = ' + NEW + ')'}")
        self.out(f"volume của {OLD}: {len(p['old'])} ({', '.join(sorted(p['old'])) or 'không có'})")
        self.out(f"volume của {NEW}: {len(p['new'])} ({', '.join(sorted(p['new'])) or 'không có'})")
        running = [c[1] for c in p["old_containers"] if c[2] == "running"]
        self.out(f"container của {OLD}: {len(p['old_containers'])} ({len(running)} đang chạy)")

    def keep_name(self, p: dict) -> None:
        set_env(self.env_file, "COMPOSE_PROJECT_NAME", OLD)
        self.out(f"đã ghi COMPOSE_PROJECT_NAME={OLD} vào {self.env_file.name}: hệ thống tiếp tục dùng volume {OLD}_*"
                 f" (`docker compose up -d --build` build image từ mã hiện tại).")

    def helper_image(self, p: dict) -> str:
        for img in (f"{NEW}-server:latest", f"{OLD}-server:latest"):
            if img in p["images"]:
                return img
        raise MigrateError(f"không có image {OLD}-server / {NEW}-server để chép dữ liệu: chạy `docker compose build manager`")

    def apply(self, p: dict) -> list[str]:
        if not p["old"]:
            raise MigrateError(f"không có volume nào của {OLD}: không có gì để chuyển")
        if p["env"] and p["env"] not in (OLD, NEW):
            raise MigrateError(f".env đang đặt COMPOSE_PROJECT_NAME={p['env']}: công cụ không biết project đó, tự xử lý")
        if both := sorted(set(p["old"]) & set(p["new"])):
            raise MigrateError(
                f"đã có volume {NEW}_{both[0]}... (đã từng chạy hệ thống tên {NEW}?). Kiểm tra lại; nếu đó là hệ thống mới rỗng"
                f" và muốn bỏ đi thì chạy `docker compose -p {NEW} down -v` rồi chạy lại công cụ này")
        if p["new_containers"]:
            raise MigrateError(f"đang có container của {NEW}: chạy `docker compose -p {NEW} down` trước")
        helper = self.helper_image(p)
        if ids := [c[0] for c in p["old_containers"]]:
            self.out(f"dừng và gỡ {len(ids)} container của {OLD} (volume giữ nguyên) ...")
            self.run("stop", "-t", "60", *ids)          # Elasticsearch / Kafka cần thời gian ghi xuống đĩa
            self.run("rm", *ids)
        for net in p["old_networks"]:                     # vd. soc-lab có tên cố định: Compose tạo lại dưới project mới
            self.run("network", "rm", net[0])
        for key, old in sorted(p["old"].items()):
            new = f"{NEW}_{key}"
            self.run("volume", "create", "--label", f"{PROJECT}={NEW}", "--label", f"{VOLUME}={key}", new)
            out = self.run("run", "--rm", "--network", "none", "--user", "0:0", "--entrypoint", "sh",
                           "-v", f"{old}:/from:ro", "-v", f"{new}:/to", helper, "-c",
                           "cp -a /from/. /to/ && find /from | wc -l && find /to | wc -l")
            counts = [int(x) for x in out.split() if x.isdigit()][-2:]
            if len(counts) != 2 or counts[0] != counts[1]:
                raise MigrateError(f"chép {old} -> {new} không khớp số file ({out.strip()!r}); volume cũ còn nguyên")
            self.out(f"  {old} -> {new}: {counts[1]} mục")
        if p["env"] == OLD:
            set_env(self.env_file, "COMPOSE_PROJECT_NAME", NEW)
            self.out(f"đã đổi COMPOSE_PROJECT_NAME trong .env thành {NEW}")
        return sorted(p["old"].values())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--apply", action="store_true", help=f"chép volume {OLD}_* sang {NEW}_* (dừng hệ thống cũ)")
    g.add_argument("--keep-name", action="store_true", help=f"giữ tên project {OLD} (ghi vào .env), không chép")
    args = ap.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="replace")      # console Windows mặc định cp1252
    m = Migrator()
    try:
        p = m.plan()
        m.report(p)
        if args.keep_name:
            m.keep_name(p)
        elif args.apply:
            old = m.apply(p)
            print(f"\nXong. Khởi động hệ thống mới (build image {APP_IMAGE} từ mã hiện tại):\n  docker compose up -d --build"
                  f"\nKiểm tra console, alert, agent đều còn rồi mới xóa dữ liệu cũ:\n  docker volume rm {' '.join(old)}")
            if p["old_images"]:
                print("  docker image rm " + " ".join(p["old_images"]))
        elif p["old"] and p["env"] != OLD:
            print(f"\nChưa thay đổi gì. Chọn một trong hai:\n  python tools/migrate_project.py --apply       # chuyển dữ liệu sang tên {NEW}"
                  f"\n  python tools/migrate_project.py --keep-name   # giữ tên {OLD}")
        else:
            print("\nKhông cần chuyển gì.")
    except MigrateError as e:
        print(f"LỖI: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
