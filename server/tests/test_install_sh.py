"""install.sh: chạy tools/test_install_sh.sh (thử các hàm với docker / python3 giả: đổi IP trên hệ thống chưa ghi tên
project, init_secrets lỗi, status, giữ tên project ghi trong .env, es-setup thoát lỗi, CRLF, tự tải mã nguồn / --fetch,
build image server trước khi up)."""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(sys.platform == "win32", reason="cần bash của Linux (trên Windows `bash` có thể là WSL)")
def test_install_sh_functions() -> None:
    r = subprocess.run(["bash", "tools/test_install_sh.sh", "install.sh"], cwd=ROOT, capture_output=True, text=True,
                       encoding="utf-8", timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr


def test_app_image_matches_compose() -> None:
    image = re.search(r"^APP_IMAGE=(\S+)", (ROOT / "install.sh").read_text(encoding="utf-8"), re.M).group(1)
    assert f"\n  image: {image}\n" in (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
