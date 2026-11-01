"""install.sh: chạy tools/test_install_sh.sh (thử các hàm với docker / python3 giả, giữ set -euo pipefail như khi chạy
thật: đổi IP trên hệ thống chưa ghi tên project, init_secrets lỗi, status, giữ tên project ghi trong .env, up lỗi thì in
log, nhiều IP trong MANAGER_TLS_IPS, info không sudo, CRLF, tự tải mã nguồn / --fetch, build image server trước khi up)."""
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


SETUP = ROOT / "wazuh" / "manager" / "entrypoint" / "10-siem-setup.sh"


@pytest.mark.skipif(sys.platform == "win32", reason="cần bash của Linux (trên Windows `bash` có thể là WSL)")
@pytest.mark.parametrize("value,ok", [("0.0.0.0/0", False), ("0.0.0.0/00", False), ("::/0", False), ("::/000", False),
                                      ("10.0.0.1,192.168.0.0/0", False), ("10.0.0.0/8, 10.1.0.0/16", True),
                                      ("10.0.0.0/08", True), ("10.10.40.254", True)])
def test_syslog_allowed_ips_rejects_all_zero_prefix(tmp_path, value, ok) -> None:
    """Bước 6 của 10-siem-setup.sh (allowed-ips) chạy trên ossec.conf tạm: prefix toàn số 0 -> giữ cấu hình cũ."""
    text = SETUP.read_text(encoding="utf-8")
    step = text[text.index("# 6. Syslog"):text.index("# 7. ")].replace("/var/ossec/etc/ossec.conf", str(tmp_path / "o.conf"))
    (tmp_path / "o.conf").write_text("<remote>\n<connection>syslog</connection>\n<allowed-ips>10.10.40.254</allowed-ips>\n</remote>\n")
    r = subprocess.run(["bash", "-c", "set -euo pipefail\n" + step], env={"SYSLOG_ALLOWED_IPS": value, "PATH": "/usr/bin:/bin"},
                       capture_output=True, text=True, encoding="utf-8", timeout=30)
    assert r.returncode == 0, r.stderr
    conf = (tmp_path / "o.conf").read_text()
    if ok:
        assert all(f"<allowed-ips>{ip}</allowed-ips>" in conf for ip in value.replace(" ", "").split(","))
    else:
        assert conf.count("<allowed-ips>") == 1 and "<allowed-ips>10.10.40.254</allowed-ips>" in conf and "không hợp lệ" in r.stdout
