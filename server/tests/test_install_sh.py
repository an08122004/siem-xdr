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


def test_console_audit_file_agrees_across_ossec_compose_settings() -> None:
    """File nhật ký console được nêu ở ba nơi: <location> trong ossec.conf, điểm gắn volume trong compose, mặc định settings."""
    from siem import settings
    ossec = (ROOT / "wazuh" / "manager" / "ossec.conf").read_text(encoding="utf-8")
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    wz, app = settings.CONSOLE_AUDIT_WAZUH_PATH, settings.CONSOLE_AUDIT_FILE
    assert f"<location>{wz}</location>" in ossec
    assert f"console_audit:{wz.rsplit('/', 1)[0]}" in compose and f"console_audit:{app.rsplit('/', 1)[0]}" in compose
    assert wz.rsplit("/", 1)[1] == app.rsplit("/", 1)[1]            # cùng tên file ở hai phía volume


SETUP = ROOT / "wazuh" / "manager" / "entrypoint" / "10-siem-setup.sh"


@pytest.mark.skipif(sys.platform == "win32", reason="cần bash của Linux (trên Windows `bash` có thể là WSL)")
@pytest.mark.parametrize("value,ok", [("0.0.0.0/0", False), ("0.0.0.0/00", False), ("::/0", False), ("::/000", False),
                                      ("10.0.0.1,192.168.0.0/0", False), ("10.0.0.0/0.0.0.0", False), ("10.0.0.0/", False),
                                      ("10.0.0.0/255.0.0.0", True), ("10.0.0.0/8, 10.1.0.0/16", True),
                                      ("10.0.0.0/08", True), ("10.10.40.254", True),
                                      # sai chính tả: danh sách cho phép từng phần tử phải từ chối
                                      ("10.0.0.0//8", False), ("0.0.0.0/0:", False), ("::/0:", False), ("10.0.0.0/33", False),
                                      ("10.0.0.256", False), ("10.0.0", False), ("10.0.0.1,,10.0.0.2", False), ("10.0.0.1,", False),
                                      ("fd00::/129", False), ("fd00:::1", False), ("fd00::1::2", False), ("abc", False),
                                      ("1:2:3", False), ("fd00::/64", True), ("::1", True), ("2001:db8:0:0:0:0:0:1", True),
                                      ("10.10.40.254,fd00::/8", True)])
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


@pytest.mark.skipif(sys.platform == "win32", reason="cần bash của Linux")
@pytest.mark.parametrize("always_fails", [False, True])
def test_quarantine_restores_files_when_error_is_outside_rules_dynamic(tmp_path, always_fails) -> None:
    """Bước 9 của 10-siem-setup.sh: lỗi do file rule động thì cách ly (giữ ở quarantine); lỗi vẫn còn sau khi cách ly
    (nằm ngoài rules-dynamic) thì chuyển file về chỗ cũ, không để mất rule AI / ngoại lệ vô ích."""
    text = SETUP.read_text(encoding="utf-8")
    step = text[text.index("# 8. Thư mục rule động"):]
    ossec = tmp_path / "ossec"
    (ossec / "bin").mkdir(parents=True)
    # analysisd giả: lỗi khi còn bad.xml trong rules-dynamic; always_fails: lỗi mãi (lỗi nằm ngoài rules-dynamic)
    cond = "true" if always_fails else f'[ -e "{ossec.as_posix()}/etc/rules-dynamic/bad.xml" ]'
    (ossec / "bin" / "wazuh-analysisd").write_text(f'#!/bin/sh\nif {cond}; then echo "ERROR: bad rule"; exit 1; fi\n')
    (ossec / "bin" / "wazuh-analysisd").chmod(0o755)
    d = ossec / "etc" / "rules-dynamic"
    d.mkdir(parents=True)
    (d / "bad.xml").write_text("x")
    (d / "ai.xml").write_text("y")
    step = (step.replace("/var/ossec", ossec.as_posix()).replace("/tmp/analysisd-test.log", (tmp_path / "t.log").as_posix())
            .replace('install -d -o 10001 -g wazuh -m 0755 "$D"', 'mkdir -p "$D"'))
    r = subprocess.run(["bash", "-c", "set -euo pipefail\n" + step], capture_output=True, text=True, encoding="utf-8", timeout=30)
    assert r.returncode == 0, r.stdout + r.stderr
    q = list((ossec / "etc" / "rules-dynamic.quarantine").glob("*/*"))
    if always_fails:
        assert sorted(p.name for p in d.iterdir()) == ["ai.xml", "bad.xml"] and not q and "đã chuyển về" in r.stdout
    else:
        assert not list(d.iterdir()) and sorted(p.name for p in q) == ["ai.xml", "bad.xml"]
