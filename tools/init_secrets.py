"""Sinh bí mật ngẫu nhiên cho lab vào thư mục secrets/ (chạy 1 lần trước `docker compose up`).

    python tools/init_secrets.py            # chỉ tạo file còn thiếu
    python tools/init_secrets.py --force    # tạo lại tất cả (phải xóa volume certs/esdata nếu đổi elastic_password)

Mỗi bí mật là 1 file riêng, được mount vào đúng service cần nó qua Docker secrets
(/run/secrets/<tên>) — không nằm trong .env, docker-compose.yml hay biến môi trường.
"""
import secrets
import string
import sys
from pathlib import Path

NAMES = [
    "elastic_password",       # superuser Elasticsearch — chỉ dùng cho es-setup / khẩn cấp
    "manager_es_password", "analyzer_es_password", "soar_es_password",
    "grafana_es_password", "analyst_es_password", "ai_es_password", "grafana_admin_password",
    "enrollment_key",         # mật khẩu enroll Wazuh agent (wazuh-manager: etc/authd.pass)
    "console_admin_password", # mật khẩu tạm của tài khoản console `admin` đầu tiên (phải đổi khi đăng nhập lần đầu)
    "wazuh_api_password",     # user Wazuh API `siem-soar` (SOAR ra lệnh active response)
]
ALPHABET = string.ascii_letters + string.digits  # không ký tự đặc biệt -> an toàn khi nhúng JSON/shell
# Wazuh API bắt buộc mật khẩu có chữ thường, chữ hoa, số và ký tự đặc biệt -> thêm đủ 4 loại (ký tự an toàn với shell)
NEEDS_SYMBOL = {"wazuh_api_password"}


def generate(name: str) -> str:
    value = [secrets.choice(ALPHABET) for _ in range(32)]
    if name in NEEDS_SYMBOL:
        extra = [secrets.choice(string.ascii_lowercase), secrets.choice(string.ascii_uppercase),
                 secrets.choice(string.digits), secrets.choice("-._")]
        for ch in extra:
            value.insert(secrets.randbelow(len(value) + 1), ch)
    return "".join(value)

sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # console Windows mặc định cp1252
out = Path(__file__).resolve().parent.parent / "secrets"
out.mkdir(exist_ok=True)
force = "--force" in sys.argv
for name in NAMES:
    p = out / name
    if p.exists() and not force:
        print(f"giữ nguyên  {p.name}")
        continue
    p.write_text(generate(name), encoding="utf-8")
    try:
        p.chmod(0o600)
    except OSError:
        pass
    print(f"đã tạo      {p.name}")
print(f"\nThư mục: {out}")
print(r"Đăng nhập console lần đầu: tài khoản admin, mật khẩu tạm trong secrets\console_admin_password "
      r"(type secrets\console_admin_password | cat secrets/console_admin_password) — console buộc đổi ngay.")
