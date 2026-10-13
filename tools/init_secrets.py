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
# Bí mật TÙY CHỌN do người dùng tự điền (không sinh ngẫu nhiên): tạo file rỗng để docker compose chạy được khi chưa dùng
OPTIONAL = [
    "misp_api_key",           # auth key MISP (feed IOC, pipeline/misp.py); điền khi đặt MISP_URL trong .env
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
    print(f"đã tạo      {p.name}")
for name in OPTIONAL:
    p = out / name
    if not p.exists():
        p.write_text("", encoding="utf-8")
        print(f"đã tạo rỗng {p.name} (tùy chọn, tự điền khi dùng)")

# Quyền trên Linux: docker compose (không swarm) bind-mount nguyên file secret vào /run/secrets, GIỮ quyền của host.
# Service chạy bằng user riêng (manager/analyzer/soar/ai-worker uid 10001, Grafana uid 472) nên file phải đọc được
# với mọi uid (644); bảo vệ ở cấp THƯ MỤC (700): user khác trên máy không vào được secrets/. File 600 thì service
# không đọc được secret và hỏng ngay khi khởi động (Docker Desktop trên Windows không lộ lỗi này).
try:
    out.chmod(0o700)
    for p in out.iterdir():
        p.chmod(0o644)
except OSError:
    pass
print(f"\nThư mục: {out}")
print(r"Đăng nhập console lần đầu: tài khoản admin, mật khẩu tạm trong secrets\console_admin_password "
      r"(type secrets\console_admin_password | cat secrets/console_admin_password) — console buộc đổi ngay.")
