"""Cấu hình chung cho mọi service phía server, đọc từ biến môi trường."""
import os
from pathlib import Path


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def _secret(name: str, default: str = "") -> str:
    """Đọc bí mật từ file do biến <NAME>_FILE trỏ tới (Docker secrets, mount chỉ đọc,
    không nằm trong biến môi trường hay file cấu hình), nếu không có thì đọc biến <NAME>."""
    path = os.getenv(f"{name}_FILE")
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    return os.getenv(name, default)


BASE_DIR = Path(__file__).resolve().parent.parent

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "kafka:9092")
TOPIC_RAW = os.getenv("TOPIC_RAW", "siem.raw")
TOPIC_ALERTS = os.getenv("TOPIC_ALERTS", "siem.alerts")

ES_URL = os.getenv("ES_URL", "https://elasticsearch:9200")
ES_USER = os.getenv("ES_USER", "")               # mỗi service một user riêng (RBAC), xem security/setup.sh
ES_PASSWORD = _secret("ES_PASSWORD")
ES_CA_CERT = os.getenv("ES_CA_CERT", "")         # CA nội bộ để xác thực chứng chỉ TLS của Elasticsearch

# Index Elasticsearch
IDX_EVENTS = "siem-events"      # thực tế ghi vào siem-events-YYYY.MM.DD
IDX_ALERTS = "siem-alerts"
IDX_AGENTS = "siem-agents"
IDX_ACTIONS = "siem-actions"
IDX_CASES = "siem-cases"

# Đăng nhập SOC console: tài khoản riêng từng người (manager/auth.py), không còn API key dùng chung
IDX_USERS = "console-users"         # NGOÀI siem-* -> Grafana / tài khoản chỉ đọc không thấy hash mật khẩu
CONSOLE_ADMIN_PASSWORD = _secret("CONSOLE_ADMIN_PASSWORD")   # chỉ dùng tạo tài khoản admin đầu tiên
CONSOLE_IDLE_MINUTES = int(os.getenv("CONSOLE_IDLE_MINUTES", "30"))      # không thao tác quá N phút -> đăng nhập lại
CONSOLE_SESSION_HOURS = int(os.getenv("CONSOLE_SESSION_HOURS", "8"))     # phiên dài tối đa N giờ
CONSOLE_MAX_FAILURES = int(os.getenv("CONSOLE_MAX_FAILURES", "5"))       # sai N lần / 15 phút -> khóa 15 phút
# Grafana đứng sau manager (https://<manager>/grafana/), dùng chung tài khoản + phiên console (manager/grafana_proxy.py).
# Tên "grafana-internal" chỉ phân giải trong mạng riêng manager <-> grafana (Grafana chỉ tin header từ mạng đó).
GRAFANA_URL = os.getenv("GRAFANA_URL", "http://grafana-internal:3000")

# Wazuh: agent kết nối tới wazuh-manager; SOAR ra lệnh phản ứng qua Wazuh API (user quyền tối thiểu)
WAZUH_API_URL = os.getenv("WAZUH_API_URL", "https://wazuh-manager:55000")
WAZUH_API_USER = os.getenv("WAZUH_API_USER", "siem-soar")
WAZUH_API_PASSWORD = _secret("WAZUH_API_PASSWORD")
WAZUH_API_CA = os.getenv("WAZUH_API_CA", os.getenv("ES_CA_CERT", ""))   # cùng CA nội bộ với Elasticsearch
WAZUH_AR_SCRIPT = os.getenv("WAZUH_AR_SCRIPT", "siem-xdr")              # script phản ứng cài sẵn trên agent
# Cảnh báo của ruleset Wazuh chuyển thành alert (xem detection/wazuh.py)
WAZUH_ALERT_MIN_LEVEL = int(os.getenv("WAZUH_ALERT_MIN_LEVEL", "7"))
WAZUH_ALERT_ANY_LEVEL = int(os.getenv("WAZUH_ALERT_ANY_LEVEL", "12"))
# sca KHÔNG có mặc định: mỗi mục CIS không đạt là 1 cảnh báo level 7 (máy demo: 83 cái lúc khởi động) — đó là
# tư thế cấu hình, xem trong event (event.module: sca), không phải sự cố cần mở case
WAZUH_ALERT_GROUPS = {g.strip() for g in os.getenv(
    "WAZUH_ALERT_GROUPS", "syscheck,rootcheck,vulnerability-detector,virustotal,yara").split(",") if g.strip()}

# Thư mục cấu hình (rules, playbooks, intel, assets)
CONFIG_DIR = Path(os.getenv("CONFIG_DIR", BASE_DIR / "config"))
RULES_DIR = Path(os.getenv("RULES_DIR", BASE_DIR / "rules"))
DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))

# ML — TẠM DỪNG (mặc định tắt): đánh giá cho thấy tỉ lệ báo nhầm quá cao, xem README mục 3.
ML_ENABLED = _bool("ML_ENABLED", False)
ML_WINDOW_SECONDS = int(os.getenv("ML_WINDOW_SECONDS", "60"))
ML_MIN_SAMPLES = int(os.getenv("ML_MIN_SAMPLES", "50"))
ML_CONTAMINATION = float(os.getenv("ML_CONTAMINATION", "0.02"))
ML_BOOTSTRAP_SYNTHETIC = _bool("ML_BOOTSTRAP_SYNTHETIC", True)

# SOAR
SOAR_AUTO_RESPONSE = _bool("SOAR_AUTO_RESPONSE", True)
SOAR_WHITELIST = [c.strip() for c in os.getenv("SOAR_WHITELIST", "127.0.0.0/8").split(",") if c.strip()]
# tối đa N lệnh kill tự động trên mỗi agent trong 60 giây, quá thì để analyst quyết định; 0 = không giới hạn
SOAR_MAX_AUTO_KILLS = int(os.getenv("SOAR_MAX_AUTO_KILLS", "10"))
NOTIFY_WEBHOOK_URL = os.getenv("NOTIFY_WEBHOOK_URL", "")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
# mỗi (rule, thực thể) tối đa 1 thông báo trong N giây, alert cùng khóa được gộp vào lần sau; 0 = không giới hạn
NOTIFY_COOLDOWN_SECONDS = int(os.getenv("NOTIFY_COOLDOWN_SECONDS", "300"))

AGENT_OFFLINE_SECONDS = int(os.getenv("AGENT_OFFLINE_SECONDS", "90"))

# Risk-based alerting (soar/risk.py): cộng risk_score theo máy / tài khoản trong N giờ, vượt ngưỡng từ >= N rule -> RBA-001
RBA_ENABLED = _bool("RBA_ENABLED", True)
RBA_THRESHOLD = float(os.getenv("RBA_THRESHOLD", "150"))
RBA_MIN_RULES = int(os.getenv("RBA_MIN_RULES", "2"))
RBA_WINDOW_HOURS = float(os.getenv("RBA_WINDOW_HOURS", "24"))
RBA_ENTITY_FIELDS = [f.strip() for f in os.getenv("RBA_ENTITY_FIELDS", "host.name,user.name").split(",") if f.strip()]

# Giám sát sức khỏe nguồn log và nền tảng (soar/health.py, alert HLT-*)
HEALTH_ENABLED = _bool("HEALTH_ENABLED", True)
AGENT_DOWN_MINUTES = float(os.getenv("AGENT_DOWN_MINUTES", "15"))          # agent mất kết nối quá N phút -> HLT-001
SOURCE_SILENT_MINUTES = float(os.getenv("SOURCE_SILENT_MINUTES", "30"))    # nguồn không gửi event N phút -> HLT-002
SOURCE_MIN_EXPECTED = float(os.getenv("SOURCE_MIN_EXPECTED", "10"))        # ... nếu trung bình phải có >= N event
VOLUME_DEVIATION = float(os.getenv("VOLUME_DEVIATION", "0.5"))             # lưu lượng giờ lệch > 50% -> HLT-003
VOLUME_MIN_PER_HOUR = float(os.getenv("VOLUME_MIN_PER_HOUR", "100"))       # ... chỉ xét nguồn >= N event / giờ
KAFKA_LAG_MAX_MESSAGES = int(os.getenv("KAFKA_LAG_MAX_MESSAGES", "5000"))  # consumer tụt sau > N message
KAFKA_LAG_MINUTES = float(os.getenv("KAFKA_LAG_MINUTES", "5"))             # ... liên tục N phút -> HLT-005
ES_DISK_MAX_PCT = float(os.getenv("ES_DISK_MAX_PCT", "80"))                # đĩa ES dùng >= N% -> HLT-006

# AI hỗ trợ viết rule (LLM nội bộ qua Ollama). AI CHỈ ĐỀ XUẤT: mọi thay đổi rule phải được
# analyst duyệt trên console; đề xuất ngoại lệ (làm giảm cảnh báo) cần 2 người duyệt.
IDX_AI_PROPOSALS = "ai-rule-proposals"
IDX_AI_JOBS = "ai-jobs"
# Danh mục rule + đề xuất AI cho tra cứu / so sánh (rules_catalog.py, Grafana "Thư viện rule"); trong siem-* -> Grafana đọc được
IDX_RULES = "siem-rules"
RULES_CATALOG_SECONDS = int(os.getenv("RULES_CATALOG_SECONDS", "60"))
# Rule chạy bóng (mode: shadow) -> bật chính thức khi: chạy đủ N ngày, dưới N alert/ngày, tỉ lệ báo nhầm dưới ngưỡng
SHADOW_MIN_DAYS = float(os.getenv("SHADOW_MIN_DAYS", "7"))
SHADOW_MAX_ALERTS_PER_DAY = float(os.getenv("SHADOW_MAX_ALERTS_PER_DAY", "5"))
SHADOW_MAX_FP_RATE = float(os.getenv("SHADOW_MAX_FP_RATE", "0.3"))
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama:11434")
AI_MODEL = os.getenv("AI_MODEL", "qwen3.5:9b")   # tốt nhất trong 4 model đã đo (AI-README mục 10); ~6,6 GB
AI_THINK = os.getenv("AI_THINK", "false").lower() in ("1", "true", "yes")   # bật chế độ suy nghĩ (qwen3...): chậm hơn nhiều
AI_INTERVAL_MINUTES = int(os.getenv("AI_INTERVAL_MINUTES", "60"))       # chu kỳ tự chạy; 0 = chỉ chạy khi bấm
AI_LOOKBACK_DAYS = int(os.getenv("AI_LOOKBACK_DAYS", "30"))             # lấy nhãn false positive / case thật
AI_REPLAY_DAYS = int(os.getenv("AI_REPLAY_DAYS", "7"))                  # replay dữ liệu để ước lượng số alert
AI_REPLAY_MAX_EVENTS = int(os.getenv("AI_REPLAY_MAX_EVENTS", "200000"))
AI_MIN_FALSE_POSITIVES = int(os.getenv("AI_MIN_FALSE_POSITIVES", "3"))  # rule có >= N báo nhầm mới đề xuất ngoại lệ
AI_MIN_GROUP_EVENTS = int(os.getenv("AI_MIN_GROUP_EVENTS", "20"))       # nhóm event chưa có rule cần >= N event
AI_MAX_NEW_RULE_ALERTS_PER_DAY = float(os.getenv("AI_MAX_NEW_RULE_ALERTS_PER_DAY", "20"))
AI_MAX_PROPOSALS_PER_RUN = int(os.getenv("AI_MAX_PROPOSALS_PER_RUN", "5"))
AI_REFINE_ROUNDS = int(os.getenv("AI_REFINE_ROUNDS", "6"))            # rule từ dataset: số lượt LLM bổ sung mẫu cho biến thể còn sót
AI_SIGMAHQ_CANDIDATES = os.getenv("AI_SIGMAHQ_CANDIDATES", "true").lower() in ("1", "true", "yes")  # vế từ rule SigmaHQ
AI_KNOWLEDGE_ROUND = os.getenv("AI_KNOWLEDGE_ROUND", "true").lower() in ("1", "true", "yes")        # hỏi cách làm khác

# Log từng request HTTP tới Elasticsearch quá nhiều -> chỉ giữ cảnh báo
import logging as _logging  # noqa: E402
_logging.getLogger("elastic_transport").setLevel(_logging.WARNING)
