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

# Bảo mật
ENROLLMENT_KEY = _secret("ENROLLMENT_KEY", "change-me-enrollment-key")
SERVER_SECRET = _secret("SERVER_SECRET", "change-me-server-secret")
API_KEY = _secret("API_KEY", "change-me-api-key")  # cho analyst/console

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
NOTIFY_WEBHOOK_URL = os.getenv("NOTIFY_WEBHOOK_URL", "")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

AGENT_OFFLINE_SECONDS = int(os.getenv("AGENT_OFFLINE_SECONDS", "90"))

# AI hỗ trợ viết rule (LLM nội bộ qua Ollama). AI CHỈ ĐỀ XUẤT: mọi thay đổi rule phải được
# analyst duyệt trên console; đề xuất ngoại lệ (làm giảm cảnh báo) cần 2 người duyệt.
IDX_AI_PROPOSALS = "ai-rule-proposals"
IDX_AI_JOBS = "ai-jobs"
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama:11434")
AI_MODEL = os.getenv("AI_MODEL", "qwen2.5-coder:7b")
AI_INTERVAL_MINUTES = int(os.getenv("AI_INTERVAL_MINUTES", "60"))       # chu kỳ tự chạy; 0 = chỉ chạy khi bấm
AI_LOOKBACK_DAYS = int(os.getenv("AI_LOOKBACK_DAYS", "30"))             # lấy nhãn false positive / case thật
AI_REPLAY_DAYS = int(os.getenv("AI_REPLAY_DAYS", "7"))                  # replay dữ liệu để ước lượng số alert
AI_REPLAY_MAX_EVENTS = int(os.getenv("AI_REPLAY_MAX_EVENTS", "200000"))
AI_MIN_FALSE_POSITIVES = int(os.getenv("AI_MIN_FALSE_POSITIVES", "3"))  # rule có >= N báo nhầm mới đề xuất ngoại lệ
AI_MIN_GROUP_EVENTS = int(os.getenv("AI_MIN_GROUP_EVENTS", "20"))       # nhóm event chưa có rule cần >= N event
AI_MAX_NEW_RULE_ALERTS_PER_DAY = float(os.getenv("AI_MAX_NEW_RULE_ALERTS_PER_DAY", "20"))
AI_MAX_PROPOSALS_PER_RUN = int(os.getenv("AI_MAX_PROPOSALS_PER_RUN", "5"))

# Log từng request HTTP tới Elasticsearch quá nhiều -> chỉ giữ cảnh báo
import logging as _logging  # noqa: E402
_logging.getLogger("elastic_transport").setLevel(_logging.WARNING)
