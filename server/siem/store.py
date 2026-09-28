"""Lớp truy cập Elasticsearch: tạo index template, ghi event/alert, quản lý
agent & action (lệnh phản ứng XDR). Elasticsearch đóng vai trò vừa là kho log,
vừa là state store cho lab (không cần thêm DB riêng)."""
from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable

from elasticsearch import Elasticsearch, helpers

from . import settings

log = logging.getLogger(__name__)

# Mọi chuỗi mặc định là keyword (để aggregate/terms trong Grafana), riêng
# message/command_line có thêm sub-field .text để full-text search.
_DYNAMIC_TEMPLATES = [
    {"long_text": {
        "match_pattern": "regex",
        "match": "^(message|command_line|original|script_block|description|output)$",
        "mapping": {"type": "keyword", "ignore_above": 8191, "fields": {"text": {"type": "text"}}},
    }},
    {"strings": {"match_mapping_type": "string", "mapping": {"type": "keyword", "ignore_above": 2048}}},
]

_TEMPLATES = {
    "siem-events": {
        "index_patterns": ["siem-events-*"],
        "template": {
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": {
                "dynamic_templates": _DYNAMIC_TEMPLATES,
                "properties": {
                    "@timestamp": {"type": "date"},
                    "source": {"properties": {"ip": {"type": "ip", "ignore_malformed": True}, "port": {"type": "long"}}},
                    "destination": {"properties": {"ip": {"type": "ip", "ignore_malformed": True}, "port": {"type": "long"}}},
                    "http": {"properties": {"response": {"properties": {"status_code": {"type": "long"}, "bytes": {"type": "long"}}}}},
                    # dữ liệu gốc thô có cấu trúc tùy ý -> không index để tránh bùng nổ mapping
                    "raw": {"type": "object", "enabled": False},
                    "winlog": {"properties": {"event_data": {"type": "flattened"}}},
                },
            },
        },
    },
    "siem-alerts": {
        "index_patterns": ["siem-alerts*"],
        "template": {
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": {
                "dynamic_templates": _DYNAMIC_TEMPLATES,
                "properties": {
                    "@timestamp": {"type": "date"},
                    "severity_score": {"type": "integer"},
                    "risk_score": {"type": "float"},
                    "source": {"properties": {"ip": {"type": "ip", "ignore_malformed": True}}},
                    "trigger_event": {"type": "object", "enabled": False},
                },
            },
        },
    },
    "siem-ai": {
        "index_patterns": ["ai-*"],
        "template": {
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": {
                "dynamic_templates": _DYNAMIC_TEMPLATES,
                "properties": {
                    "@timestamp": {"type": "date"},
                    "created_at": {"type": "date"},
                    "updated_at": {"type": "date"},
                    # nội dung đề xuất / output LLM có cấu trúc tùy ý -> lưu nguyên, không index
                    "proposal": {"type": "object", "enabled": False},
                    "llm": {"type": "object", "enabled": False},
                    "evidence": {"type": "object", "enabled": False},
                },
            },
        },
    },
    "siem-state": {
        "index_patterns": ["siem-agents", "siem-actions", "siem-cases"],
        "template": {
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": {
                "dynamic_templates": _DYNAMIC_TEMPLATES,
                "properties": {
                    "@timestamp": {"type": "date"},
                    "created_at": {"type": "date"},
                    "updated_at": {"type": "date"},
                    "last_seen": {"type": "date"},
                    "expires_at": {"type": "date"},
                    "sla_due": {"type": "date"},
                    "params": {"type": "object", "enabled": False},
                },
            },
        },
    },
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id() -> str:
    return uuid.uuid4().hex


def connect(wait: bool = True, templates: bool = True) -> Elasticsearch:
    auth = (settings.ES_USER, settings.ES_PASSWORD) if settings.ES_USER else None
    tls = {"ca_certs": settings.ES_CA_CERT, "verify_certs": True} if settings.ES_CA_CERT else {}
    es = Elasticsearch(settings.ES_URL, basic_auth=auth, request_timeout=30, **tls)
    for attempt in range(60 if wait else 1):
        try:
            if es.ping():
                break
        except Exception:  # noqa: BLE001
            pass
        log.info("chờ Elasticsearch sẵn sàng (%s)...", attempt + 1)
        time.sleep(3)
    if templates:  # service không có quyền manage_index_templates (vd ai-worker) thì bỏ qua
        ensure_templates(es)
    return es


def ensure_templates(es: Elasticsearch) -> None:
    for name, body in _TEMPLATES.items():
        try:
            es.indices.put_index_template(name=name, **body)
        except Exception as e:  # noqa: BLE001
            log.warning("không tạo được index template %s: %s", name, e)


def events_index(ts: str | None) -> str:
    day = (ts or now_iso())[:10].replace("-", ".")
    return f"{settings.IDX_EVENTS}-{day}"


def bulk_index(es: Elasticsearch, actions: Iterable[dict[str, Any]]) -> int:
    ok, errors = helpers.bulk(es, actions, raise_on_error=False, stats_only=False)
    if errors:
        log.warning("bulk có %d lỗi, ví dụ: %s", len(errors), errors[:1])
    return ok


# --------------------------------------------------------------------------
# Agents
# --------------------------------------------------------------------------

def upsert_agent(es: Elasticsearch, info: dict[str, Any], ip: str | None, extra: dict[str, Any] | None = None) -> None:
    doc = {
        "agent_id": info.get("agent_id"),
        "hostname": info.get("hostname"),
        "os": info.get("os"),
        "version": info.get("version"),
        "ip": ip,
        "last_seen": now_iso(),
    } | (extra or {})
    es.update(index=settings.IDX_AGENTS, id=doc["agent_id"], doc=doc, doc_as_upsert=True,
              refresh="wait_for" if extra else None)


def get_agent(es: Elasticsearch, agent_id: str) -> dict[str, Any] | None:
    try:
        return es.get(index=settings.IDX_AGENTS, id=agent_id)["_source"]
    except Exception:  # noqa: BLE001 - chưa có agent / index chưa tồn tại
        return None


def update_agent(es: Elasticsearch, agent_id: str, fields: dict[str, Any]) -> None:
    es.update(index=settings.IDX_AGENTS, id=agent_id, doc=fields, refresh="wait_for", retry_on_conflict=3)


# Trường bí mật của agent: không bao giờ trả ra API/console.
_AGENT_SECRETS = ("token_hash", "prev_token_hash")


def enrollment_state(a: dict[str, Any]) -> str:
    if a.get("revoked"):
        return "revoked"
    if a.get("reenroll_allowed"):
        return "reenroll_allowed"
    if not a.get("token_hash"):
        return "legacy_token"     # agent cũ còn token HMAC, sẽ tự đổi sang token ngẫu nhiên khi kết nối
    return "ok"


def list_agents(es: Elasticsearch) -> list[dict[str, Any]]:
    try:
        res = es.search(index=settings.IDX_AGENTS, size=1000, sort=[{"agent_id": "asc"}])
    except Exception:  # noqa: BLE001 - index chưa tồn tại
        return []
    now = time.time()
    agents = []
    for h in res["hits"]["hits"]:
        a = h["_source"]
        seen = datetime.fromisoformat(a["last_seen"]).timestamp() if a.get("last_seen") else 0
        a["status"] = "online" if now - seen < settings.AGENT_OFFLINE_SECONDS else "offline"
        a["enrollment"] = enrollment_state(a)
        for k in _AGENT_SECRETS:
            a.pop(k, None)
        agents.append(a)
    return agents


# --------------------------------------------------------------------------
# Actions (lệnh phản ứng XDR)
# --------------------------------------------------------------------------

ACTION_TYPES = {"block_ip", "unblock_ip", "kill_process", "isolate_host", "unisolate_host"}


def create_action(es: Elasticsearch, agent_id: str, action_type: str, params: dict[str, Any],
                  *, alert_id: str | None = None, source: str = "manual",
                  expires_at: str | None = None) -> dict[str, Any]:
    if action_type not in ACTION_TYPES:
        raise ValueError(f"loại action không hỗ trợ: {action_type}")
    doc = {
        "id": new_id(),
        "agent_id": agent_id,
        "type": action_type,
        "params": params,
        "target": str(params.get("ip") or params.get("pid") or params.get("name") or agent_id),
        "alert_id": alert_id,
        "source": source,          # manual | soar
        "status": "pending",       # pending -> sent -> success | failed
        "created_at": now_iso(),
        "updated_at": now_iso(),
        "expires_at": expires_at,  # với block_ip: thời điểm SOAR tự gỡ chặn
        "reverted": False,
        "output": "",
    }
    es.index(index=settings.IDX_ACTIONS, id=doc["id"], document=doc, refresh="wait_for")
    return doc


def claim_pending_actions(es: Elasticsearch, agent_id: str) -> list[dict[str, Any]]:
    """Lấy các action pending của agent và chuyển sang 'sent' (optimistic locking
    bằng seq_no để 2 lần poll đồng thời không nhận trùng lệnh)."""
    try:
        res = es.search(
            index=settings.IDX_ACTIONS, size=50, seq_no_primary_term=True,
            query={"bool": {"filter": [{"term": {"agent_id": agent_id}}, {"term": {"status": "pending"}}]}},
            sort=[{"created_at": "asc"}],
        )
    except Exception:  # noqa: BLE001
        return []
    claimed = []
    for h in res["hits"]["hits"]:
        try:
            es.update(index=settings.IDX_ACTIONS, id=h["_id"], doc={"status": "sent", "updated_at": now_iso()},
                      if_seq_no=h["_seq_no"], if_primary_term=h["_primary_term"])
        except Exception:  # noqa: BLE001 - đã bị request khác nhận
            continue
        src = h["_source"]
        # expires_at: agent tự gỡ chặn đúng hạn kể cả khi mất kết nối tới manager lúc hết hạn
        claimed.append({k: src.get(k) for k in ("id", "agent_id", "type", "params", "alert_id", "created_at", "expires_at")})
    return claimed


def finish_action(es: Elasticsearch, action_id: str, agent_id: str, status: str, output: str) -> bool:
    try:
        cur = es.get(index=settings.IDX_ACTIONS, id=action_id)["_source"]
    except Exception:  # noqa: BLE001
        return False
    if cur.get("agent_id") != agent_id:
        return False
    es.update(index=settings.IDX_ACTIONS, id=action_id, refresh="wait_for",
              doc={"status": status if status in ("success", "failed") else "failed",
                   "output": (output or "")[:8000], "updated_at": now_iso()})
    if cur.get("type") == "unblock_ip" and status == "success":
        # Gỡ chặn (thủ công hoặc do hết hạn) -> đánh dấu các lệnh chặn cũ cùng IP là đã gỡ,
        # nếu không SOAR sẽ tưởng IP vẫn đang bị chặn và bỏ qua lần tấn công sau.
        es.update_by_query(index=settings.IDX_ACTIONS, conflicts="proceed", refresh=True, query={"bool": {"filter": [
            {"term": {"agent_id": agent_id}}, {"term": {"type": "block_ip"}}, {"term": {"target": cur.get("target")}},
            {"term": {"reverted": False}}]}}, script={"source": "ctx._source.reverted = true", "lang": "painless"})
    return True


def search(es: Elasticsearch, index: str, query: dict | None = None, size: int = 100,
           sort: list | None = None) -> list[dict[str, Any]]:
    try:
        res = es.search(index=index, size=size, query=query or {"match_all": {}},
                        sort=sort or [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}])
    except Exception:  # noqa: BLE001
        return []
    return [h["_source"] | {"_id": h["_id"]} for h in res["hits"]["hits"]]
