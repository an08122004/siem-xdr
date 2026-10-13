"""SOAR — Security Orchestration, Automation and Response.

Nhận alert từ Kafka [siem.alerts], đối chiếu với playbook (config/playbooks.yml)
và thực hiện các bước tự động:

  block_ip      tạo lệnh chặn IP cho agent (XDR response), tự gỡ sau `duration` giây
  kill_process  diệt tiến trình độc hại (cả cây tiến trình) trên máy đã báo alert
  isolate_host  cô lập máy khỏi mạng (chỉ giữ kết nối tới wazuh-manager)
  (lệnh được soar/wazuh.py gửi xuống Wazuh agent qua Wazuh API, xem Responder)
  notify        gửi thông báo webhook (Slack/Discord/Teams tương thích) / Telegram
  create_case   gom alert thành case để analyst điều tra

Bước nào có `approval: true` sẽ KHÔNG tự chạy mà chỉ ghi thành đề xuất để analyst
bấm duyệt trên console — phù hợp với hành động nặng như cô lập máy.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import json
import logging
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from .. import priority as prio
from .. import settings, store
from .cases import CasePlaybooks
from .wazuh import PROC_NAME
from ..detection.rules import SEVERITY_SCORE
from ..pipeline.normalize import get

log = logging.getLogger("soar")


# Case chưa đóng -> alert mới cùng rule + thực thể được gom vào case này
OPEN_CASE_STATUSES = ("open", "in_progress", "contained")
# Lệnh chặn thành công không có hạn chỉ được coi là còn hiệu lực trong N phút (xem Soar._active_block)
BLOCK_TRUST_MINUTES = 10
# Lệnh gỡ chặn (khi hết hạn) chưa thành công sau N phút -> tạo lại (xem Soar.housekeeping)
REVERT_RETRY_MINUTES = 15
# Cửa sổ đếm giới hạn số lệnh kill tự động trên mỗi agent (xem Soar._allow_kill)
AUTO_KILL_WINDOW_SECONDS = 60
# Bước chỉ chạy 1 lần cho mỗi alert dù nhiều playbook cùng khớp (vd playbook riêng + "Cảnh báo chung mức critical")
ONCE_PER_ALERT = ("notify", "create_case")
CASE_MAX_ALERT_IDS = 500
# Thêm alert vào case NGAY TRÊN Elasticsearch (bản mới nhất của case), bỏ qua nếu đã có (Kafka giao lại alert sau khi
# SOAR khởi động lại). Trước đây SOAR ghi đè alert_ids bằng danh sách đọc từ kết quả search, vốn trễ tới 1 giây so với
# bản mới nhất: alert dồn dập cùng rule + thực thể ghi đè nhau và bị mất khỏi case.
# Alert mới ưu tiên cao hơn case (vd P3 -> P1 vì máy chủ critical) -> nâng ưu tiên case, kéo hạn SLA chưa đạt về sớm hơn
# (không bao giờ lùi hạn), ghi vào lịch sử case. So sánh chuỗi: "P1" < "P2", thời điểm ISO cùng định dạng UTC.
CASE_ADD_ALERT = """
if (ctx._source.alert_ids == null) { ctx._source.alert_ids = new ArrayList(); }
if (ctx._source.alert_ids.contains(params.id)) { ctx.op = 'noop'; }
else {
  ctx._source.alert_ids.add(params.id);
  if (ctx._source.alert_ids.size() > params.max) { ctx._source.alert_ids.remove(0); }
  ctx._source.alert_count = (ctx._source.alert_count == null ? 0 : ctx._source.alert_count) + 1;
  ctx._source.updated_at = params.now;
  if (params.prio != null && (ctx._source.priority == null || params.prio.compareTo(ctx._source.priority) < 0)) {
    def old = ctx._source.priority;
    ctx._source.priority = params.prio;
    if (ctx._source.sla == null) { ctx._source.sla = new HashMap(); }
    if (ctx._source.acknowledged_at == null && (ctx._source.sla_due == null || params.ack_due.compareTo(ctx._source.sla_due) < 0)) {
      ctx._source.sla_due = params.ack_due; ctx._source.sla.ack_due = params.ack_due;
    }
    if (ctx._source.contained_at == null && (ctx._source.contain_due == null || params.contain_due.compareTo(ctx._source.contain_due) < 0)) {
      ctx._source.contain_due = params.contain_due; ctx._source.sla.contain_due = params.contain_due;
    }
    if (ctx._source.notes == null) { ctx._source.notes = new ArrayList(); }
    ctx._source.notes.add(['at': params.now, 'by': 'hệ thống',
                           'text': 'nâng ưu tiên ' + old + ' -> ' + params.prio + ' do alert ' + params.id]);
  }
}
"""


def endpoint_agent(alert: dict[str, Any]) -> str | None:
    """Agent ra lệnh được (Wazuh agent). Log syslog (firewall, Suricata) mang agent.id giả `syslog-<ip>`, sự kiện
    đăng nhập của chính SOC console mang `soc-console` (manager/auth.py): không có agent nào để chạy lệnh trên đó."""
    agent_id = get(alert, "agent.id")
    return None if not agent_id or str(agent_id).startswith("syslog-") or agent_id == "soc-console" else str(agent_id)


def case_entity(alert: dict[str, Any]) -> str:
    """Thực thể chính của alert: gom case và gộp thông báo theo (rule, thực thể)."""
    return str(get(alert, "source.ip") or get(alert, "user.name") or get(alert, "host.name") or "unknown")


class Playbook:
    def __init__(self, d: dict[str, Any]):
        self.name = d["name"]
        w = d.get("when") or {}
        self.rule_ids = [str(x) for x in w.get("rule_ids", ["*"])]
        self.min_severity = SEVERITY_SCORE[w.get("min_severity", "low")]
        self.sources = w.get("sources")          # ["rule", "ml"]
        self.tags_any = set(w.get("tags_any") or [])
        self.steps = d.get("steps") or []

    def matches(self, alert: dict[str, Any]) -> bool:
        rid = str(get(alert, "rule.id", ""))
        if not any(fnmatch.fnmatch(rid, p) for p in self.rule_ids):
            return False
        if alert.get("severity_score", 0) < self.min_severity:
            return False
        if self.sources and get(alert, "alert.source") not in self.sources:
            return False
        if self.tags_any and not self.tags_any & set(get(alert, "rule.tags") or []):
            return False
        return True


def load_playbooks(path: Path) -> list[Playbook]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    pbs = [Playbook(p) for p in data.get("playbooks", []) if p.get("enabled", True)]
    log.info("đã nạp %d playbook", len(pbs))
    return pbs


class Soar:
    def __init__(self, es, playbooks: list[Playbook], auto_response: bool = True,
                 whitelist: list[str] | None = None, notifier=None, case_playbooks: CasePlaybooks | None = None,
                 max_auto_kills: int = 0, clock=time.monotonic):
        self.es = es
        self.playbooks = playbooks
        self.case_playbooks = case_playbooks or CasePlaybooks(None)
        self.auto_response = auto_response
        self.whitelist = [ipaddress.ip_network(c, strict=False) for c in (whitelist or [])]
        self.notifier = notifier or Notifier()
        self.max_auto_kills, self.clock = max_auto_kills, clock      # 0 = không giới hạn
        self._kills: dict[str, list[float]] = {}                     # agent -> thời điểm các lần tự kill gần đây

    # ------------------------------------------------------------------
    def handle(self, alert: dict[str, Any]) -> list[dict[str, Any]]:
        if get(alert, "alert.shadow"):
            # rule chạy bóng: chỉ để đo số alert / tỉ lệ báo nhầm trước khi bật chính thức (detection/rules.py)
            return []
        results: list[dict[str, Any]] = []
        done: set[str] = set()
        for pb in self.playbooks:
            if not pb.matches(alert):
                continue
            log.info("alert %s khớp playbook '%s'", get(alert, "rule.id"), pb.name)
            for step in pb.steps:
                action = step.get("action")
                if action in ONCE_PER_ALERT and action in done:
                    results.append({"playbook": pb.name, "action": action, "status": "skipped",
                                    "detail": "đã thực hiện ở playbook trước"})
                    continue
                try:
                    res = self.run_step(step, alert)
                except Exception as e:  # noqa: BLE001
                    log.exception("bước %s lỗi", action)
                    res = {"status": "error", "detail": str(e)}
                if action in ONCE_PER_ALERT:
                    done.add(action)
                results.append({"playbook": pb.name, "action": action, **res})
        if results:
            self._update_alert(alert, results)
        return results

    def run_step(self, step: dict[str, Any], alert: dict[str, Any]) -> dict[str, Any]:
        action = step.get("action")
        if action == "notify":
            return self.notifier.send(alert)
        if action == "create_case":
            return self.create_case(alert)
        if action not in ("block_ip", "kill_process", "isolate_host"):
            return {"status": "error", "detail": f"action không hỗ trợ: {action}"}

        if step.get("approval"):
            who = "lead (Trưởng nhóm IR)" if action == "isolate_host" else "analyst"     # cùng quyền với tự tạo lệnh đó
            return {"status": "awaiting_approval", "detail": f"cần {who} duyệt hoặc từ chối trên console"}
        if not self.auto_response:
            return {"status": "skipped", "detail": "SOAR_AUTO_RESPONSE=false"}

        if action == "block_ip":
            return self.block_ip(step, alert)
        agent_id = endpoint_agent(alert)
        if not agent_id:
            return {"status": "skipped", "detail": "alert không gắn với Wazuh agent nào (vd log syslog của firewall)"}
        if action == "kill_process":
            # chỉ kill tự động theo PID: kill theo tên giết MỌI tiến trình cùng tên (vd tên httpd -> sập web).
            # Kill theo tên vẫn làm được thủ công trên console, có người chịu trách nhiệm.
            pid = get(alert, "process.pid")
            if not pid:
                return {"status": "skipped", "detail": "alert không có PID, không tự kill theo tên tiến trình"}
            if not self._allow_kill(agent_id):
                return {"status": "skipped", "detail": f"đã tự kill {self.max_auto_kills} lần trên agent {agent_id} trong "
                                                       f"{AUTO_KILL_WINDOW_SECONDS} giây qua, lệnh tiếp theo để analyst quyết định"}
            params: dict[str, Any] = {"pid": pid}
            # tên tiến trình trong alert: script trên agent không kill nếu PID đã được cấp lại cho tiến trình khác
            # (tên có ký tự lạ thì không gửi, script kill như trước)
            if PROC_NAME.match(str(get(alert, "process.name") or "")):
                params["expect"] = get(alert, "process.name")
            a = store.create_action(self.es, agent_id, "kill_process", params,
                                    alert_id=get(alert, "alert.id"), source="soar")
            return {"status": "queued", "action_id": a["id"], "agent_id": agent_id, "target": str(pid)}
        a = store.create_action(self.es, agent_id, "isolate_host", {}, alert_id=get(alert, "alert.id"), source="soar")
        return {"status": "queued", "action_id": a["id"], "agent_id": agent_id}

    def _allow_kill(self, agent_id: str) -> bool:
        """Tối đa `max_auto_kills` lệnh kill tự động trên một agent trong AUTO_KILL_WINDOW_SECONDS giây. Chặn trường hợp
        alert giả / báo nhầm hàng loạt biến SOAR thành công cụ kill dần mọi tiến trình trên máy (vd lỗ hổng tiêm log sửa
        11/10/2026: mỗi request một PID). Alert vượt giới hạn vẫn được thông báo và gom case."""
        if self.max_auto_kills <= 0:
            return True
        now = self.clock()
        recent = [t for t in self._kills.get(agent_id, []) if now - t < AUTO_KILL_WINDOW_SECONDS]
        allowed = len(recent) < self.max_auto_kills
        self._kills[agent_id] = recent + [now] if allowed else recent
        return allowed

    def block_ip(self, step: dict[str, Any], alert: dict[str, Any]) -> dict[str, Any]:
        ip = get(alert, step.get("target", "source.ip"))
        try:
            addr = ipaddress.ip_address(str(ip))
        except ValueError:
            return {"status": "skipped", "detail": f"không có IP hợp lệ ({ip})"}
        if any(addr in n for n in self.whitelist):
            return {"status": "skipped", "detail": f"{ip} nằm trong whitelist"}

        if step.get("scope") == "all":
            agents = [a["agent_id"] for a in store.list_agents(self.es) if a["status"] == "online"]
        else:
            agents = [endpoint_agent(alert)] if endpoint_agent(alert) else []
        if not agents:
            return {"status": "skipped", "detail": "không có agent để thực thi"}

        duration = int(step.get("duration", 3600))
        expires = (datetime.now(timezone.utc) + timedelta(seconds=duration)).isoformat() if duration > 0 else None
        queued, dup, extended = [], [], []
        for agent_id in agents:
            if cur := self._active_block(agent_id, str(addr)):
                (extended if self._extend_block(cur, expires) else dup).append(agent_id)
                continue
            a = store.create_action(self.es, agent_id, "block_ip", {"ip": str(addr), "duration": duration},
                                    alert_id=get(alert, "alert.id"), source="soar", expires_at=expires)
            queued.append(a["id"])
        status = "queued" if queued else "extended" if extended else "skipped"
        detail = "; ".join(x for x in (f"gia hạn chặn tới {expires or 'vĩnh viễn'} trên {extended}" if extended else "",
                                        f"đã chặn sẵn trên {dup}" if dup else "") if x)
        return {"status": status, "target": str(addr), "agents": agents, "action_ids": queued, "detail": detail}

    def _active_block(self, agent_id: str, ip: str) -> dict[str, Any] | None:
        """Lệnh chặn IP này trên agent còn hiệu lực (để không chặn trùng khi alert dồn dập), không có thì None.
        Chỉ tin: lệnh đang gửi/chờ kết quả, lệnh thành công còn hạn, hoặc thành công trong BLOCK_TRUST_MINUTES gần đây.
        Không tin lệnh thành công cũ không có hạn: luật iptables trên agent mất khi máy / container khởi động lại, mà
        bản ghi vẫn ghi 'đang chặn' -> kẻ tấn công không bị chặn lại (đã gặp khi chạy E2E 30/9). Script chặn trên agent
        kiểm tra luật trước khi thêm nên gửi lại lệnh chặn không gây hại. Lệnh đã được yêu cầu gỡ (hết hạn) cũng không
        tính: luật của nó sắp bị lệnh gỡ xóa."""
        now = datetime.now(timezone.utc)
        recent = (now - timedelta(minutes=BLOCK_TRUST_MINUTES)).isoformat()
        success = [{"term": {"status": "success"}}]
        hits = store.search(self.es, settings.IDX_ACTIONS, size=1, query={"bool": {
            "filter": [{"term": {"agent_id": agent_id}}, {"term": {"type": "block_ip"}}, {"term": {"target": ip}},
                       {"term": {"reverted": False}}],
            "must_not": [{"exists": {"field": "revert_requested_at"}}],
            "should": [{"terms": {"status": ["pending", "sent"]}},
                       {"bool": {"filter": success + [{"range": {"expires_at": {"gt": now.isoformat()}}}]}},
                       {"bool": {"filter": success + [{"range": {"created_at": {"gte": recent}}}]}}],
            "minimum_should_match": 1,
        }}, sort=[{"created_at": "desc"}])
        return hits[0] if hits else None

    def _extend_block(self, block: dict[str, Any], expires: str | None) -> bool:
        """Lệnh chặn đang hiệu lực hết hạn sớm hơn lần chặn mới (`expires` None = vĩnh viễn) -> kéo dài hạn của chính
        lệnh đó; luật trên agent vẫn còn nên không cần gửi lại. Trước đây lần chặn mới bị bỏ qua: AUTH-001 chặn 1 giờ rồi
        AUTH-002 (tài khoản có thể đã bị chiếm, playbook chặn 24 giờ) cùng IP thì IP vẫn được gỡ sau 1 giờ."""
        old = block.get("expires_at")
        if old is None:
            return False                                    # đang chặn vĩnh viễn
        if expires is not None and datetime.fromisoformat(expires) <= datetime.fromisoformat(old):
            return False
        # không đổi updated_at: housekeeping dùng nó tính quá hạn cho lệnh còn chờ agent báo kết quả
        self.es.update(index=settings.IDX_ACTIONS, id=block["_id"], refresh="wait_for", doc={"expires_at": expires})
        log.info("gia hạn chặn %s trên %s: %s -> %s", block.get("target"), block.get("agent_id"), old, expires or "vĩnh viễn")
        return True

    def create_case(self, alert: dict[str, Any]) -> dict[str, Any]:
        """Gom alert vào case đang mở cùng rule + cùng thực thể trong 24h, nếu không có thì tạo mới."""
        entity = case_entity(alert)
        since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        existing = store.search(self.es, settings.IDX_CASES, size=1, query={"bool": {"filter": [
            {"term": {"rule_id": get(alert, "rule.id")}}, {"term": {"entity": entity}},
            {"terms": {"status": list(OPEN_CASE_STATUSES)}}, {"range": {"created_at": {"gte": since}}},
        ]}}, sort=[{"created_at": "desc"}])
        alert_id, now = get(alert, "alert.id"), store.now_iso()
        level = alert.get("priority")
        if level not in prio.PRIORITIES:                # alert tạo trước khi có priority.py
            level = prio.policy().priority(alert.get("severity"), get(alert, "asset.criticality"))
        if existing:
            case = existing[0]
            self.es.update(index=settings.IDX_CASES, id=case["_id"], retry_on_conflict=5, script={
                "lang": "painless", "source": CASE_ADD_ALERT,
                "params": {"id": alert_id, "now": now, "max": CASE_MAX_ALERT_IDS, "prio": level,
                           **prio.policy().dues(now, level)}})
            return {"status": "updated", "case_id": case["_id"]}
        case_id = store.new_id()
        # kỹ thuật MITRE + tag: chọn playbook cho rule không biết trước mã (rule AI viết, cảnh báo ruleset Wazuh)
        techniques = get(alert, "rule.mitre.technique") or []
        self.es.index(index=settings.IDX_CASES, id=case_id, refresh="wait_for", document={
            "@timestamp": now, "created_at": now, "updated_at": now,
            "id": case_id, "title": f"{get(alert, 'rule.name')} — {entity}", "rule_id": get(alert, "rule.id"),
            "entity": entity, "severity": alert.get("severity"), "status": "open",
            "alert_ids": [alert_id], "alert_count": 1, "assignee": None,
            "host": get(alert, "host.name") or get(alert, "agent.id"), "notes": [],
            "asset": {k: get(alert, f"asset.{k}") for k in ("id", "criticality") if get(alert, f"asset.{k}")} or None,
            **self.case_playbooks.build(str(get(alert, "rule.id", "")), alert.get("severity", "medium"),
                                        techniques=[techniques] if isinstance(techniques, str) else techniques,
                                        tags=get(alert, "rule.tags") or [], priority=level, created=now),
        })
        return {"status": "created", "case_id": case_id}

    def _update_alert(self, alert: dict[str, Any], results: list[dict[str, Any]]) -> None:
        alert_id = get(alert, "alert.id")
        acted = any(r.get("status") in ("queued", "extended") for r in results)
        status = "in_progress" if acted else get(alert, "alert.status", "open")
        for attempt in range(5):
            try:
                self.es.update(index=settings.IDX_ALERTS, id=alert_id, retry_on_conflict=3,
                               doc={"soar": {"results": results, "handled_at": store.now_iso()},
                                    "alert": {"status": status}})
                return
            except Exception as e:  # noqa: BLE001 - alert có thể chưa kịp index
                if attempt == 4:
                    log.warning("không cập nhật được alert %s: %s", alert_id, e)
                time.sleep(1)

    # ------------------------------------------------------------------
    def housekeeping(self) -> None:
        """Tự gỡ chặn IP hết hạn + đánh dấu lệnh quá hạn không phản hồi.
        Lệnh chặn chỉ thành `reverted` khi lệnh gỡ báo thành công (store.finish_action). Ở đây chỉ ghi
        `revert_requested_at`: lệnh gỡ thất bại / không phản hồi thì REVERT_RETRY_MINUTES sau tạo lại, không để IP
        bị chặn mãi (trước đây đánh dấu đã gỡ ngay khi tạo lệnh gỡ, lệnh gỡ lỗi là không bao giờ thử lại)."""
        now = store.now_iso()
        retry = (datetime.now(timezone.utc) - timedelta(minutes=REVERT_RETRY_MINUTES)).isoformat()
        expired = store.search(self.es, settings.IDX_ACTIONS, size=100, query={"bool": {
            "filter": [{"term": {"type": "block_ip"}}, {"term": {"status": "success"}}, {"term": {"reverted": False}},
                       {"range": {"expires_at": {"lte": now}}}],
            "should": [{"bool": {"must_not": [{"exists": {"field": "revert_requested_at"}}]}},
                       {"range": {"revert_requested_at": {"lte": retry}}}],
            "minimum_should_match": 1,
        }}, sort=[{"created_at": "asc"}])
        for a in expired:
            ip = a.get("target")
            store.create_action(self.es, a["agent_id"], "unblock_ip", {"ip": ip}, alert_id=a.get("alert_id"), source="soar")
            self.es.update(index=settings.IDX_ACTIONS, id=a["_id"], doc={"revert_requested_at": now, "updated_at": now})
            log.info("hết hạn chặn %s trên %s -> tạo lệnh gỡ chặn%s", ip, a["agent_id"],
                     " (thử lại)" if a.get("revert_requested_at") else "")

        stale = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        try:
            self.es.update_by_query(index=settings.IDX_ACTIONS, conflicts="proceed", query={"bool": {"filter": [
                {"term": {"status": "sent"}}, {"range": {"updated_at": {"lte": stale}}}]}},
                script={"source": "ctx._source.status='timeout'", "lang": "painless"})
        except Exception:  # noqa: BLE001
            pass


class Notifier:
    """`cooldown` > 0: mỗi (rule, thực thể) tối đa 1 thông báo trong `cooldown` giây; alert cùng khóa trong khoảng đó
    được gộp và đếm vào thông báo kế tiếp. Rule match (vd LNX-*, WIN-*) không có suppress nên một đợt tấn công sinh
    hàng loạt alert; trước đây mỗi alert là 1 tin nhắn (Telegram còn chặn khi gửi quá nhanh). Alert vẫn đủ trong case."""

    def __init__(self, webhook: str = "", tg_token: str = "", tg_chat: str = "", cooldown: int = 0,
                 clock=time.monotonic):
        self.webhook = webhook
        self.tg_token = tg_token
        self.tg_chat = tg_chat
        self.cooldown, self.clock = cooldown, clock
        self._last: dict[tuple[str, str], tuple[float, int]] = {}   # (rule, thực thể) -> (lần gửi, số alert đã gộp)

    def _throttle(self, alert: dict[str, Any]) -> int | None:
        """None: đang trong thời gian chờ, gộp alert này. Ngược lại: số alert đã gộp kể từ lần gửi trước."""
        if self.cooldown <= 0:
            return 0
        key, now = (str(get(alert, "rule.id")), case_entity(alert)), self.clock()
        last = self._last.get(key)
        if last and now - last[0] < self.cooldown:
            self._last[key] = (last[0], last[1] + 1)
            return None
        self._last[key] = (now, 0)
        if len(self._last) > 10000:                     # không giữ mãi khóa của các IP chỉ xuất hiện một lần
            self._last = {k: v for k, v in self._last.items() if now - v[0] < self.cooldown}
        return last[1] if last else 0

    def send(self, alert: dict[str, Any]) -> dict[str, Any]:
        merged = self._throttle(alert)
        if merged is None:
            return {"status": "throttled",
                    "detail": f"{get(alert, 'rule.id')} / {case_entity(alert)} đã thông báo trong {self.cooldown} giây qua"}
        text = (f"🚨 {alert.get('message')}\nRule: {get(alert, 'rule.id')} — {get(alert, 'rule.description', '')}\n"
                f"MITRE: {get(alert, 'rule.mitre.tactic')} {get(alert, 'rule.mitre.technique')}\n"
                f"Risk: {alert.get('risk_score')}")
        if merged:
            text += f"\n(+{merged} cảnh báo cùng rule và thực thể từ lần thông báo trước, xem case)"
        sent = []
        if self.webhook:
            self._post(self.webhook, {"text": text, "content": text, "alert": {k: v for k, v in alert.items() if k != "trigger_event"}})
            sent.append("webhook")
        if self.tg_token and self.tg_chat:
            self._post(f"https://api.telegram.org/bot{self.tg_token}/sendMessage", {"chat_id": self.tg_chat, "text": text})
            sent.append("telegram")
        if not sent:
            log.info("NOTIFY (chưa cấu hình kênh): %s", text.replace("\n", " | "))
            return {"status": "logged"}
        return {"status": "sent", "channels": sent}

    @staticmethod
    def _post(url: str, payload: dict[str, Any]) -> None:
        req = urllib.request.Request(url, data=json.dumps(payload, default=str).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        try:
            urllib.request.urlopen(req, timeout=10).read()
        except Exception as e:  # noqa: BLE001
            log.warning("gửi thông báo lỗi: %s", e)
