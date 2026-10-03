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

from .. import settings, store
from .cases import CasePlaybooks
from ..detection.rules import SEVERITY_SCORE
from ..pipeline.normalize import get

log = logging.getLogger("soar")


# Case chưa đóng -> alert mới cùng rule + thực thể được gom vào case này
OPEN_CASE_STATUSES = ("open", "in_progress", "contained")
# Lệnh chặn thành công không có hạn chỉ được coi là còn hiệu lực trong N phút (xem Soar._already_blocked)
BLOCK_TRUST_MINUTES = 10
# Lệnh gỡ chặn (khi hết hạn) chưa thành công sau N phút -> tạo lại (xem Soar.housekeeping)
REVERT_RETRY_MINUTES = 15


def endpoint_agent(alert: dict[str, Any]) -> str | None:
    """Agent ra lệnh được (Wazuh agent). Log syslog (firewall, Suricata) mang agent.id giả `syslog-<ip>`,
    không có agent nào để chạy lệnh trên đó."""
    agent_id = get(alert, "agent.id")
    return None if not agent_id or str(agent_id).startswith("syslog-") else str(agent_id)


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
                 whitelist: list[str] | None = None, notifier=None, case_playbooks: CasePlaybooks | None = None):
        self.es = es
        self.playbooks = playbooks
        self.case_playbooks = case_playbooks or CasePlaybooks(None)
        self.auto_response = auto_response
        self.whitelist = [ipaddress.ip_network(c, strict=False) for c in (whitelist or [])]
        self.notifier = notifier or Notifier()

    # ------------------------------------------------------------------
    def handle(self, alert: dict[str, Any]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for pb in self.playbooks:
            if not pb.matches(alert):
                continue
            log.info("alert %s khớp playbook '%s'", get(alert, "rule.id"), pb.name)
            for step in pb.steps:
                try:
                    res = self.run_step(step, alert)
                except Exception as e:  # noqa: BLE001
                    log.exception("bước %s lỗi", step.get("action"))
                    res = {"status": "error", "detail": str(e)}
                results.append({"playbook": pb.name, "action": step.get("action"), **res})
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
            return {"status": "awaiting_approval", "detail": "cần analyst duyệt trên console"}
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
            a = store.create_action(self.es, agent_id, "kill_process", {"pid": pid},
                                    alert_id=get(alert, "alert.id"), source="soar")
            return {"status": "queued", "action_id": a["id"], "agent_id": agent_id, "target": str(pid)}
        a = store.create_action(self.es, agent_id, "isolate_host", {}, alert_id=get(alert, "alert.id"), source="soar")
        return {"status": "queued", "action_id": a["id"], "agent_id": agent_id}

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
        queued, dup = [], []
        for agent_id in agents:
            if self._already_blocked(agent_id, str(addr)):
                dup.append(agent_id)
                continue
            a = store.create_action(self.es, agent_id, "block_ip", {"ip": str(addr), "duration": duration},
                                    alert_id=get(alert, "alert.id"), source="soar", expires_at=expires)
            queued.append(a["id"])
        status = "queued" if queued else "skipped"
        return {"status": status, "target": str(addr), "agents": agents, "action_ids": queued,
                "detail": f"đã chặn sẵn trên {dup}" if dup else ""}

    def _already_blocked(self, agent_id: str, ip: str) -> bool:
        """Có lệnh chặn IP này trên agent còn hiệu lực không (để không chặn trùng khi alert dồn dập).
        Chỉ tin: lệnh đang gửi/chờ kết quả, lệnh thành công còn hạn, hoặc thành công trong BLOCK_TRUST_MINUTES gần đây.
        Không tin lệnh thành công cũ không có hạn: luật iptables trên agent mất khi máy / container khởi động lại, mà
        bản ghi vẫn ghi 'đang chặn' -> kẻ tấn công không bị chặn lại (đã gặp khi chạy E2E 30/9). Script chặn trên agent
        kiểm tra luật trước khi thêm nên gửi lại lệnh chặn không gây hại."""
        now = datetime.now(timezone.utc)
        recent = (now - timedelta(minutes=BLOCK_TRUST_MINUTES)).isoformat()
        success = [{"term": {"status": "success"}}]
        hits = store.search(self.es, settings.IDX_ACTIONS, size=1, query={"bool": {
            "filter": [{"term": {"agent_id": agent_id}}, {"term": {"type": "block_ip"}}, {"term": {"target": ip}},
                       {"term": {"reverted": False}}],
            "should": [{"terms": {"status": ["pending", "sent"]}},
                       {"bool": {"filter": success + [{"range": {"expires_at": {"gt": now.isoformat()}}}]}},
                       {"bool": {"filter": success + [{"range": {"created_at": {"gte": recent}}}]}}],
            "minimum_should_match": 1,
        }}, sort=[{"created_at": "desc"}])
        return bool(hits)

    def create_case(self, alert: dict[str, Any]) -> dict[str, Any]:
        """Gom alert vào case đang mở cùng rule + cùng thực thể trong 24h, nếu không có thì tạo mới."""
        entity = get(alert, "source.ip") or get(alert, "user.name") or get(alert, "host.name") or "unknown"
        since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        existing = store.search(self.es, settings.IDX_CASES, size=1, query={"bool": {"filter": [
            {"term": {"rule_id": get(alert, "rule.id")}}, {"term": {"entity": str(entity)}},
            {"terms": {"status": list(OPEN_CASE_STATUSES)}}, {"range": {"created_at": {"gte": since}}},
        ]}}, sort=[{"created_at": "desc"}])
        alert_id = get(alert, "alert.id")
        if existing:
            case = existing[0]
            ids = (case.get("alert_ids") or []) + [alert_id]
            self.es.update(index=settings.IDX_CASES, id=case["_id"],
                           doc={"alert_ids": ids[-500:], "alert_count": len(ids), "updated_at": store.now_iso()})
            return {"status": "updated", "case_id": case["_id"]}
        case_id = store.new_id()
        self.es.index(index=settings.IDX_CASES, id=case_id, refresh="wait_for", document={
            "@timestamp": store.now_iso(), "created_at": store.now_iso(), "updated_at": store.now_iso(),
            "id": case_id, "title": f"{get(alert, 'rule.name')} — {entity}", "rule_id": get(alert, "rule.id"),
            "entity": str(entity), "severity": alert.get("severity"), "status": "open",
            "alert_ids": [alert_id], "alert_count": 1, "assignee": None,
            "host": get(alert, "host.name") or get(alert, "agent.id"), "notes": [],
            **self.case_playbooks.build(str(get(alert, "rule.id", "")), alert.get("severity", "medium")),
        })
        return {"status": "created", "case_id": case_id}

    def _update_alert(self, alert: dict[str, Any], results: list[dict[str, Any]]) -> None:
        alert_id = get(alert, "alert.id")
        status = "in_progress" if any(r.get("status") == "queued" for r in results) else get(alert, "alert.status", "open")
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
    def __init__(self, webhook: str = "", tg_token: str = "", tg_chat: str = ""):
        self.webhook = webhook
        self.tg_token = tg_token
        self.tg_chat = tg_chat

    def send(self, alert: dict[str, Any]) -> dict[str, Any]:
        text = (f"🚨 {alert.get('message')}\nRule: {get(alert, 'rule.id')} — {get(alert, 'rule.description', '')}\n"
                f"MITRE: {get(alert, 'rule.mitre.tactic')} {get(alert, 'rule.mitre.technique')}\n"
                f"Risk: {alert.get('risk_score')}")
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
